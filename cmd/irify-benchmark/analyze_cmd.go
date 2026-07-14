package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/irify/irify-benchmark/internal/store"
	"github.com/irify/irify-benchmark/pkg/schema"
)

var (
	analyzeCmd = &cobra.Command{
		Use:   "analyze",
		Short: "Analyze benchmark results (false positives, coverage, etc.)",
	}

	analyzeFPCmd = &cobra.Command{
		Use:   "fp <project-id>",
		Short: "Analyze false positives for a project",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			projectID := args[0]
			engine, _ := cmd.Flags().GetString("engine")
			version, _ := cmd.Flags().GetString("version")
			format, _ := cmd.Flags().GetString("format")
			output, _ := cmd.Flags().GetString("output")

			hs, err := store.NewHybridStore(".", "data/benchmark.db")
			if err != nil {
				return fmt.Errorf("init hybrid store: %w", err)
			}
			defer hs.Close()

			report, err := buildFPReport(hs, projectID, engine, version)
			if err != nil {
				return err
			}

			var w io.Writer = os.Stdout
			if output != "" {
				f, err := os.Create(output)
				if err != nil {
					return fmt.Errorf("create output file: %w", err)
				}
				defer f.Close()
				w = f
			}

			switch format {
			case "json":
				enc := json.NewEncoder(w)
				enc.SetIndent("", "  ")
				return enc.Encode(report)
			case "markdown", "md":
				return renderFPReportMarkdown(report, w)
			default:
				return renderFPReportText(report, w)
			}
		},
	}
)

func init() {
	analyzeCmd.AddCommand(analyzeFPCmd)
	analyzeFPCmd.Flags().String("engine", "", "Engine name")
	analyzeFPCmd.Flags().String("version", "", "Engine version")
	analyzeFPCmd.Flags().String("format", "text", "Output format: text, json, markdown")
	analyzeFPCmd.Flags().String("output", "", "Output file path (default: stdout)")
}

// fpReportStore abstracts store ops needed by FP analysis.
type fpReportStore interface {
	findingsQueryStore
}

type fpReport struct {
	ProjectID       string              `json:"project_id"`
	ProjectName     string              `json:"project_name"`
	Engine          string              `json:"engine"`
	EngineVersion   string              `json:"engine_version"`
	TotalCases      int                 `json:"total_cases"`
	TP              int                 `json:"tp"`
	FN              int                 `json:"fn"`
	FP              int                 `json:"fp"`
	TN              int                 `json:"tn"`
	TotalFindings   int                 `json:"total_findings"`
	FalsePositives  []fpItem            `json:"false_positives"`
	RuleSummary     []fpRuleSummary     `json:"rule_summary"`
	MissingRules    []string            `json:"missing_rules,omitempty"`
	AnalysisNotes   string              `json:"analysis_notes"`
}

type fpItem struct {
	Index       int              `json:"index"`
	RuleID      string           `json:"rule_id"`
	RuleName    string           `json:"rule_name"`
	Severity    string           `json:"severity"`
	Source      *schema.Location `json:"source,omitempty"`
	Sink        *schema.Location `json:"sink,omitempty"`
	Reason      string           `json:"reason"`
}

type fpRuleSummary struct {
	RuleName       string `json:"rule_name"`
	RuleID         string `json:"rule_id"`
	Count          int    `json:"count"`
	Severity       string `json:"severity"`
	SuggestedAction string `json:"suggested_action"`
}

func buildFPReport(store fpReportStore, projectID, engine, version string) (*fpReport, error) {
	engine, version, err := resolveScanVersion(store, projectID, engine, version)
	if err != nil {
		return nil, err
	}

	project, err := store.ReadProject(projectID)
	if err != nil {
		return nil, fmt.Errorf("read project: %w", err)
	}

	caseSet, err := store.ReadCases(projectID)
	if err != nil {
		return nil, fmt.Errorf("read cases: %w", err)
	}

	findingSet, err := store.GetFindings(projectID, engine, version)
	if err != nil {
		return nil, fmt.Errorf("get findings: %w", err)
	}

	result, _ := store.GetResult(projectID, engine, version)

	// Build set of finding indices that are true positives
	tpIndices := make(map[int]bool)
	if result != nil {
		for _, cr := range result.CaseResults {
			if cr.Status == "tp" && cr.FindingIndex >= 0 {
				tpIndices[cr.FindingIndex] = true
			}
		}
	}

	var fpItems []fpItem
	ruleCount := make(map[string]*fpRuleSummary)
	for i, f := range findingSet.Findings {
		if tpIndices[i] {
			continue // skip true positives
		}

		// Any finding that is not a TP is considered a false positive in benchmark context
		reason := classifyFPReason(f, caseSet)
		item := fpItem{
			Index:    i,
			RuleID:   f.RuleID,
			RuleName: f.RuleName,
			Severity: f.Severity,
			Reason:   reason,
		}
		if f.Flow != nil {
			item.Source = f.Flow.Source
			item.Sink = f.Flow.Sink
		}
		fpItems = append(fpItems, item)

		k := f.RuleID + "|" + f.RuleName
		if ruleCount[k] == nil {
			ruleCount[k] = &fpRuleSummary{
				RuleID:   f.RuleID,
				RuleName: f.RuleName,
				Severity: f.Severity,
			}
		}
		ruleCount[k].Count++
	}

	var ruleSummary []fpRuleSummary
	for _, rs := range ruleCount {
		rs.SuggestedAction = suggestActionForRule(rs.RuleName, projectID)
		ruleSummary = append(ruleSummary, *rs)
	}
	sort.Slice(ruleSummary, func(i, j int) bool {
		return ruleSummary[i].Count > ruleSummary[j].Count
	})

	tp := 0
	fn := 0
	fp := len(fpItems)
	tn := 0
	if result != nil && result.Summary != nil {
		tp = result.Summary.TP
		fn = result.Summary.FN
		tn = result.Summary.TN
	}

	report := &fpReport{
		ProjectID:      projectID,
		ProjectName:    project.Name,
		Engine:         engine,
		EngineVersion:  version,
		TotalCases:     len(caseSet.Cases),
		TP:             tp,
		FN:             fn,
		FP:             fp,
		TN:             tn,
		TotalFindings:  len(findingSet.Findings),
		FalsePositives: fpItems,
		RuleSummary:    ruleSummary,
		MissingRules:   detectMissingRules(projectID, caseSet, result),
		AnalysisNotes:  generateAnalysisNotes(projectID, ruleSummary, fp, fn),
	}

	return report, nil
}

func classifyFPReason(finding schema.Finding, caseSet *schema.CaseSet) string {
	if finding.RuleName == "检测Java空Catch块" {
		return "该规则检测空catch块，但在Securibench Micro测试集中与目标漏洞类型无关，属于跨类型误报。建议按项目漏洞类型过滤无关规则。"
	}
	if finding.RuleName == "检查Java通过PrintStackTrace泄露信息" {
		return "该规则检测printStackTrace信息泄露，与当前项目目标漏洞类型不匹配。Securibench Micro代码中虽存在printStackTrace调用，但并非项目测试目标。"
	}
	if finding.RuleName == "检测Java Lang库未检查返回值的API" {
		return "该规则检测String/Runtime等返回值未使用，属于代码质量规则，与项目安全漏洞测试目标无关。"
	}
	if strings.Contains(finding.RuleName, "SQL") && !strings.Contains(caseSet.ProjectID, "sqli") {
		return "SQL相关规则在非SQLi测试项目中触发，属于跨类型误报。"
	}
	if strings.Contains(finding.RuleName, "ResultSet") || strings.Contains(finding.RuleName, "Statement资源") {
		return "资源泄漏规则检测JDBC资源未释放，与项目目标漏洞类型无关。"
	}
	if finding.RuleName == "检测Java泛型异常捕获" {
		return "泛型异常捕获规则与项目目标漏洞类型无关。"
	}
	if finding.RuleName == "检测 Java SQL 语句拼接漏洞" {
		if strings.Contains(caseSet.ProjectID, "sqli") {
			return "SQL拼接规则在SQLi项目中触发，但源/汇点与测试用例期望位置不匹配，可能是规则覆盖范围过宽或匹配精度不足。"
		}
		return "SQL拼接规则在非SQLi项目中触发，属于跨类型误报。"
	}
	return "规则检出位置与测试用例期望不匹配，或规则目标与项目测试范围不符。"
}

func suggestActionForRule(ruleName, projectID string) string {
	if ruleName == "检测Java空Catch块" {
		return "在benchmark扫描时排除此规则，或增加lang/opcode过滤限制其在Servlet/Web上下文中的触发。"
	}
	if ruleName == "检查Java通过PrintStackTrace泄露信息" {
		return "在benchmark扫描时排除此规则，或增加调用上下文限制（如仅在HTTP响应处理链中触发）。"
	}
	if ruleName == "检测Java Lang库未检查返回值的API" {
		return "此规则为info级别代码质量规则，建议在安全benchmark中直接排除。"
	}
	if strings.Contains(ruleName, "SQL") {
		if strings.Contains(projectID, "sqli") {
			return "优化source/sink匹配精度，增加对HttpServletRequest.getParameter等Web入口的显式追踪。"
		}
		return "在非SQLi项目中排除此规则。"
	}
	if strings.Contains(ruleName, "ResultSet") || strings.Contains(ruleName, "Statement资源") {
		return "资源泄漏规则与安全漏洞benchmark目标不符，建议排除。"
	}
	if ruleName == "检测Java泛型异常捕获" {
		return "代码风格规则，建议benchmark排除。"
	}
	return "请检查规则是否与项目测试目标匹配，不匹配则排除。"
}

func detectMissingRules(projectID string, caseSet *schema.CaseSet, result *schema.Result) []string {
	var missing []string
	if strings.Contains(projectID, "sqli") {
		if result == nil || result.Summary == nil || result.Summary.TP == 0 {
			missing = append(missing, "缺少有效的Java SQL注入检测规则（如java-add-string-and-execute-query.sf在当前项目中未检出任何TP）")
		}
	}
	if strings.Contains(projectID, "xss") {
		if result == nil || result.Summary == nil || result.Summary.TP == 0 {
			missing = append(missing, "缺少Java XSS检测规则（yaklang buildin中无Java XSS规则）")
		}
	}
	if strings.Contains(projectID, "path-traversal") {
		if result == nil || result.Summary == nil || result.Summary.TP == 0 {
			missing = append(missing, "缺少Java Path Traversal检测规则（yaklang buildin中无Java文件操作类规则）")
		}
	}
	if strings.Contains(projectID, "open-redirect") {
		if result == nil || result.Summary == nil || result.Summary.TP == 0 {
			missing = append(missing, "缺少Java Open Redirect检测规则（现有java-direct-url-redirect.sf未在本项目触发）")
		}
	}
	return missing
}

func generateAnalysisNotes(projectID string, ruleSummary []fpRuleSummary, fp, fn int) string {
	var parts []string
	parts = append(parts, fmt.Sprintf("项目 %s 共产生 %d 个误报，%d 个漏报。", projectID, fp, fn))
	if len(ruleSummary) > 0 {
		parts = append(parts, fmt.Sprintf("主要误报来源：%s（%d次）。", ruleSummary[0].RuleName, ruleSummary[0].Count))
	}
	if fn > 0 && fp > 0 {
		parts = append(parts, "当前扫描结果以误报为主，且存在大量漏报，说明规则集与测试项目不匹配或规则精度不足。")
	} else if fn > 0 {
		parts = append(parts, "当前扫描结果全部为漏报，说明缺少针对该项目漏洞类型的有效规则。")
	}
	return strings.Join(parts, "")
}

func renderFPReportText(r *fpReport, w io.Writer) error {
	fmt.Fprintf(w, "False Positive Analysis Report\n")
	fmt.Fprintf(w, "==============================\n\n")
	fmt.Fprintf(w, "Project:      %s (%s)\n", r.ProjectID, r.ProjectName)
	fmt.Fprintf(w, "Engine:       %s %s\n", r.Engine, r.EngineVersion)
	fmt.Fprintf(w, "Total Cases:  %d\n", r.TotalCases)
	fmt.Fprintf(w, "TP: %-4d FN: %-4d FP: %-4d TN: %d\n", r.TP, r.FN, r.FP, r.TN)
	fmt.Fprintf(w, "Total Findings: %d\n", r.TotalFindings)
	fmt.Fprintln(w)

	if len(r.MissingRules) > 0 {
		fmt.Fprintln(w, "Missing Rules:")
		for _, m := range r.MissingRules {
			fmt.Fprintf(w, "  - %s\n", m)
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintln(w, "Rule Summary (False Positives by Rule):")
	fmt.Fprintf(w, "  %-40s %-10s %s\n", "RULE NAME", "COUNT", "SUGGESTED ACTION")
	for _, rs := range r.RuleSummary {
		name := rs.RuleName
		if len(name) > 38 {
			name = name[:35] + "..."
		}
		fmt.Fprintf(w, "  %-40s %-10d %s\n", name, rs.Count, rs.SuggestedAction)
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "False Positive Details:")
	for _, item := range r.FalsePositives {
		fmt.Fprintf(w, "\n[#%d] %s\n", item.Index, item.RuleName)
		fmt.Fprintf(w, "  RuleID:   %s\n", item.RuleID)
		if item.Source != nil {
			fmt.Fprintf(w, "  Source:   %s:%d (%s)\n", filepath.Base(item.Source.File), item.Source.Line, item.Source.Symbol)
		}
		if item.Sink != nil {
			fmt.Fprintf(w, "  Sink:     %s:%d (%s)\n", filepath.Base(item.Sink.File), item.Sink.Line, item.Sink.Symbol)
		}
		fmt.Fprintf(w, "  Reason:   %s\n", item.Reason)
	}

	fmt.Fprintln(w)
	fmt.Fprintf(w, "Analysis Notes: %s\n", r.AnalysisNotes)
	return nil
}

func renderFPReportMarkdown(r *fpReport, w io.Writer) error {
	fmt.Fprintf(w, "# False Positive Analysis Report\n\n")
	fmt.Fprintf(w, "- **Project**: `%s` (%s)\n", r.ProjectID, r.ProjectName)
	fmt.Fprintf(w, "- **Engine**: %s %s\n", r.Engine, r.EngineVersion)
	fmt.Fprintf(w, "- **Total Cases**: %d\n", r.TotalCases)
	fmt.Fprintf(w, "- **Results**: TP=%d / FN=%d / FP=%d / TN=%d\n", r.TP, r.FN, r.FP, r.TN)
	fmt.Fprintf(w, "- **Total Findings**: %d\n\n", r.TotalFindings)

	if len(r.MissingRules) > 0 {
		fmt.Fprintf(w, "## Missing Rules\n\n")
		for _, m := range r.MissingRules {
			fmt.Fprintf(w, "- %s\n", m)
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintf(w, "## Rule Summary (False Positive Distribution)\n\n")
	fmt.Fprintf(w, "| Rule Name | Count | Severity | Suggested Action |\n")
	fmt.Fprintf(w, "|-----------|-------|----------|------------------|\n")
	for _, rs := range r.RuleSummary {
		fmt.Fprintf(w, "| %s | %d | %s | %s |\n", strings.ReplaceAll(rs.RuleName, "|", "\\|"), rs.Count, rs.Severity, rs.SuggestedAction)
	}
	fmt.Fprintln(w)

	fmt.Fprintf(w, "## False Positive Details\n\n")
	for _, item := range r.FalsePositives {
		fmt.Fprintf(w, "### #%d %s\n\n", item.Index, item.RuleName)
		fmt.Fprintf(w, "- **Rule ID**: `%s`\n", item.RuleID)
		if item.Source != nil {
			fmt.Fprintf(w, "- **Source**: `%s:%d` (`%s`)\n", item.Source.File, item.Source.Line, item.Source.Symbol)
		}
		if item.Sink != nil {
			fmt.Fprintf(w, "- **Sink**: `%s:%d` (`%s`)\n", item.Sink.File, item.Sink.Line, item.Sink.Symbol)
		}
		fmt.Fprintf(w, "- **Reason**: %s\n\n", item.Reason)
	}

	fmt.Fprintf(w, "## Analysis Notes\n\n")
	fmt.Fprintf(w, "%s\n", r.AnalysisNotes)
	return nil
}
