package diagnose

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/irify/irify-benchmark/internal/flowmatch"
	"github.com/irify/irify-benchmark/pkg/schema"
)

func DiagnoseCase(c schema.Case, findings []schema.Finding, result *schema.Result, threshold float64, ruleRoot string) CaseDiagnosis {
	status := "fn"
	if result != nil {
		for _, cr := range result.CaseResults {
			if cr.CaseID == c.CaseID {
				status = cr.Status
				break
			}
		}
	}
	diag := CaseDiagnosis{
		CaseID:     c.CaseID,
		Status:     status,
		Category:   CategoryUnknown,
		Confidence: string(ConfidenceLow),
	}
	if c.Expectation != nil {
		diag.ExpectedFlow = c.Expectation.Flow
	}

	bestIdx, bestFinding, bestScore := bestFindingForCase(c, findings, threshold)
	if bestIdx >= 0 {
		diag.BestCandidateFinding = &CandidateFinding{
			Index:    bestIdx,
			RuleID:   bestFinding.RuleID,
			RuleName: bestFinding.RuleName,
			CWE:      bestFinding.CWE,
			Severity: bestFinding.Severity,
			Flow:     bestFinding.Flow,
			Score:    bestScore,
		}
		diag.ScoreBreakdown = &bestScore
		diag.RuleCandidates = ruleCandidatesForCase(ruleRoot, c, bestFinding)
	}
	classifyCase(&diag, c, bestFinding)
	diag.SuggestedNextCommands = nextCommandsForCase(c.CaseID)
	diag.RuleReviewSuggestions = suggestionsForCase(diag, bestFinding)
	enrichCaseRuleReviewSuggestions(&diag, c, bestFinding)
	return diag
}

func DiagnoseFinding(index int, finding schema.Finding, cases []schema.Case, result *schema.Result, threshold float64, ruleRoot string) FindingDiagnosis {
	diag := FindingDiagnosis{
		FindingIndex: index,
		Status:       "unmatched_finding",
		Category:     CategoryUnknown,
		Confidence:   string(ConfidenceLow),
		Finding:      finding,
	}
	if isNoiseRule(finding.RuleName) {
		diag.Category = CategoryCrossCWEOrNoiseRule
		diag.Confidence = string(ConfidenceHigh)
		diag.TraceEvidence = append(diag.TraceEvidence, TraceEvidence{
			Kind:    "noise_rule",
			Message: fmt.Sprintf("Rule %q is outside benchmark target vulnerability classes.", finding.RuleName),
		})
	}

	bestCase, score := nearestCaseForFinding(finding, cases, threshold)
	if bestCase != nil {
		diag.NearestCases = []string{bestCase.CaseID}
		diag.ScoreBreakdown = &score
		diag.RuleCandidates = ruleCandidatesForCase(ruleRoot, *bestCase, finding)
	}
	if diag.Category == CategoryUnknown && score.Total >= threshold {
		diag.Category = CategoryDuplicateFindingForCase
		diag.Confidence = string(ConfidenceMedium)
	}
	if diag.Category == CategoryCrossCWEOrNoiseRule {
		diag.RuleReviewSuggestions = []RuleReviewSuggestion{{
			SuggestionID:         fmt.Sprintf("exclude-noise-%d", index),
			RulePatchRecommended: false,
			SuggestionType:       "exclude_noise_rule",
			Confidence:           diag.Confidence,
			RuleID:               finding.RuleID,
			RuleName:             finding.RuleName,
			EvidenceRefs:         []EvidenceRef{{FindingIndex: index}},
			ReviewComments:       []ReviewComment{{Line: 1, Message: "This finding is from a non-target rule for the current benchmark scope."}},
		}}
	}
	enrichFindingRuleReviewSuggestions(&diag)
	return diag
}

func bestFindingForCase(c schema.Case, findings []schema.Finding, threshold float64) (int, schema.Finding, ScoreBreakdown) {
	bestIdx := -1
	var best schema.Finding
	var bestScore ScoreBreakdown
	caseCWE := expectedCWE(c)
	for i, finding := range findings {
		// Scope filter: when the case declares an expected CWE, only in-scope
		// findings are eligible to be its best candidate. This mirrors the
		// matcher's scope filtering and prevents cross-CWE / code-quality
		// findings from winning the best-candidate slot on proximity alone,
		// which would otherwise produce a misleading BestCandidateFinding on a
		// false negative. A case with no declared CWE is lenient (legacy).
		if caseCWE != "" && !cweInScope(caseCWE, finding.CWE) {
			continue
		}
		score := scoreBreakdown(c, finding, threshold)
		// Distortion-B fix: precise source/sink coverage wins over fuzzy
		// proximity, mirroring the matcher. A finding whose flow precisely
		// covers the case's annotated source and sink is boosted to the max
		// score so it outranks merely-proximate in-scope findings and the
		// BestCandidateFinding points at the real covering flow. Non-taint
		// findings (path/value) never precise-match a taint case.
		if flowmatch.ExactFlowMatch(c, finding) {
			score.Total = 1.0
			score.SourceSymbol = 0.25
			score.SinkSymbol = 0.25
			score.FilePath = 0.30
			score.LineProximity = 0.20
		}
		if score.Total > bestScore.Total {
			bestIdx = i
			best = finding
			bestScore = score
		}
	}
	return bestIdx, best, bestScore
}

// expectedCWE returns the canonical CWE the case declares it expects to be
// detected as. Empty means the case does not constrain by CWE.
func expectedCWE(c schema.Case) string {
	if c.Metadata == nil {
		return ""
	}
	return normaliseCWE(c.Metadata.CWE)
}

// cweInScope reports whether a finding's CWE matches the case's declared CWE.
// An empty case CWE is lenient (accepts any finding). A finding with an empty
// CWE is out-of-scope whenever the case declares one, so unmapped noise cannot
// win a best-candidate slot.
func cweInScope(caseCWE, findingCWE string) bool {
	if caseCWE == "" {
		return true
	}
	return normaliseCWE(caseCWE) == normaliseCWE(findingCWE) && findingCWE != ""
}

// normaliseCWE collapses CWE spellings ("CWE-89", "cwe-89", "89", "  CWE-89 ")
// into the canonical "CWE-<id>" form. Empty / non-numeric input maps to "".
func normaliseCWE(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	for _, pfx := range []string{"CWE-", "cwe-"} {
		if rest := strings.TrimPrefix(s, pfx); rest != s {
			return "CWE-" + strings.TrimSpace(rest)
		}
	}
	if _, err := strconv.Atoi(s); err == nil {
		return "CWE-" + s
	}
	return s
}

func nearestCaseForFinding(finding schema.Finding, cases []schema.Case, threshold float64) (*schema.Case, ScoreBreakdown) {
	var best *schema.Case
	var bestScore ScoreBreakdown
	for i := range cases {
		score := scoreBreakdown(cases[i], finding, threshold)
		if score.Total > bestScore.Total {
			best = &cases[i]
			bestScore = score
		}
	}
	return best, bestScore
}

func classifyCase(diag *CaseDiagnosis, c schema.Case, finding schema.Finding) {
	if diag.Status == "tp" {
		diag.Category = CategoryMatchedTP
		diag.Confidence = string(ConfidenceHigh)
		return
	}
	if diag.ScoreBreakdown == nil || c.Expectation == nil || c.Expectation.Flow == nil || finding.Flow == nil {
		diag.Category = CategoryNoSameCWEFinding
		diag.Confidence = string(ConfidenceMedium)
		return
	}
	exp := c.Expectation.Flow
	if exp.Source != nil {
		if loc, ok := traceContainsSymbol(finding.Flow, exp.Source.Symbol); ok && diag.ScoreBreakdown.SinkSymbol > 0 {
			diag.Category = CategoryMatcherEndpointSource
			diag.Confidence = string(ConfidenceHigh)
			diag.TraceEvidence = append(diag.TraceEvidence, TraceEvidence{
				Kind:     "trace_contains_expected_source",
				Message:  fmt.Sprintf("Trace contains expected source symbol %q even though the endpoint source differs.", exp.Source.Symbol),
				Location: loc,
			})
			return
		}
	}
	if diag.ScoreBreakdown.SourceSymbol > 0 && diag.ScoreBreakdown.SinkSymbol == 0 {
		diag.Category = CategorySinkMethodMismatch
		diag.Confidence = string(ConfidenceMedium)
		return
	}
	if diag.ScoreBreakdown.FilePath == 0 && (diag.ScoreBreakdown.SourceSymbol > 0 || diag.ScoreBreakdown.SinkSymbol > 0) {
		diag.Category = CategoryPathOrPrefixMismatch
		diag.Confidence = string(ConfidenceMedium)
		return
	}
	diag.Category = CategoryUnknown
	diag.Confidence = string(ConfidenceLow)
}

func ruleCandidatesForCase(ruleRoot string, c schema.Case, finding schema.Finding) []RuleCandidate {
	if ruleRoot == "" {
		return nil
	}
	cwe := ""
	if c.Metadata != nil {
		cwe = c.Metadata.CWE
	}
	return MapRuleCandidates(ruleRoot, RuleLookup{
		Language: c.Language,
		CWE:      cwe,
		RuleID:   finding.RuleID,
		RuleName: finding.RuleName,
	})
}

func suggestionsForCase(diag CaseDiagnosis, finding schema.Finding) []RuleReviewSuggestion {
	switch diag.Category {
	case CategoryMatcherEndpointSource, CategoryPathOrPrefixMismatch, CategoryConverterLoss:
		return []RuleReviewSuggestion{{
			SuggestionID:         fmt.Sprintf("benchmark-fix-%s", diag.CaseID),
			RulePatchRecommended: false,
			SuggestionType:       "benchmark_matcher_fix",
			Confidence:           diag.Confidence,
			RuleID:               finding.RuleID,
			RuleName:             finding.RuleName,
			EvidenceRefs:         []EvidenceRef{{CaseID: diag.CaseID}},
			ReviewComments:       []ReviewComment{{Line: 1, Message: "Evidence points to benchmark matcher or converter behavior before SyntaxFlow rule changes."}},
		}}
	case CategorySinkMethodMismatch, CategoryNoSameCWEFinding, CategoryRulePrecisionIssue:
		return []RuleReviewSuggestion{{
			SuggestionID:         fmt.Sprintf("rule-review-%s", diag.CaseID),
			RulePatchRecommended: true,
			SuggestionType:       "add_sink",
			Confidence:           diag.Confidence,
			RuleID:               finding.RuleID,
			RuleName:             finding.RuleName,
			EvidenceRefs:         []EvidenceRef{{CaseID: diag.CaseID}},
			ReviewComments:       []ReviewComment{{Line: 1, Message: "Review the candidate SyntaxFlow rule against this benchmark evidence."}},
		}}
	default:
		return nil
	}
}

func nextCommandsForCase(caseID string) []string {
	return []string{
		fmt.Sprintf("irify-benchmark diagnose case <project-id> %s --engine yaklang --format json", caseID),
	}
}

type BuildReportInput struct {
	ProjectID     string
	ProjectName   string
	Engine        string
	EngineVersion string
	Cases         []schema.Case
	Findings      []schema.Finding
	Result        *schema.Result
	RuleRoot      string
	Threshold     float64
}

func BuildReport(input BuildReportInput) Report {
	report := Report{
		ProjectID:     input.ProjectID,
		ProjectName:   input.ProjectName,
		Engine:        input.Engine,
		EngineVersion: input.EngineVersion,
	}
	if input.Result != nil && input.Result.Summary != nil {
		report.Summary.TP = input.Result.Summary.TP
		report.Summary.FP = input.Result.Summary.FP
		report.Summary.FN = input.Result.Summary.FN
		report.Summary.TN = input.Result.Summary.TN
	}

	for _, c := range input.Cases {
		diag := DiagnoseCase(c, input.Findings, input.Result, input.Threshold, input.RuleRoot)
		report.CaseDiagnoses = append(report.CaseDiagnoses, diag)
	}

	matchedFindings := map[int]bool{}
	if input.Result != nil {
		for _, cr := range input.Result.CaseResults {
			if cr.FindingIndex >= 0 && cr.Status == "tp" {
				matchedFindings[cr.FindingIndex] = true
			}
		}
	}
	for i, finding := range input.Findings {
		if matchedFindings[i] {
			continue
		}
		report.Summary.UnmatchedFindings++
		diag := DiagnoseFinding(i, finding, input.Cases, input.Result, input.Threshold, input.RuleRoot)
		report.FindingDiagnoses = append(report.FindingDiagnoses, diag)
	}

	if input.Result == nil || input.Result.Summary == nil {
		for _, diag := range report.CaseDiagnoses {
			switch diag.Status {
			case "tp":
				report.Summary.TP++
			case "fp":
				report.Summary.FP++
			case "tn":
				report.Summary.TN++
			default:
				report.Summary.FN++
			}
		}
	}

	report.CategorySummary = buildCategorySummary(report)
	report.RuleSummaries = buildRuleSummaries(report)
	plan := BuildRemediationPlan(report)
	report.RemediationPlan = &plan
	return report
}

func buildCategorySummary(report Report) []CategorySummary {
	counts := map[Category]int{}
	for _, diag := range report.CaseDiagnoses {
		counts[diag.Category]++
	}
	for _, diag := range report.FindingDiagnoses {
		counts[diag.Category]++
	}
	items := make([]CategorySummary, 0, len(counts))
	for category, count := range counts {
		items = append(items, CategorySummary{Category: category, Count: count})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Count != items[j].Count {
			return items[i].Count > items[j].Count
		}
		return items[i].Category < items[j].Category
	})
	return items
}

func buildRuleSummaries(report Report) []RuleSummary {
	byRule := map[string]*RuleSummary{}
	add := func(ruleID, ruleName string, candidates []RuleCandidate, suggestions []RuleReviewSuggestion) {
		key := ruleID + "|" + ruleName
		if byRule[key] == nil {
			byRule[key] = &RuleSummary{RuleID: ruleID, RuleName: ruleName, Candidates: candidates}
		}
		byRule[key].Count++
		byRule[key].Suggestions = append(byRule[key].Suggestions, suggestions...)
	}
	for _, diag := range report.CaseDiagnoses {
		if diag.BestCandidateFinding != nil {
			add(diag.BestCandidateFinding.RuleID, diag.BestCandidateFinding.RuleName, diag.RuleCandidates, diag.RuleReviewSuggestions)
		}
	}
	for _, diag := range report.FindingDiagnoses {
		add(diag.Finding.RuleID, diag.Finding.RuleName, diag.RuleCandidates, diag.RuleReviewSuggestions)
	}

	items := make([]RuleSummary, 0, len(byRule))
	for _, item := range byRule {
		items = append(items, *item)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Count != items[j].Count {
			return items[i].Count > items[j].Count
		}
		return items[i].RuleName < items[j].RuleName
	})
	return items
}
