package runner

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/irify/irify-benchmark/pkg/schema"
)

// IrifyConverter adapts yak code-scan --format irify output to the canonical FindingSet.
type IrifyConverter struct{}

// Detect returns true when the JSON contains the characteristic "Risks" and "Rules"
// top-level fields produced by yak --format irify.
func (c *IrifyConverter) Detect(data []byte) bool {
	var probe struct {
		Risks map[string]json.RawMessage `json:"Risks"`
		Rules []json.RawMessage          `json:"Rules"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return false
	}
	return len(probe.Risks) > 0 || len(probe.Rules) > 0
}

// Convert transforms yak irify JSON into a canonical FindingSet.
func (c *IrifyConverter) Convert(data []byte) (*schema.FindingSet, error) {
	var report irifyReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("unmarshal irify report: %w", err)
	}

	fs := &schema.FindingSet{
		Engine:        "yaklang",
		EngineVersion: report.EngineVersion,
		ProgramName:   report.ProgramName,
	}

	if report.ReportTime != "" {
		if t, err := time.Parse(time.RFC3339Nano, report.ReportTime); err == nil {
			fs.ScanTime = t
		} else if t, err := time.Parse(time.RFC3339, report.ReportTime); err == nil {
			fs.ScanTime = t
		}
	}

	// Build rule_name -> rule_id lookup table.
	// Yak irify sometimes embeds rule_id inside the 'content' field instead of
	// a top-level JSON property, so we fall back to regex extraction.
	ruleIDByName := make(map[string]string, len(report.Rules))
	for _, r := range report.Rules {
		if r.RuleName == "" {
			continue
		}
		rid := r.RuleID
		if rid == "" && r.Content != "" {
			rid = extractRuleIDFromContent(r.Content)
		}
		ruleIDByName[r.RuleName] = rid
	}

	// Convert each Risk into a canonical Finding.
	for _, risk := range report.Risks {
		finding := c.adaptRisk(risk, ruleIDByName)
		fs.Findings = append(fs.Findings, finding)
	}

	return fs, nil
}

func (c *IrifyConverter) adaptRisk(risk irifyRisk, ruleIDByName map[string]string) schema.Finding {
	f := schema.Finding{
		RuleID:   ruleIDByName[risk.RuleName],
		RuleName: risk.RuleName,
		Severity: risk.Severity,
	}

	// Synthesize Flow from data_flow_paths when available.
	if len(risk.DataFlowPaths) > 0 {
		path := risk.DataFlowPaths[0]
		f.Flow = c.synthesizeFlowFromPath(path, risk.CodeRange)
	}

	// Fallback: use the single code_range as both source and sink.
	if f.Flow == nil && risk.CodeRange != nil {
		f.Flow = &schema.Flow{
			Source: c.codeRangeToLocation(risk.CodeRange, ""),
			Sink:   c.codeRangeToLocation(risk.CodeRange, ""),
		}
	}

	return f
}

func (c *IrifyConverter) synthesizeFlowFromPath(path irifyDataFlowPath, fallbackCodeRange *irifyCodeRange) *schema.Flow {
	nodes := path.Nodes
	if len(nodes) == 0 {
		return nil
	}

	flow := &schema.Flow{}

	// Source: prefer the entry node; otherwise the first node.
	sourceNode := &nodes[0]
	for i := range nodes {
		if nodes[i].IsEntryNode {
			sourceNode = &nodes[i]
			break
		}
	}
	flow.Source = c.nodeToLocation(sourceNode)

	// Sink: the last node in the path.
	sinkNode := &nodes[len(nodes)-1]
	flow.Sink = c.nodeToLocation(sinkNode)

	// Sanitizers: any nodes between source and sink (excluding both ends).
	// We conservatively mark them as not-yet-verified (Effective=false).
	for i := 1; i < len(nodes)-1; i++ {
		loc := c.nodeToLocation(&nodes[i])
		if loc != nil {
			flow.Sanitizers = append(flow.Sanitizers, schema.Sanitizer{
				Location:  *loc,
				Effective: false,
			})
		}
	}

	return flow
}

func (c *IrifyConverter) nodeToLocation(node *irifyDataFlowNode) *schema.Location {
	if node == nil {
		return nil
	}
	return c.codeRangeToLocation(&node.CodeRange, c.extractSymbol(node))
}

func (c *IrifyConverter) codeRangeToLocation(cr *irifyCodeRange, symbol string) *schema.Location {
	if cr == nil {
		return nil
	}
	loc := &schema.Location{
		Symbol: symbol,
		File:   c.cleanPath(cr.URL),
		Line:   cr.StartLine,
		Column: cr.StartColumn,
	}
	return loc
}

func (c *IrifyConverter) extractSymbol(node *irifyDataFlowNode) string {
	// Best-effort symbol extraction from IR code or source code.
	if node.IRCode != "" {
		// IR code often looks like "Parameter-filename" or "Function-read".
		parts := strings.SplitN(node.IRCode, "-", 2)
		if len(parts) == 2 {
			return strings.TrimSpace(parts[1])
		}
		return strings.TrimSpace(node.IRCode)
	}
	return ""
}

func (c *IrifyConverter) cleanPath(p string) string {
	// Yak irify outputs paths starting with "/src/..." when scanning a directory.
	// Strip the leading slash to make it relative to the project source root.
	p = filepath.Clean(p)
	p = strings.TrimPrefix(p, "/")
	return p
}

var ruleIDRe = regexp.MustCompile(`rule_id:\s*"([^"]+)"`)

func extractRuleIDFromContent(content string) string {
	m := ruleIDRe.FindStringSubmatch(content)
	if len(m) >= 2 {
		return m[1]
	}
	return ""
}

// ---------------------------------------------------------------------------
// Intermediate structures that mirror yak --format irify JSON schema.
// ---------------------------------------------------------------------------

type irifyReport struct {
	ReportType    string                 `json:"report_type"`
	EngineVersion string                 `json:"engine_version"`
	ReportTime    string                 `json:"report_time"`
	ProgramName   string                 `json:"program_name"`
	ProgramLang   string                 `json:"program_lang"`
	RiskNums      int                    `json:"RiskNums"`
	Rules         []irifyRule            `json:"Rules"`
	Risks         map[string]irifyRisk   `json:"Risks"`
	Files         []irifyFile            `json:"File"`
}

type irifyRule struct {
	RuleName string   `json:"rule_name"`
	RuleID   string   `json:"rule_id"`
	Severity string   `json:"severity"`
	Language string   `json:"language"`
	Content  string   `json:"content"`
	Risks    []string `json:"risks"`
}

type irifyRisk struct {
	ID              int                   `json:"id"`
	Hash            string                `json:"hash"`
	Title           string                `json:"title"`
	TitleVerbose    string                `json:"title_verbose"`
	Severity        string                `json:"severity"`
	RuleName        string                `json:"rule_name"`
	CodeSourceURL   string                `json:"code_source_url"`
	Line            int                   `json:"line"`
	CodeRange       *irifyCodeRange       `json:"-"`
	CodeFragment    string                `json:"code_fragment"`
	FunctionName    string                `json:"function_name"`
	ProgramName     string                `json:"program_name"`
	DataFlowPaths   []irifyDataFlowPath   `json:"data_flow_paths"`
}

// UnmarshalJSON handles the fact that yak sometimes serialises code_range as
// a JSON string instead of a nested object.
func (r *irifyRisk) UnmarshalJSON(data []byte) error {
	type alias irifyRisk
	var aux struct {
		*alias
		CodeRange json.RawMessage `json:"code_range"`
	}
	aux.alias = (*alias)(r)
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	if len(aux.CodeRange) > 0 {
		// Try as object first.
		var crObj irifyCodeRange
		if err := json.Unmarshal(aux.CodeRange, &crObj); err == nil {
			r.CodeRange = &crObj
		} else {
			// Fallback: it may be a double-encoded string.
			var s string
			if err := json.Unmarshal(aux.CodeRange, &s); err == nil {
				var cr irifyCodeRange
				if err := json.Unmarshal([]byte(s), &cr); err == nil {
					r.CodeRange = &cr
				}
			}
		}
	}
	return nil
}

type irifyCodeRange struct {
	URL            string `json:"url"`
	StartLine      int    `json:"start_line"`
	StartColumn    int    `json:"start_column"`
	EndLine        int    `json:"end_line"`
	EndColumn      int    `json:"end_column"`
	SourceCodeLine int    `json:"source_code_line"`
}

type irifyDataFlowPath struct {
	Description string              `json:"description"`
	Nodes       []irifyDataFlowNode `json:"nodes"`
}

type irifyDataFlowNode struct {
	NodeID      string         `json:"node_id"`
	IRCode      string         `json:"ir_code"`
	SourceCode  string         `json:"source_code"`
	CodeRange   irifyCodeRange `json:"code_range"`
	IsEntryNode bool           `json:"is_entry_node"`
}

type irifyFile struct {
	Path   string   `json:"path"`
	Length int      `json:"length"`
	Risks  []string `json:"risks"`
}
