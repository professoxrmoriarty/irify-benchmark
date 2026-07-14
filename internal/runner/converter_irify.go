package runner

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/irify/irify-benchmark/internal/flowmatch"
	"github.com/irify/irify-benchmark/pkg/schema"
)

// IrifyConverter adapts yak code-scan --format irify output to the canonical FindingSet.
type IrifyConverter struct {
	programPrefix string // e.g. "src(2026-06-05 12:19:18)/" to strip from paths
}

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

	// Yak --memory mode embeds the program name as a directory prefix in paths.
	// Strip it so paths match the project source root (e.g. "src/...").
	if report.ProgramName != "" {
		c.programPrefix = report.ProgramName + "/"
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

	// Convert each Risk into a canonical Finding. Yak emits risks as a JSON
	// object (map), whose iteration order is non-deterministic in Go; sort by
	// a stable key so the produced findings array — and therefore downstream
	// finding indexes — are reproducible across runs and test-safe.
	riskKeys := make([]string, 0, len(report.Risks))
	for k := range report.Risks {
		riskKeys = append(riskKeys, k)
	}
	sort.Strings(riskKeys)
	for _, k := range riskKeys {
		risk := report.Risks[k]
		findings := c.adaptRisk(risk, ruleIDByName)
		fs.Findings = append(fs.Findings, findings...)
	}

	return fs, nil
}

func (c *IrifyConverter) adaptRisk(risk irifyRisk, ruleIDByName map[string]string) []schema.Finding {
	base := schema.Finding{
		RuleID:   ruleIDByName[risk.RuleName],
		RuleName: risk.RuleName,
		CWE:      primaryCWE(risk.CWE),
		Severity: risk.Severity,
	}

	// Form-aware flow reconstruction. yak SyntaxFlow findings come in three
	// shapes, determined by how the .sf rule reports its alert:
	//   - taint: a real source->sink data_flow_path with a recognisable
	//     source API call. We reconstruct Flow.Source/Sink precisely.
	//   - path : a data_flow_path exists but carries no source-API call
	//     (e.g. resource-leak rules that alert on a value). We do NOT
	//     fabricate a source==sink self-referential flow; Flow stays nil
	//     and only the risk's code_range locates the finding.
	//   - value: no data_flow_path at all (e.g. hardcoded-secret rules that
	//     alert on a constant). Flow is nil; only code_range locates it.
	//
	// Multi-sink expansion: a single SyntaxFlow alert deduplicates by taint
	// variable, so one risk can carry a data_flow_path that passes the
	// tainted value to N distinct sink calls (e.g. writer.println @48 and
	// writer.println @49 in the same function). The path nodes already
	// contain every sink call's correct code_range; we expand one risk into
	// one finding per distinct sink so each benchmark case (annotated
	// per-sink) can be matched independently. Previously the converter picked
	// only the greatest-line sink, leaving the other N-1 sinks as FN.
	if len(risk.DataFlowPaths) > 0 {
		path := risk.DataFlowPaths[0]
		return c.synthesizeFlowsFromPath(path, risk.CodeRange, base)
	}

	// No data_flow_path: classify the finding form. A "value" finding
	// (hardcoded-secret rules that alert on a constant) carries no flow.
	if base.Flow == nil {
		base.Kind = schema.FindingKindValue
	}
	return []schema.Finding{base}
}

// knownSourcePatterns are substrings commonly found in IR code for source nodes.
// They are used to exclude false sink candidates.
var knownSourcePatterns = []string{
	"getParameter", "getHeader", "getCookies", "getQueryString",
	"getInputStream", "getReader", "getAttribute",
}

// knownSinkPatterns are substrings that strongly indicate a real sink.
// When multiple candidates share the same line number, these are used to
// break ties in favour of the actual sink.
var knownSinkPatterns = []string{
	"sendRedirect", "println", "print", "write",
	"FileWriter", "FileReader", "FileInputStream", "FileOutputStream",
	"executeQuery", "executeUpdate", "prepareStatement", "createStatement",
	"exec", "ProcessBuilder",
}

// extractMainFunction pulls the primary function name from an IR code string.
// IR codes look like "Prefix-functionName(args)" or "Prefix-functionName".
// We strip arguments and take the last dot-separated segment so that nested
// calls (e.g. sendRedirect(..., getParameter(...))) do not trigger source
// heuristics on the outer function.
func extractMainFunction(irCode string) string {
	if idx := strings.Index(irCode, "("); idx >= 0 {
		irCode = irCode[:idx]
	}
	parts := strings.Split(irCode, ".")
	if len(parts) > 0 {
		return strings.TrimSpace(parts[len(parts)-1])
	}
	return strings.TrimSpace(irCode)
}

func isSourceNode(node *irifyDataFlowNode) bool {
	mainFn := strings.ToLower(extractMainFunction(node.IRCode))
	for _, p := range knownSourcePatterns {
		if mainFn == strings.ToLower(p) {
			return true
		}
	}
	return false
}

func isLikelySink(irCode string) bool {
	head := strings.ToLower(extractMainFunction(irCode))
	for _, p := range knownSinkPatterns {
		if head == strings.ToLower(p) {
			return true
		}
	}
	return false
}

// findSinkNode selects the most likely sink from a data-flow path.
// The yak --with-dataflow-path output does not guarantee that the last node is
// the sink; nodes appear in graph-traversal order. We therefore use a
// heuristic: among non-entry nodes that look like function calls (contain "(")
// and are not known source patterns, pick the one with the greatest line
// number. When several candidates share the same line, prefer the one whose
// IR code contains a known sink pattern.
func findSinkNode(nodes []irifyDataFlowNode) *irifyDataFlowNode {
	var candidates []*irifyDataFlowNode
	for i := range nodes {
		node := &nodes[i]
		if node.IsEntryNode {
			continue
		}
		if isSourceNode(node) {
			continue
		}
		ir := node.IRCode
		// Require a function-call-like shape: contains "(".
		if !strings.Contains(ir, "(") {
			continue
		}
		candidates = append(candidates, node)
	}
	if len(candidates) == 0 {
		return nil
	}
	best := candidates[0]
	for _, cand := range candidates[1:] {
		if cand.CodeRange.StartLine > best.CodeRange.StartLine {
			best = cand
			continue
		}
		if cand.CodeRange.StartLine == best.CodeRange.StartLine {
			// Tie-break: prefer known sinks.
			if isLikelySink(cand.IRCode) && !isLikelySink(best.IRCode) {
				best = cand
			}
		}
	}
	return best
}

// synthesizeFlowFromPath reconstructs a source->sink flow from a yak
// data_flow_path and reports the finding kind.
//
// Returns (flow, kind):
//   - (flow, "taint") when the path yields a usable source and sink. The
//     source node is selected in priority order:
//       1. A node whose IR is a call (contains "(") and whose method name is
//          a known source pattern (e.g. getParameter). This anchors the
//          source to the real source-API call rather than the SSA entry
//          parameter, which yak may place on the parameter declaration line.
//       2. Otherwise the SSA entry node (IsEntryNode). For request-bound
//          parameters (e.g. Spring @RequestParam) the entry node IS the
//          taint origin and there is no getParameter-style call, so the
//          entry node is the correct source.
//     The sink is chosen by the existing findSinkNode heuristic.
//   - (nil, "path") when the path has neither a source candidate nor a sink
//     candidate, i.e. it carries no source->sink semantics. Fabricating a
//     flow would mislead the matcher. (Resource-leak rules that alert on a
//     single value still produce a taint-classified flow here when a sink
//     call node exists; their CWE scope filtering keeps them off unrelated
//     cases.)
func (c *IrifyConverter) synthesizeFlowFromPath(path irifyDataFlowPath, fallbackCodeRange *irifyCodeRange) (*schema.Flow, string) {
	nodes := path.Nodes
	if len(nodes) == 0 {
		return nil, schema.FindingKindPath
	}

	// Source priority 1: a known source-API call node (getParameter etc.).
	var sourceNode *irifyDataFlowNode
	for i := range nodes {
		node := &nodes[i]
		if isSourceAPICall(node) {
			if sourceNode == nil || node.CodeRange.StartLine < sourceNode.CodeRange.StartLine {
				sourceNode = node
			}
		}
	}

	// Source priority 2: the SSA entry node (correct origin for
	// @RequestParam-style bound parameters where there is no getParameter call).
	if sourceNode == nil {
		for i := range nodes {
			if nodes[i].IsEntryNode {
				sourceNode = &nodes[i]
				break
			}
		}
	}
	// Source priority 3: the first node.
	if sourceNode == nil {
		sourceNode = &nodes[0]
	}

	// Sink: use heuristic to find the real sink; fallback to last node.
	sinkNode := findSinkNode(nodes)
	if sinkNode == nil {
		sinkNode = &nodes[len(nodes)-1]
	}

	// If the only node is the entry/source itself (no sink candidate and the
	// last node is the source), the path carries no source->sink semantics:
	// classify as a non-taint "path" and emit no flow.
	if sourceNode == sinkNode && len(nodes) == 1 {
		return nil, schema.FindingKindPath
	}

	flow := &schema.Flow{}
	flow.Source = c.nodeToLocation(sourceNode)
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

	return flow, schema.FindingKindTaint
}

// synthesizeFlowsFromPath expands one data_flow_path into one finding per
// distinct sink call, sharing a common source. This reconstructs the
// per-sink flows that SyntaxFlow's alert-by-variable deduplication collapses
// into a single risk: when a tainted value reaches N sink calls in the same
// function (e.g. writer.println @48 and @49), the path already carries every
// sink node with its correct code_range, so we emit N findings instead of the
// single greatest-line sink the old findSinkNode heuristic kept.
//
// Expansion rules:
//   - Sink candidates are nodes that are not entry nodes, not known source
//     patterns, look like calls (contain "("), and match a known sink
//     pattern. Candidates are deduplicated by (start_line, sink_head) since
//     yak's path repeats the same node many times along the taint graph.
//   - 0 sink candidates: falls back to synthesizeFlowFromPath (preserves the
//     prior path/value classification and last-node fallback).
//   - 1 sink candidate: falls back to synthesizeFlowFromPath (identical to
//     pre-expansion behaviour, no regression risk).
//   - N sink candidates: emits N findings, each with the shared source and a
//     distinct sink, ordered by sink line for reproducibility. Sanitizers are
//     the intermediate path nodes between source and the furthest sink so all
//     expanded findings share the same sanitiser context.
//
// The base finding carries the rule/CWE/severity common to every expanded
// finding; each returned finding is a copy with its own Flow.
func (c *IrifyConverter) synthesizeFlowsFromPath(path irifyDataFlowPath, fallbackCodeRange *irifyCodeRange, base schema.Finding) []schema.Finding {
	nodes := path.Nodes
	if len(nodes) == 0 {
		base.Kind = schema.FindingKindPath
		return []schema.Finding{base}
	}

	// Collect distinct sink candidates, keyed by (line, head) to dedupe the
	// repeated nodes yak emits along the taint graph.
	type sinkKey struct {
		line int
		head string
	}
	seen := map[sinkKey]bool{}
	var sinks []*irifyDataFlowNode
	for i := range nodes {
		node := &nodes[i]
		if node.IsEntryNode || isSourceNode(node) {
			continue
		}
		if !strings.Contains(node.IRCode, "(") {
			continue
		}
		if !isLikelySink(node.IRCode) {
			// Only expand real sinks. The pre-expansion path used any call
			// candidate; expansion is narrower to avoid fabricating findings
			// for non-sink intermediate calls.
			continue
		}
		key := sinkKey{line: node.CodeRange.StartLine, head: extractMainFunction(node.IRCode)}
		if seen[key] {
			continue
		}
		seen[key] = true
		sinks = append(sinks, node)
	}

	// 0 or 1 sink candidates: preserve prior behaviour exactly.
	if len(sinks) <= 1 {
		flow, kind := c.synthesizeFlowFromPath(path, fallbackCodeRange)
		base.Flow = flow
		base.Kind = kind
		return []schema.Finding{base}
	}

	// N sinks: expand. Pick the shared source with the same 3-level priority
	// as synthesizeFlowFromPath.
	sourceNode := c.selectSourceNode(nodes)
	if sourceNode == nil {
		// Should not happen (len(nodes)>0), but guard against a panic.
		flow, kind := c.synthesizeFlowFromPath(path, fallbackCodeRange)
		base.Flow = flow
		base.Kind = kind
		return []schema.Finding{base}
	}

	// Order sinks by line for reproducible finding output.
	sort.Slice(sinks, func(i, j int) bool {
		return sinks[i].CodeRange.StartLine < sinks[j].CodeRange.StartLine
	})

	// Sanitizers: intermediate nodes between source and the furthest sink,
	// excluding the source and every sink. All expanded findings share this
	// set since they differ only in sink.
	var sanitizers []schema.Sanitizer
	maxSinkLine := sinks[len(sinks)-1].CodeRange.StartLine
	for i := range nodes {
		node := &nodes[i]
		if node == sourceNode {
			continue
		}
		if node.CodeRange.StartLine <= sourceNode.CodeRange.StartLine {
			continue
		}
		if node.CodeRange.StartLine >= maxSinkLine {
			continue
		}
		if isLikelySink(node.IRCode) {
			continue
		}
		loc := c.nodeToLocation(node)
		if loc == nil {
			continue
		}
		sanitizers = append(sanitizers, schema.Sanitizer{Location: *loc, Effective: false})
	}

	findings := make([]schema.Finding, 0, len(sinks))
	for _, sink := range sinks {
		f := base
		f.Flow = &schema.Flow{
			Source:     c.nodeToLocation(sourceNode),
			Sink:       c.nodeToLocation(sink),
			Sanitizers:  sanitizers,
		}
		f.Kind = schema.FindingKindTaint
		findings = append(findings, f)
	}
	return findings
}

// selectSourceNode picks the source node for a path using the same 3-level
// priority as synthesizeFlowFromPath:
//  1. the lowest-line known source-API call (getParameter etc.), anchoring
//     the source to the real source-API call rather than the SSA entry
//     parameter declaration line;
//  2. the SSA entry node (correct origin for @RequestParam-style bound
//     parameters where there is no getParameter call);
//  3. the first node.
func (c *IrifyConverter) selectSourceNode(nodes []irifyDataFlowNode) *irifyDataFlowNode {
	var sourceNode *irifyDataFlowNode
	for i := range nodes {
		node := &nodes[i]
		if isSourceAPICall(node) {
			if sourceNode == nil || node.CodeRange.StartLine < sourceNode.CodeRange.StartLine {
				sourceNode = node
			}
		}
	}
	if sourceNode == nil {
		for i := range nodes {
			if nodes[i].IsEntryNode {
				sourceNode = &nodes[i]
				break
			}
		}
	}
	if sourceNode == nil {
		sourceNode = &nodes[0]
	}
	return sourceNode
}

// isSourceAPICall reports whether a data-flow node represents a recognisable
// source-API call (e.g. req.getParameter(...)). It requires both that the IR
// is a call (contains "(") and that its method name matches a known source
// pattern, so bare SSA parameter anchors like "Parameter-req" are excluded
// even when IsEntryNode is true.
func isSourceAPICall(node *irifyDataFlowNode) bool {
	if !strings.Contains(node.IRCode, "(") {
		return false
	}
	mainFn := strings.ToLower(extractMainFunction(node.IRCode))
	for _, p := range knownSourcePatterns {
		if mainFn == strings.ToLower(p) {
			return true
		}
	}
	return false
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
	// Normalise yak SSA IR toString into a source-code-style receiver.method
	// symbol via the shared flowmatch normaliser, so the matcher can compare
	// it against case annotations by method name. Falls back to "" when the
	// node has no IR code.
	if node.IRCode == "" {
		return ""
	}
	return flowmatch.NormalizeIRSymbol(node.IRCode)
}

func (c *IrifyConverter) cleanPath(p string) string {
	// Yak irify outputs paths starting with "/src/..." when scanning a directory.
	// In --memory mode it may prefix paths with the program name, e.g.
	// "/src(2026-06-05 12:19:18)/securibench/micro/basic/Basic40.java".
	// Replace the program-name prefix with "src" so paths become relative to
	// the project source root ("src/securibench/micro/basic/Basic40.java").
	p = filepath.Clean(p)
	p = strings.TrimPrefix(p, "/")
	if c.programPrefix != "" {
		p = strings.Replace(p, c.programPrefix, "src/", 1)
	}
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
	CWE             []string              `json:"cwe"`
	CodeSourceURL   string                `json:"code_source_url"`
	Line            int                   `json:"line"`
	CodeRange       *irifyCodeRange       `json:"-"`
	CodeFragment    string                `json:"code_fragment"`
	FunctionName    string                `json:"function_name"`
	ProgramName     string                `json:"program_name"`
	DataFlowPaths   []irifyDataFlowPath   `json:"data_flow_paths"`
}

// primaryCWE normalises the raw CWE array emitted by yak into a single
// canonical identifier. yak reports CWEs as an array (e.g. ["CWE-209"]); the
// first entry is the primary weakness. Missing or malformed entries collapse
// to an empty string so the matcher treats the finding as unscoped noise.
func primaryCWE(cwes []string) string {
	for _, raw := range cwes {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		// Some engines emit a bare number or lowercase prefix; normalise to
		// the canonical "CWE-<id>" form so it compares equal to case metadata.
		if n := strings.TrimPrefix(s, "CWE-"); n != s {
			return "CWE-" + n
		}
		if n := strings.TrimPrefix(s, "cwe-"); n != s {
			return "CWE-" + n
		}
		if _, err := strconv.Atoi(s); err == nil {
			return "CWE-" + s
		}
		return s
	}
	return ""
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
