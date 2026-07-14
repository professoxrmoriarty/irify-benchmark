package diagnose

import (
	"path/filepath"
	"strings"

	"github.com/irify/irify-benchmark/internal/flowmatch"
	"github.com/irify/irify-benchmark/pkg/schema"
)

const thresholdDefault = 0.80

func scoreBreakdown(c schema.Case, f schema.Finding, threshold float64) ScoreBreakdown {
	if threshold == 0 {
		threshold = thresholdDefault
	}
	out := ScoreBreakdown{Threshold: threshold}
	if c.Expectation == nil || c.Expectation.Flow == nil || f.Flow == nil {
		return out
	}

	exp := c.Expectation.Flow
	found := f.Flow
	refFile := c.SourceCode
	if refFile == "" && exp.Source != nil {
		refFile = exp.Source.File
	}
	if refFile == "" && exp.Sink != nil {
		refFile = exp.Sink.File
	}
	if pathOverlaps(refFile, found.Source) || pathOverlaps(refFile, found.Sink) {
		out.FilePath = 0.30
	}
	if exp.Source != nil && found.Source != nil && symbolMatches(exp.Source.Symbol, found.Source.Symbol) {
		out.SourceSymbol = 0.25
	}
	if exp.Sink != nil && found.Sink != nil && symbolMatches(exp.Sink.Symbol, found.Sink.Symbol) {
		out.SinkSymbol = 0.25
	}
	out.LineProximity = lineProximity(exp, found)
	out.Total = out.FilePath + out.SourceSymbol + out.SinkSymbol + out.LineProximity
	return out
}

func pathOverlaps(expected string, loc *schema.Location) bool {
	if expected == "" || loc == nil || loc.File == "" {
		return false
	}
	expected = filepath.ToSlash(strings.TrimPrefix(expected, "src/"))
	found := filepath.ToSlash(strings.TrimPrefix(loc.File, "src/"))
	if strings.EqualFold(expected, found) || strings.EqualFold(filepath.Base(expected), filepath.Base(found)) {
		return true
	}
	return strings.Contains(strings.ToLower(found), strings.ToLower(expected)) ||
		strings.Contains(strings.ToLower(expected), strings.ToLower(found))
}

// symbolMatches reports whether a finding symbol matches the case's expected
// source/sink symbol. It delegates to the shared flowmatch normaliser so the
// diagnose layer and the matcher agree on SSA-IR-to-source-symbol mapping.
//
// A match is true when the expected method name appears as a method segment
// of the finding symbol (segment-aware, so "execute" != "executeQuery"), OR
// when the two normalised symbols are identical / one contains the other as a
// full segment. This keeps the diagnose categorisation consistent with the
// matcher's precise-match semantics.
func symbolMatches(expected, found string) bool {
	if flowmatch.SymbolContainsMethod(expected, found) {
		return true
	}
	if flowmatch.SymbolContainsMethod(found, expected) {
		return true
	}
	// Fall back to exact normalised equality for source-style symbols that
	// share no method segment (e.g. identical receiver.method).
	ne := flowmatch.NormalizeIRSymbol(expected)
	nf := flowmatch.NormalizeIRSymbol(found)
	if ne == "" || nf == "" {
		return false
	}
	return strings.EqualFold(ne, nf)
}

func normalizeSymbol(s string) string {
	// Retained as a thin wrapper for any residual callers; delegates to the
	// shared flowmatch normaliser.
	return flowmatch.NormalizeIRSymbol(s)
}

func lineProximity(exp, found *schema.Flow) float64 {
	sourceDist := locationDistance(exp.Source, found.Source)
	sinkDist := locationDistance(exp.Sink, found.Sink)
	if sourceDist < 0 || sinkDist < 0 {
		return 0
	}
	if sourceDist <= 3 && sinkDist <= 3 {
		return 0.20
	}
	if (sourceDist <= 3 && sinkDist <= 10) || (sinkDist <= 3 && sourceDist <= 10) {
		return 0.10
	}
	return 0
}

func locationDistance(a, b *schema.Location) int {
	if a == nil || b == nil {
		return -1
	}
	if a.Line > b.Line {
		return a.Line - b.Line
	}
	return b.Line - a.Line
}

func traceContainsSymbol(flow *schema.Flow, expected string) (*schema.Location, bool) {
	if flow == nil {
		return nil, false
	}
	for _, sanitizer := range flow.Sanitizers {
		loc := sanitizer.Location
		if symbolMatches(expected, loc.Symbol) {
			return &loc, true
		}
	}
	return nil, false
}

func isNoiseRule(ruleName string) bool {
	noise := []string{
		"空Catch块",
		"PrintStackTrace",
		"泛型异常捕获",
		"未检查返回值",
		"资源未释放",
		"DriverManager getConnection",
	}
	for _, item := range noise {
		if strings.Contains(strings.ToLower(ruleName), strings.ToLower(item)) {
			return true
		}
	}
	return false
}
