package matcher

import (
	"path/filepath"
	"strings"

	"github.com/irify/irify-benchmark/pkg/schema"
)

// MatchScore captures the result of scoring a single case against a single finding.
type MatchScore struct {
	Total          float64
	SourceMatch    bool
	SinkMatch      bool
	SanitizerMatch bool
	TraceComplete  bool
	LineDistance   int // average line distance between source and sink
}

const (
	weightFilePath     = 0.30
	weightSourceSymbol = 0.25
	weightSinkSymbol   = 0.25
	weightLineProximity = 0.20
)

// Score evaluates how well a finding matches an expected case.
// It returns a MatchScore with Total in the range [0, 1].
func Score(c schema.Case, f schema.Finding) MatchScore {
	var score MatchScore

	if c.Expectation == nil || c.Expectation.Flow == nil || f.Flow == nil {
		return score
	}

	expFlow := c.Expectation.Flow
	fndFlow := f.Flow

	// File path match: use SourceCode when available, otherwise fall back to
	// the expected source or sink file path.
	referenceFile := c.SourceCode
	if referenceFile == "" && expFlow.Source != nil && expFlow.Source.File != "" {
		referenceFile = expFlow.Source.File
	}
	if referenceFile == "" && expFlow.Sink != nil && expFlow.Sink.File != "" {
		referenceFile = expFlow.Sink.File
	}
	if filePathsOverlap(referenceFile, fndFlow) {
		score.Total += weightFilePath
	}

	// Source symbol match
	if expFlow.Source != nil && fndFlow.Source != nil {
		if symbolsMatch(expFlow.Source.Symbol, fndFlow.Source.Symbol) {
			score.SourceMatch = true
			score.Total += weightSourceSymbol
		}
	}

	// Sink symbol match
	if expFlow.Sink != nil && fndFlow.Sink != nil {
		if symbolsMatch(expFlow.Sink.Symbol, fndFlow.Sink.Symbol) {
			score.SinkMatch = true
			score.Total += weightSinkSymbol
		}
	}

	// Line proximity
	lineScore := computeLineProximity(expFlow, fndFlow)
	score.Total += lineScore

	// Line distance (average of source and sink distances)
	score.LineDistance = computeLineDistance(expFlow, fndFlow)

	// Sanitizer match (does not affect Total yet)
	score.SanitizerMatch = sanitizersMatch(expFlow.Sanitizers, fndFlow.Sanitizers)

	// Trace completeness
	score.TraceComplete = score.SourceMatch && score.SinkMatch

	return score
}

// filePathsOverlap checks whether the finding references a file path that
// overlaps with the case's source_code path.
func filePathsOverlap(sourceCode string, fndFlow *schema.Flow) bool {
	if sourceCode == "" || fndFlow == nil {
		return false
	}

	base := filepath.Base(sourceCode)

	check := func(loc *schema.Location) bool {
		if loc == nil || loc.File == "" {
			return false
		}
		if strings.EqualFold(loc.File, base) || strings.EqualFold(sourceCode, loc.File) {
			return true
		}
		if strings.Contains(strings.ToLower(sourceCode), strings.ToLower(loc.File)) ||
			strings.Contains(strings.ToLower(loc.File), strings.ToLower(sourceCode)) {
			return true
		}
		return false
	}

	return check(fndFlow.Source) || check(fndFlow.Sink)
}

// computeLineProximity calculates the line-proximity contribution [0, 0.20].
func computeLineProximity(expFlow, fndFlow *schema.Flow) float64 {
	if expFlow == nil || fndFlow == nil {
		return 0
	}

	srcDist := lineDistance(expFlow.Source, fndFlow.Source)
	sinkDist := lineDistance(expFlow.Sink, fndFlow.Sink)

	if srcDist < 0 || sinkDist < 0 {
		return 0
	}

	// Full credit when both distances are small.
	if srcDist <= 3 && sinkDist <= 3 {
		return weightLineProximity
	}
	// Partial credit when one is very close and the other is moderately close.
	if (srcDist <= 3 && sinkDist <= 10) || (sinkDist <= 3 && srcDist <= 10) {
		return weightLineProximity / 2
	}
	return 0
}

// lineDistance returns the absolute difference between two location line numbers.
// Returns -1 if either location is nil.
func lineDistance(a, b *schema.Location) int {
	if a == nil || b == nil {
		return -1
	}
	dist := a.Line - b.Line
	if dist < 0 {
		dist = -dist
	}
	return dist
}

// computeLineDistance returns the average line distance between source and sink.
// Returns 0 if any required location is missing.
func computeLineDistance(expFlow, fndFlow *schema.Flow) int {
	srcDist := lineDistance(expFlow.Source, fndFlow.Source)
	sinkDist := lineDistance(expFlow.Sink, fndFlow.Sink)
	if srcDist < 0 || sinkDist < 0 {
		return 0
	}
	return (srcDist + sinkDist) / 2
}

// sanitizersMatch checks whether any sanitizer symbol overlaps case-insensitively.
func sanitizersMatch(expected []schema.Sanitizer, found []schema.Sanitizer) bool {
	if len(expected) == 0 || len(found) == 0 {
		return false
	}
	for _, e := range expected {
		for _, f := range found {
			if strings.EqualFold(e.Symbol, f.Symbol) {
				return true
			}
		}
	}
	return false
}

// symbolsMatch checks whether the expected and found symbols match.
// It supports fuzzy matching for qualified method names, parameter types, etc.
func symbolsMatch(expected, found string) bool {
	expected = strings.TrimSpace(strings.ToLower(expected))
	found = strings.TrimSpace(strings.ToLower(found))
	if expected == found {
		return true
	}
	if expected == "" || found == "" {
		return false
	}
	// Strip call arguments: e.g. "println(foo)" -> "println"
	if idx := strings.Index(expected, "("); idx >= 0 {
		expected = expected[:idx]
	}
	if idx := strings.Index(found, "("); idx >= 0 {
		found = found[:idx]
	}
	expected = strings.TrimSpace(expected)
	found = strings.TrimSpace(found)
	if expected == found {
		return true
	}
	// Extract last segment after the last '.': e.g. "req.getParameter" -> "getParameter"
	lastPart := func(s string) string {
		parts := strings.Split(s, ".")
		return strings.TrimSpace(parts[len(parts)-1])
	}
	expLast := lastPart(expected)
	fndLast := lastPart(found)
	if expLast != "" && fndLast != "" && expLast == fndLast {
		return true
	}
	// Fallback to substring matching: if one contains the other
	if strings.Contains(expected, found) || strings.Contains(found, expected) {
		return true
	}
	return false
}
