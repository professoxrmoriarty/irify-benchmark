package flowmatch

import (
	"path/filepath"
	"strings"

	"github.com/irify/irify-benchmark/pkg/schema"
)

// lineTolerance is the maximum number of lines a finding's source/sink line
// may differ from the case-annotated line while still counting as a precise
// match. yak occasionally anchors an SSA entry node to the parameter
// declaration line rather than the API call line, so a small tolerance is
// required.
const lineTolerance = 2

// ExactFlowMatch reports whether a finding's source->sink flow precisely
// covers the case's expected source and sink positions.
//
// A precise match requires all three:
//  1. The finding's source line is within lineTolerance of the case source
//     line, AND the case source method name appears as a method segment of
//     the finding's (normalised) source symbol.
//  2. The same for the sink.
//  3. The finding's source/sink file overlaps the case's reference file.
//
// Symbol equality is NOT required: yak symbols are SSA IR toString strings
// and differ from source-code symbols; only the method name must match
// (segment-aware, see SymbolContainsMethod).
//
// The case must declare a flow (Expectation.Flow with source and sink) and
// the finding must be a taint-kind finding with a populated flow. Non-taint
// findings (path/value) never precisely match a taint case.
func ExactFlowMatch(c schema.Case, f schema.Finding) bool {
	if !isTaintFinding(f) {
		return false
	}
	if c.Expectation == nil || c.Expectation.Flow == nil || f.Flow == nil {
		return false
	}
	exp := c.Expectation.Flow
	if exp.Source == nil || exp.Sink == nil || f.Flow.Source == nil || f.Flow.Sink == nil {
		return false
	}

	if !linesClose(exp.Source.Line, f.Flow.Source.Line) {
		return false
	}
	if !linesClose(exp.Sink.Line, f.Flow.Sink.Line) {
		return false
	}
	if !SymbolContainsMethod(exp.Source.Symbol, f.Flow.Source.Symbol) {
		return false
	}
	if !SymbolContainsMethod(exp.Sink.Symbol, f.Flow.Sink.Symbol) {
		return false
	}
	return filesOverlap(c, f)
}

// IsTaintFinding reports whether a finding carries a real source->sink taint
// flow that is eligible for precise flow matching. Empty Kind is treated as
// taint for backward compatibility with findings produced before the Kind
// field existed.
func IsTaintFinding(f schema.Finding) bool { return isTaintFinding(f) }

func isTaintFinding(f schema.Finding) bool {
	kind := f.Kind
	if kind == "" {
		kind = schema.FindingKindTaint
	}
	return kind == schema.FindingKindTaint && f.Flow != nil
}

// linesClose reports whether two line numbers are within lineTolerance of
// each other. A zero line (unknown) never matches a known line.
func linesClose(a, b int) bool {
	if a == 0 || b == 0 {
		return false
	}
	d := a - b
	if d < 0 {
		d = -d
	}
	return d <= lineTolerance
}

// filesOverlap reports whether the finding's flow file paths overlap the
// case's reference source file. It mirrors the matcher's filePathsOverlap
// semantics so precise and fuzzy matching agree on file scope.
func filesOverlap(c schema.Case, f schema.Finding) bool {
	reference := c.SourceCode
	if reference == "" && c.Expectation != nil && c.Expectation.Flow != nil {
		if c.Expectation.Flow.Source != nil {
			reference = c.Expectation.Flow.Source.File
		}
	}
	if reference == "" && c.Expectation != nil && c.Expectation.Flow != nil {
		if c.Expectation.Flow.Sink != nil {
			reference = c.Expectation.Flow.Sink.File
		}
	}
	if reference == "" {
		return true // no reference to constrain against
	}
	candFiles := []string{}
	if f.Flow != nil {
		if f.Flow.Source != nil && f.Flow.Source.File != "" {
			candFiles = append(candFiles, f.Flow.Source.File)
		}
		if f.Flow.Sink != nil && f.Flow.Sink.File != "" {
			candFiles = append(candFiles, f.Flow.Sink.File)
		}
	}
	for _, cand := range candFiles {
		if pathOverlaps(reference, cand) {
			return true
		}
	}
	return false
}

func pathOverlaps(expected, found string) bool {
	expected = filepath.ToSlash(strings.TrimPrefix(expected, "src/"))
	found = filepath.ToSlash(strings.TrimPrefix(found, "src/"))
	if strings.EqualFold(expected, found) || strings.EqualFold(filepath.Base(expected), filepath.Base(found)) {
		return true
	}
	return strings.Contains(strings.ToLower(found), strings.ToLower(expected)) ||
		strings.Contains(strings.ToLower(expected), strings.ToLower(found))
}