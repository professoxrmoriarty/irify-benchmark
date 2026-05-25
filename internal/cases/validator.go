package cases

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/irify/irify-benchmark/pkg/schema"
)

// ValidationResult collects errors and warnings from case validation.
type ValidationResult struct {
	Errors   []string
	Warnings []string
}

// HasErrors returns true if any hard errors were found.
func (r *ValidationResult) HasErrors() bool {
	return len(r.Errors) > 0
}

// HasWarnings returns true if any warnings were found.
func (r *ValidationResult) HasWarnings() bool {
	return len(r.Warnings) > 0
}

// Print writes validation results to stdout with emoji-style prefixes.
func (r *ValidationResult) Print() {
	for _, e := range r.Errors {
		fmt.Printf("  \u274c %s\n", e)
	}
	for _, w := range r.Warnings {
		fmt.Printf("  \u26a0\ufe0f  %s\n", w)
	}
}

// ValidateCase checks a case's source/sink locations against the project's source tree.
func ValidateCase(projectID string, c schema.Case) *ValidationResult {
	result := &ValidationResult{}

	// Validate source_code file exists.
	if c.SourceCode != "" {
		path := filepath.Join("cases", projectID, "src", c.SourceCode)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			result.Errors = append(result.Errors,
				fmt.Sprintf("source_code file %q not found in project src/", c.SourceCode))
		}
	}

	// Validate expectation flow.
	if c.Expectation != nil && c.Expectation.Flow != nil {
		if c.Expectation.Flow.Source != nil {
			validateLocation(projectID, c.Expectation.Flow.Source, "source", result)
		}
		if c.Expectation.Flow.Sink != nil {
			validateLocation(projectID, c.Expectation.Flow.Sink, "sink", result)
		}
		for i := range c.Expectation.Flow.Sanitizers {
			validateLocation(projectID, &c.Expectation.Flow.Sanitizers[i].Location,
				fmt.Sprintf("sanitizer[%d]", i), result)
		}

		// Warn if source line is after sink line in the same file.
		if c.Expectation.Flow.Source != nil && c.Expectation.Flow.Sink != nil {
			src := c.Expectation.Flow.Source
			sink := c.Expectation.Flow.Sink
			if src.File == sink.File && src.Line > sink.Line {
				result.Warnings = append(result.Warnings,
					fmt.Sprintf("source line (%d) is after sink line (%d) in the same file — unusual flow",
						src.Line, sink.Line))
			}
		}
	}

	return result
}

func validateLocation(projectID string, loc *schema.Location, name string, result *ValidationResult) {
	if loc == nil {
		return
	}
	if loc.File == "" {
		result.Errors = append(result.Errors, fmt.Sprintf("%s: file is empty", name))
		return
	}

	path := filepath.Join("cases", projectID, "src", loc.File)
	data, err := os.ReadFile(path)
	if err != nil {
		result.Errors = append(result.Errors,
			fmt.Sprintf("%s file %q: %v", name, loc.File, err))
		return
	}

	lines := strings.Split(string(data), "\n")
	if loc.Line < 1 || loc.Line > len(lines) {
		result.Errors = append(result.Errors,
			fmt.Sprintf("%s line %d out of bounds (file %q has %d lines)",
				name, loc.Line, loc.File, len(lines)))
		return
	}

	// Check symbol presence on the claimed line.
	if loc.Symbol != "" {
		lineContent := lines[loc.Line-1]
		if !strings.Contains(lineContent, loc.Symbol) {
			suggestion := findSimilarSymbol(lineContent, loc.Symbol)
			if suggestion != "" {
				result.Warnings = append(result.Warnings,
					fmt.Sprintf("%s symbol %q not found on line %d (did you mean %q?)",
						name, loc.Symbol, loc.Line, suggestion))
			} else {
				result.Warnings = append(result.Warnings,
					fmt.Sprintf("%s symbol %q not found on line %d",
						name, loc.Symbol, loc.Line))
			}
		}
	}
}

// findSimilarSymbol tries to find the closest token on the line using Levenshtein distance.
func findSimilarSymbol(lineContent, target string) string {
	// Extract candidate tokens (alphanumeric + dot/underscore).
	var candidates []string
	for _, tok := range strings.FieldsFunc(lineContent, func(r rune) bool {
		return !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z') &&
			!(r >= '0' && r <= '9') && r != '.' && r != '_'
	}) {
		if len(tok) >= 3 {
			candidates = append(candidates, tok)
		}
	}

	best := ""
	bestDist := len(target) // threshold
	for _, cand := range candidates {
		d := levenshtein(target, cand)
		if d < bestDist {
			bestDist = d
			best = cand
		}
	}
	if bestDist <= len(target)/3+1 {
		return best
	}
	return ""
}

// levenshtein computes the edit distance between two strings.
func levenshtein(a, b string) int {
	if len(a) == 0 {
		return len(b)
	}
	if len(b) == 0 {
		return len(a)
	}
	prev := make([]int, len(b)+1)
	for j := 0; j <= len(b); j++ {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		curr := make([]int, len(b)+1)
		curr[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 0
			if a[i-1] != b[j-1] {
				cost = 1
			}
			curr[j] = min(curr[j-1]+1, prev[j]+1, prev[j-1]+cost)
		}
		prev = curr
	}
	return prev[len(b)]
}

func min(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}
