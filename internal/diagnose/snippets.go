package diagnose

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/irify/irify-benchmark/pkg/schema"
)

const maxRuleSnippetLines = 140

func enrichCaseRuleReviewSuggestions(diag *CaseDiagnosis, c schema.Case, finding schema.Finding) {
	if diag == nil || len(diag.RuleReviewSuggestions) == 0 {
		return
	}
	candidate := firstRuleCandidate(diag.RuleCandidates)
	for i := range diag.RuleReviewSuggestions {
		enrichSuggestion(&diag.RuleReviewSuggestions[i], candidate, c, finding)
	}
}

func enrichFindingRuleReviewSuggestions(diag *FindingDiagnosis) {
	if diag == nil || len(diag.RuleReviewSuggestions) == 0 {
		return
	}
	candidate := firstRuleCandidate(diag.RuleCandidates)
	c := schema.Case{}
	if len(diag.NearestCases) > 0 {
		c.CaseID = diag.NearestCases[0]
	}
	for i := range diag.RuleReviewSuggestions {
		enrichSuggestion(&diag.RuleReviewSuggestions[i], candidate, c, diag.Finding)
	}
}

func firstRuleCandidate(candidates []RuleCandidate) *RuleCandidate {
	if len(candidates) == 0 {
		return nil
	}
	return &candidates[0]
}

func enrichSuggestion(suggestion *RuleReviewSuggestion, candidate *RuleCandidate, c schema.Case, finding schema.Finding) {
	if suggestion == nil {
		return
	}
	if candidate == nil {
		if len(suggestion.ValidationCommands) == 0 {
			suggestion.ValidationCommands = validationCommandsForCase(c.CaseID, suggestion.RuleFile)
		}
		return
	}

	suggestion.RuleFile = candidate.Path
	if suggestion.OriginalSnippet == "" {
		suggestion.OriginalSnippet = readRuleSnippet(candidate.Path)
	}
	if suggestion.SuggestedSnippet == "" && suggestion.OriginalSnippet != "" {
		suggestion.SuggestedSnippet = buildSuggestedRuleSnippet(suggestion.OriginalSnippet, c, finding, suggestion)
	}
	if len(suggestion.DiffHunks) == 0 && suggestion.SuggestedSnippet != "" {
		suggestion.DiffHunks = []DiffHunk{{
			OldStart: 1,
			OldLines: countLines(suggestion.OriginalSnippet),
			NewStart: 1,
			NewLines: countLines(suggestion.SuggestedSnippet),
		}}
	}
	if len(suggestion.ValidationCommands) == 0 {
		suggestion.ValidationCommands = validationCommandsForCase(c.CaseID, suggestion.RuleFile)
	}
}

func readRuleSnippet(path string) string {
	if path == "" {
		return ""
	}
	contentBytes, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return ""
	}
	lines := strings.Split(strings.ReplaceAll(string(contentBytes), "\r\n", "\n"), "\n")
	if len(lines) > maxRuleSnippetLines {
		lines = append(lines[:maxRuleSnippetLines], "// ... truncated by irify-benchmark diagnosis ...")
	}
	return strings.TrimRight(strings.Join(lines, "\n"), "\n")
}

func buildSuggestedRuleSnippet(original string, c schema.Case, finding schema.Finding, suggestion *RuleReviewSuggestion) string {
	var b strings.Builder
	b.WriteString(strings.TrimRight(original, "\n"))
	b.WriteString("\n\n")
	b.WriteString("// --- IRify benchmark diagnosis suggestion ---\n")
	b.WriteString(fmt.Sprintf("// Type: %s. Confidence: %s.\n", suggestion.SuggestionType, suggestion.Confidence))
	if suggestion.RulePatchRecommended {
		b.WriteString("// Review this SyntaxFlow rule before applying any patch. The benchmark evidence suggests the rule may need a source/sink/guard adjustment.\n")
	} else {
		b.WriteString("// This is Benchmark-side evidence. Prefer matcher/converter/expectation fixes before changing this rule.\n")
	}
	if c.Expectation != nil && c.Expectation.Flow != nil {
		appendLocationComment(&b, "Expected source", c.Expectation.Flow.Source)
		appendLocationComment(&b, "Expected sink", c.Expectation.Flow.Sink)
	}
	if finding.Flow != nil {
		appendLocationComment(&b, "Nearest finding source", finding.Flow.Source)
		appendLocationComment(&b, "Nearest finding sink", finding.Flow.Sink)
	}
	b.WriteString("// Suggested next step: ask AI to turn this evidence into a minimal SyntaxFlow diff, then validate against this benchmark case.\n")
	return b.String()
}

func appendLocationComment(b *strings.Builder, label string, loc *schema.Location) {
	if loc == nil {
		return
	}
	b.WriteString(fmt.Sprintf("// %s: %s (%s:%d)\n", label, loc.Symbol, loc.File, loc.Line))
}

func validationCommandsForCase(caseID, ruleFile string) []string {
	commands := []string{
		fmt.Sprintf("irify-benchmark diagnose case <project-id> %s --engine yaklang --format json", caseID),
	}
	if ruleFile != "" {
		commands = append(commands, fmt.Sprintf("irify-benchmark diagnose <project-id> --engine yaklang --format markdown # review %s", ruleFile))
	}
	return commands
}

func countLines(value string) int {
	if value == "" {
		return 0
	}
	return strings.Count(value, "\n") + 1
}
