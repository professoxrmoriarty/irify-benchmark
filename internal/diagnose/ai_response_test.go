package diagnose

import (
	"strings"
	"testing"
)

func TestValidateAIResponseAcceptsFencedJSON(t *testing.T) {
	input := []byte(`
The diagnosis is below:

` + "```json" + `
{
  "root_causes": [
    {"category": "sink_method_mismatch", "summary": "sink differs", "evidence_refs": ["case-1"], "confidence": "medium"}
  ],
  "rule_suggestions": [
    {"rule_id": "rule-1", "rule_file": "java/x.sf", "reason": "missing sink", "review_only_diff": "+ sink", "validation_commands": ["validate"]}
  ],
  "benchmark_fixes": [],
  "validation_plan": ["run diagnose"],
  "uncertainties": []
}
` + "```" + `
`)

	result := ValidateAIResponse(input)

	if !result.Valid {
		t.Fatalf("expected valid response, got errors: %#v", result.Errors)
	}
	if result.Counts.RootCauses != 1 || result.Counts.RuleSuggestions != 1 || result.Counts.ValidationSteps != 1 {
		t.Fatalf("unexpected counts: %#v", result.Counts)
	}
	if result.Response == nil {
		t.Fatal("expected parsed response payload")
	}
	if got := result.Response.RuleSuggestions[0].ReviewOnlyDiff; got != "+ sink" {
		t.Fatalf("review_only_diff = %q, want + sink", got)
	}
	if got := result.Response.RuleSuggestions[0].ValidationCommands[0]; got != "validate" {
		t.Fatalf("validation command = %q, want validate", got)
	}
}

func TestValidateAIResponseRejectsMissingRequiredSections(t *testing.T) {
	input := []byte(`{"root_causes":[],"validation_plan":[],"uncertainties":[]}`)

	result := ValidateAIResponse(input)

	if result.Valid {
		t.Fatal("expected invalid response")
	}
	joined := strings.Join(result.Errors, "\n")
	for _, expected := range []string{"rule_suggestions", "benchmark_fixes"} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("expected error mentioning %q, got %#v", expected, result.Errors)
		}
	}
}

func TestValidateAIResponseRejectsRuleSuggestionWithoutDiff(t *testing.T) {
	input := []byte(`{
  "root_causes": [],
  "rule_suggestions": [{"rule_id": "rule-1", "rule_file": "java/x.sf", "reason": "missing sink"}],
  "benchmark_fixes": [],
  "validation_plan": [],
  "uncertainties": []
}`)

	result := ValidateAIResponse(input)

	if result.Valid {
		t.Fatal("expected invalid response")
	}
	if !strings.Contains(strings.Join(result.Errors, "\n"), "review_only_diff") {
		t.Fatalf("expected review_only_diff error, got %#v", result.Errors)
	}
}
