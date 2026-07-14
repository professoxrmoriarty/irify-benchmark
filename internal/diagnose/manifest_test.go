package diagnose

import (
	"strings"
	"testing"
)

func TestBuildAgentHandoffManifestDescribesAIWorkflowAndGuardrails(t *testing.T) {
	report := Report{
		ProjectID:     "p1",
		ProjectName:   "Project 1",
		Engine:        "yaklang",
		EngineVersion: "dev",
		Summary:       Summary{TP: 2, FN: 1, UnmatchedFindings: 3},
		CaseDiagnoses: []CaseDiagnosis{{
			CaseID:     "case-1",
			Status:     "fn",
			Category:   CategorySinkMethodMismatch,
			Confidence: string(ConfidenceMedium),
			RuleReviewSuggestions: []RuleReviewSuggestion{{
				SuggestionID:         "s1",
				RulePatchRecommended: true,
				SuggestionType:       "sink_guard",
				RuleID:               "rule-1",
				RuleFile:             "sfbuildin/java/rule-1.sf",
				ValidationCommands:   []string{"irify-benchmark diagnose p1 --engine yaklang --format json"},
			}},
		}},
	}

	manifest := BuildAgentHandoffManifest(report, DiagnosticBundleOptions{MaxPriorities: 4, MaxRuleReviews: 2})

	if manifest.ProjectID != "p1" {
		t.Fatalf("project_id = %q, want p1", manifest.ProjectID)
	}
	if len(manifest.WorkflowSteps) < 5 {
		t.Fatalf("workflow steps = %d, want at least 5", len(manifest.WorkflowSteps))
	}
	steps := strings.Join(stepIDs(manifest.WorkflowSteps), "\n")
	for _, expected := range []string{"validate-benchmark", "run-scan", "diagnose", "ask-ai", "validate-ai-response"} {
		if !strings.Contains(steps, expected) {
			t.Fatalf("workflow missing %q: %#v", expected, manifest.WorkflowSteps)
		}
	}
	joinedForbidden := strings.Join(manifest.Guardrails.Forbidden, "\n")
	if !strings.Contains(joinedForbidden, "Do not modify yaklang/common/syntaxflow/sfbuildin") {
		t.Fatalf("forbidden guardrails missing sfbuildin constraint: %#v", manifest.Guardrails.Forbidden)
	}
	if len(manifest.RuleReviewQueue) != 1 {
		t.Fatalf("rule review queue = %d, want 1", len(manifest.RuleReviewQueue))
	}
	if !manifest.RuleReviewQueue[0].ReviewOnly {
		t.Fatalf("rule review queue item must be review-only: %#v", manifest.RuleReviewQueue[0])
	}
}

func stepIDs(steps []AgentWorkflowStep) []string {
	ids := make([]string, 0, len(steps))
	for _, step := range steps {
		ids = append(ids, step.ID)
	}
	return ids
}
