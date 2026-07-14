package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/irify/irify-benchmark/internal/diagnose"
)

func TestRenderDiagnosisJSON(t *testing.T) {
	report := diagnose.Report{
		ProjectID:     "p1",
		ProjectName:   "Project 1",
		Engine:        "yaklang",
		EngineVersion: "dev",
		Summary:       diagnose.Summary{FN: 1, UnmatchedFindings: 2},
	}
	var buf bytes.Buffer
	if err := renderDiagnosis(report, "json", diagnose.DiagnosticBundleOptions{}, &buf); err != nil {
		t.Fatal(err)
	}
	var decoded diagnose.Report
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, buf.String())
	}
	if decoded.ProjectID != "p1" {
		t.Fatalf("project_id = %q", decoded.ProjectID)
	}
}

func TestRunValidateAIResponseAcceptsValidResponse(t *testing.T) {
	input := strings.NewReader(`{
  "root_causes": [],
  "rule_suggestions": [],
  "benchmark_fixes": [],
  "validation_plan": ["run tests"],
  "uncertainties": []
}`)
	var buf bytes.Buffer

	if err := runValidateAIResponse(input, &buf); err != nil {
		t.Fatal(err)
	}
	var decoded diagnose.AIResponseValidation
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, buf.String())
	}
	if !decoded.Valid {
		t.Fatalf("expected valid response: %#v", decoded)
	}
}

func TestRunValidateAIResponseRejectsInvalidResponse(t *testing.T) {
	input := strings.NewReader(`{"root_causes":[]}`)
	var buf bytes.Buffer

	err := runValidateAIResponse(input, &buf)

	if err == nil {
		t.Fatal("expected validation error")
	}
	var decoded diagnose.AIResponseValidation
	if jsonErr := json.Unmarshal(buf.Bytes(), &decoded); jsonErr != nil {
		t.Fatalf("invalid json: %v\n%s", jsonErr, buf.String())
	}
	if decoded.Valid {
		t.Fatalf("expected invalid response: %#v", decoded)
	}
	if !strings.Contains(strings.Join(decoded.Errors, "\n"), "rule_suggestions") {
		t.Fatalf("expected missing rule_suggestions error: %#v", decoded.Errors)
	}
}

func TestRenderDiagnosisMarkdown(t *testing.T) {
	report := diagnose.Report{
		ProjectID:     "p1",
		ProjectName:   "Project 1",
		Engine:        "yaklang",
		EngineVersion: "dev",
		Summary:       diagnose.Summary{TP: 1, FN: 2},
	}
	var buf bytes.Buffer
	if err := renderDiagnosis(report, "markdown", diagnose.DiagnosticBundleOptions{}, &buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "# Benchmark Diagnosis") {
		t.Fatalf("markdown missing title: %s", buf.String())
	}
}

func TestRenderDiagnosisBundle(t *testing.T) {
	report := diagnose.Report{
		ProjectID:     "p1",
		ProjectName:   "Project 1",
		Engine:        "yaklang",
		EngineVersion: "dev",
		Summary:       diagnose.Summary{FN: 1, UnmatchedFindings: 2},
		CaseDiagnoses: []diagnose.CaseDiagnosis{{
			CaseID:     "case-1",
			Status:     "fn",
			Category:   diagnose.CategorySinkMethodMismatch,
			Confidence: string(diagnose.ConfidenceMedium),
			RuleReviewSuggestions: []diagnose.RuleReviewSuggestion{{
				SuggestionID:         "s1",
				RulePatchRecommended: true,
				SuggestionType:       "add_sink",
				Confidence:           string(diagnose.ConfidenceMedium),
				RuleID:               "rule-1",
				OriginalSnippet:      "alert $sink;",
				SuggestedSnippet:     "alert $sink;\n// Expected sink",
			}},
		}},
	}
	var buf bytes.Buffer
	if err := renderDiagnosis(report, "bundle", diagnose.DiagnosticBundleOptions{}, &buf); err != nil {
		t.Fatal(err)
	}
	var decoded diagnose.DiagnosticBundle
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid bundle json: %v\n%s", err, buf.String())
	}
	if decoded.ProjectID != "p1" {
		t.Fatalf("project_id = %q, want p1", decoded.ProjectID)
	}
	if len(decoded.RuleReviews) != 1 {
		t.Fatalf("rule reviews = %d, want 1", len(decoded.RuleReviews))
	}
	var raw map[string]any
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := raw["case_diagnoses"]; ok {
		t.Fatal("bundle must not expose full case diagnoses")
	}
}

func TestRenderDiagnosisBundleHonorsLimits(t *testing.T) {
	report := diagnose.Report{
		ProjectID:     "p1",
		ProjectName:   "Project 1",
		Engine:        "yaklang",
		EngineVersion: "dev",
		CaseDiagnoses: []diagnose.CaseDiagnosis{
			{
				CaseID:     "case-1",
				Status:     "fn",
				Category:   diagnose.CategorySinkMethodMismatch,
				Confidence: string(diagnose.ConfidenceMedium),
				RuleReviewSuggestions: []diagnose.RuleReviewSuggestion{{
					SuggestionID:         "s1",
					RulePatchRecommended: true,
					SuggestionType:       "add_sink",
					Confidence:           string(diagnose.ConfidenceMedium),
					RuleID:               "rule-1",
				}},
			},
			{
				CaseID:     "case-2",
				Status:     "fn",
				Category:   diagnose.CategoryPathOrPrefixMismatch,
				Confidence: string(diagnose.ConfidenceMedium),
				RuleReviewSuggestions: []diagnose.RuleReviewSuggestion{{
					SuggestionID:         "s2",
					RulePatchRecommended: false,
					SuggestionType:       "benchmark_matcher_fix",
					Confidence:           string(diagnose.ConfidenceMedium),
					RuleID:               "rule-2",
				}},
			},
		},
	}
	var buf bytes.Buffer
	if err := renderDiagnosis(report, "bundle", diagnose.DiagnosticBundleOptions{MaxPriorities: 1, MaxRuleReviews: 1}, &buf); err != nil {
		t.Fatal(err)
	}
	var decoded diagnose.DiagnosticBundle
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid bundle json: %v\n%s", err, buf.String())
	}
	if len(decoded.Priorities) != 1 {
		t.Fatalf("priorities = %d, want 1", len(decoded.Priorities))
	}
	if len(decoded.RuleReviews) != 1 {
		t.Fatalf("rule reviews = %d, want 1", len(decoded.RuleReviews))
	}
}

func TestRenderDiagnosisManifest(t *testing.T) {
	report := diagnose.Report{
		ProjectID:     "p1",
		ProjectName:   "Project 1",
		Engine:        "yaklang",
		EngineVersion: "dev",
		Summary:       diagnose.Summary{FN: 1, UnmatchedFindings: 2},
		CaseDiagnoses: []diagnose.CaseDiagnosis{{
			CaseID:     "case-1",
			Status:     "fn",
			Category:   diagnose.CategorySinkMethodMismatch,
			Confidence: string(diagnose.ConfidenceMedium),
		}},
	}
	var buf bytes.Buffer
	if err := renderDiagnosis(report, "manifest", diagnose.DiagnosticBundleOptions{MaxPriorities: 1, MaxRuleReviews: 1}, &buf); err != nil {
		t.Fatal(err)
	}
	var decoded diagnose.AgentHandoffManifest
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid manifest json: %v\n%s", err, buf.String())
	}
	if decoded.ProjectID != "p1" {
		t.Fatalf("project_id = %q, want p1", decoded.ProjectID)
	}
	if len(decoded.WorkflowSteps) == 0 || decoded.WorkflowSteps[0].ID != "validate-benchmark" {
		t.Fatalf("unexpected workflow steps: %#v", decoded.WorkflowSteps)
	}
}

func TestRenderDiagnosisPrompt(t *testing.T) {
	report := diagnose.Report{
		ProjectID:     "p1",
		ProjectName:   "Project 1",
		Engine:        "yaklang",
		EngineVersion: "dev",
		Summary:       diagnose.Summary{FN: 1, UnmatchedFindings: 2},
		CaseDiagnoses: []diagnose.CaseDiagnosis{{
			CaseID:     "case-1",
			Status:     "fn",
			Category:   diagnose.CategorySinkMethodMismatch,
			Confidence: string(diagnose.ConfidenceMedium),
			RuleReviewSuggestions: []diagnose.RuleReviewSuggestion{{
				SuggestionID:         "s1",
				RulePatchRecommended: true,
				SuggestionType:       "add_sink",
				Confidence:           string(diagnose.ConfidenceMedium),
				RuleID:               "rule-1",
				RuleName:             "Rule 1",
				OriginalSnippet:      "alert $sink;",
				SuggestedSnippet:     "alert $sink;\n// Expected sink",
			}},
		}},
	}
	var buf bytes.Buffer
	if err := renderDiagnosis(report, "prompt", diagnose.DiagnosticBundleOptions{MaxPriorities: 1, MaxRuleReviews: 1}, &buf); err != nil {
		t.Fatal(err)
	}
	output := buf.String()
	for _, expected := range []string{
		"# IRify Benchmark Diagnosis Task",
		"Do not modify SyntaxFlow rules directly",
		"Return rule modification suggestions as review-only diffs",
		"## Response Contract",
		"root_causes",
		"rule_suggestions",
		"benchmark_fixes",
		"validation_plan",
		"uncertainties",
		"```json",
		"\"rule_reviews\"",
		"```",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("prompt missing %q:\n%s", expected, output)
		}
	}
}
