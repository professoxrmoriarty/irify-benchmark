package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/irify/irify-benchmark/internal/diagnose"
)

func TestWriteDiagnosisResponsePrompt(t *testing.T) {
	report := diagnose.Report{
		ProjectID:     "p1",
		ProjectName:   "Project 1",
		Engine:        "yaklang",
		EngineVersion: "dev",
		Summary:       diagnose.Summary{FN: 1},
	}
	rec := httptest.NewRecorder()

	writeDiagnosisResponse(rec, report, "prompt", diagnose.DiagnosticBundleOptions{MaxPriorities: 1})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if contentType := rec.Header().Get("Content-Type"); !strings.HasPrefix(contentType, "text/plain") {
		t.Fatalf("content-type = %q, want text/plain", contentType)
	}
	output := rec.Body.String()
	for _, expected := range []string{"# IRify Benchmark Diagnosis Task", "## Response Contract", "## Diagnostic Bundle"} {
		if !strings.Contains(output, expected) {
			t.Fatalf("prompt missing %q:\n%s", expected, output)
		}
	}
}

func TestHandleValidateAIResponseAcceptsValidResponse(t *testing.T) {
	body := `{
  "root_causes": [],
  "rule_suggestions": [],
  "benchmark_fixes": [],
  "validation_plan": ["rerun diagnose"],
  "uncertainties": []
}`
	req := httptest.NewRequest(http.MethodPost, "/api/diagnosis/validate-response", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handleValidateAIResponse(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var decoded diagnose.AIResponseValidation
	if err := json.Unmarshal(rec.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, rec.Body.String())
	}
	if !decoded.Valid {
		t.Fatalf("expected valid response: %#v", decoded)
	}
	if decoded.Counts.ValidationSteps != 1 {
		t.Fatalf("validation steps = %d, want 1", decoded.Counts.ValidationSteps)
	}
}

func TestHandleValidateAIResponseReturnsContractErrors(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/diagnosis/validate-response", strings.NewReader(`{"root_causes":[]}`))
	rec := httptest.NewRecorder()

	handleValidateAIResponse(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var decoded diagnose.AIResponseValidation
	if err := json.Unmarshal(rec.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, rec.Body.String())
	}
	if decoded.Valid {
		t.Fatalf("expected invalid response: %#v", decoded)
	}
	if !strings.Contains(strings.Join(decoded.Errors, "\n"), "rule_suggestions") {
		t.Fatalf("expected missing rule_suggestions error: %#v", decoded.Errors)
	}
}

func TestHandleValidateAIResponseRejectsWrongMethod(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/diagnosis/validate-response", nil)
	rec := httptest.NewRecorder()

	handleValidateAIResponse(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
}
