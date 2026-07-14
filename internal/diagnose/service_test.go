package diagnose

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/irify/irify-benchmark/pkg/schema"
)

func TestClassifyEndpointSourceMismatchWhenTraceContainsExpectedSource(t *testing.T) {
	c := schema.Case{
		CaseID:   "basic-basic1-001",
		Language: "java",
		Expectation: &schema.Expectation{
			Type: "must_alert",
			Flow: &schema.Flow{
				Source: &schema.Location{Symbol: "req.getParameter", Line: 36, File: "securibench/micro/basic/Basic1.java"},
				Sink:   &schema.Location{Symbol: "writer.println", Line: 39, File: "securibench/micro/basic/Basic1.java"},
			},
		},
		Metadata: &schema.Metadata{CWE: "CWE-79"},
	}
	finding := schema.Finding{
		RuleID:   "91441632-5409-4bfe-8c54-cb49e21c870d",
		RuleName: "检测Java Servlet XSS漏洞",
		CWE:      "CWE-79",
		Severity: "middle",
		Flow: &schema.Flow{
			Source: &schema.Location{Symbol: "\"name\"", Line: 36, File: "src/securibench/micro/basic/Basic1.java"},
			Sink:   &schema.Location{Symbol: "writer.println(ParameterMember-parameter[2].getWriter(Parameter-resp),ParameterMember-parameter[1].getParameter(Parameter-req,\"name\"))", Line: 39, File: "src/securibench/micro/basic/Basic1.java"},
			Sanitizers: []schema.Sanitizer{
				{Location: schema.Location{Symbol: "parameter[1].getParameter(Parameter-req,\"name\")", Line: 36, File: "src/securibench/micro/basic/Basic1.java"}},
			},
		},
	}

	diag := DiagnoseCase(c, []schema.Finding{finding}, nil, 0.80, "")

	if diag.Category != CategoryMatcherEndpointSource {
		t.Fatalf("category = %q, want %q", diag.Category, CategoryMatcherEndpointSource)
	}
	if diag.Confidence != string(ConfidenceHigh) {
		t.Fatalf("confidence = %q, want high", diag.Confidence)
	}
	if diag.BestCandidateFinding == nil {
		t.Fatal("expected best candidate finding")
	}
	if len(diag.TraceEvidence) == 0 {
		t.Fatal("expected trace evidence")
	}
	if len(diag.RuleReviewSuggestions) == 0 {
		t.Fatal("expected benchmark-side rule review suggestion")
	}
	if diag.RuleReviewSuggestions[0].RulePatchRecommended {
		t.Fatal("matcher endpoint mismatch must not recommend rule patch")
	}
}

func TestClassifyNoiseRuleForNonTargetFinding(t *testing.T) {
	cases := []schema.Case{
		{
			CaseID:   "basic-basic1-001",
			Language: "java",
			Expectation: &schema.Expectation{Type: "must_alert", Flow: &schema.Flow{
				Source: &schema.Location{Symbol: "req.getParameter", Line: 36, File: "Basic1.java"},
				Sink:   &schema.Location{Symbol: "writer.println", Line: 39, File: "Basic1.java"},
			}},
			Metadata: &schema.Metadata{CWE: "CWE-79"},
		},
	}
	finding := schema.Finding{
		RuleName: "检测Java空Catch块",
		Severity: "low",
		Flow: &schema.Flow{
			Source: &schema.Location{Symbol: "e", Line: 46, File: "src/securibench/micro/reflection/Refl2.java"},
			Sink:   &schema.Location{Symbol: "catch(Undefined-e)", Line: 44, File: "src/securibench/micro/reflection/Refl2.java"},
		},
	}

	diag := DiagnoseFinding(0, finding, cases, nil, 0.80, "")

	if diag.Category != CategoryCrossCWEOrNoiseRule {
		t.Fatalf("category = %q, want %q", diag.Category, CategoryCrossCWEOrNoiseRule)
	}
	if diag.Confidence != string(ConfidenceHigh) {
		t.Fatalf("confidence = %q, want high", diag.Confidence)
	}
	if len(diag.RuleReviewSuggestions) == 0 || diag.RuleReviewSuggestions[0].SuggestionType != "exclude_noise_rule" {
		t.Fatalf("expected exclude_noise_rule suggestion: %#v", diag.RuleReviewSuggestions)
	}
}

// TestDiagnoseCaseScopeFilterExcludesCrossCWEBestCandidate is the regression test
// for the diagnosis-side mirror of matcher distortion A: a code-quality finding
// (CWE-390, empty-catch) that shares file/source proximity with a SQLi case
// (CWE-89) must NOT become the case's BestCandidateFinding. With scope
// filtering, the cross-CWE finding is excluded from the candidate pool, so the
// case has no best candidate (BestCandidateFinding == nil) rather than pointing
// at an unrelated noise rule.
func TestDiagnoseCaseScopeFilterExcludesCrossCWEBestCandidate(t *testing.T) {
	c := schema.Case{
		CaseID:     "sqli-case-001",
		SourceCode: "Basic19.java",
		Expectation: &schema.Expectation{
			Type: "must_alert",
			Flow: &schema.Flow{
				Source: &schema.Location{Symbol: "req.getParameter", Line: 40, File: "Basic19.java"},
				Sink:   &schema.Location{Symbol: "con.prepareStatement", Line: 45, File: "Basic19.java"},
			},
		},
		Metadata: &schema.Metadata{CWE: "CWE-89"},
	}
	// Noise finding (empty-catch, CWE-390) that coincidentally scores on
	// file + source proximity. Without scope filtering it would win.
	noise := schema.Finding{
		RuleName: "检测Java空Catch块",
		CWE:      "CWE-390",
		Severity: "low",
		Flow: &schema.Flow{
			Source: &schema.Location{Symbol: "req.getParameter", Line: 40, File: "Basic19.java"},
			Sink:   &schema.Location{Symbol: "e.printStackTrace", Line: 50, File: "Basic19.java"},
		},
	}
	// In-scope SQLi finding that does not actually match this case.
	inScope := schema.Finding{
		RuleName: "检测Java SQL注入漏洞",
		CWE:      "CWE-89",
		Severity: "high",
		Flow: &schema.Flow{
			Source: &schema.Location{Symbol: "req.getParameter", Line: 40, File: "Other.java"},
			Sink:   &schema.Location{Symbol: "stmt.execute", Line: 100, File: "Other.java"},
		},
	}

	diag := DiagnoseCase(c, []schema.Finding{noise, inScope}, nil, 0.80, "")

	// The decisive assertion: best candidate must never be the noise rule.
	if diag.BestCandidateFinding != nil && diag.BestCandidateFinding.RuleName == "检测Java空Catch块" {
		t.Errorf("noise rule must not be best candidate, got %#v", diag.BestCandidateFinding)
	}
	// And if a best candidate exists, it must be in-scope (CWE-89).
	if diag.BestCandidateFinding != nil && diag.BestCandidateFinding.CWE != "CWE-89" {
		t.Errorf("best candidate CWE = %q, want CWE-89 (in-scope only)", diag.BestCandidateFinding.CWE)
	}
}

func TestFindingRuleReviewSuggestionIncludesRuleSnippetsForNoiseRule(t *testing.T) {
	dir := t.TempDir()
	rulePath := filepath.Join(dir, "java", "cwe-209-information-exposure", "java-print-stack-trace.sf")
	if err := os.MkdirAll(filepath.Dir(rulePath), 0755); err != nil {
		t.Fatal(err)
	}
	ruleContent := `desc(
	title: "PrintStackTrace"
	rule_id: "noise-rule"
)
*.printStackTrace() as $sink;
alert $sink;
`
	if err := os.WriteFile(rulePath, []byte(ruleContent), 0644); err != nil {
		t.Fatal(err)
	}
	cases := []schema.Case{
		{
			CaseID:     "basic-basic1-001",
			Language:   "java",
			SourceCode: "src/securibench/micro/basic/Basic1.java",
			Expectation: &schema.Expectation{Type: "must_alert", Flow: &schema.Flow{
				Source: &schema.Location{Symbol: "req.getParameter", Line: 36, File: "src/securibench/micro/basic/Basic1.java"},
				Sink:   &schema.Location{Symbol: "writer.println", Line: 39, File: "src/securibench/micro/basic/Basic1.java"},
			}},
			Metadata: &schema.Metadata{CWE: "CWE-79"},
		},
	}
	finding := schema.Finding{
		RuleID:   "noise-rule",
		RuleName: "检查Java通过PrintStackTrace泄露信息",
		Severity: "low",
		Flow: &schema.Flow{
			Source: &schema.Location{Symbol: "e", Line: 46, File: "src/securibench/micro/basic/Basic1.java"},
			Sink:   &schema.Location{Symbol: "e.printStackTrace", Line: 46, File: "src/securibench/micro/basic/Basic1.java"},
		},
	}

	diag := DiagnoseFinding(7, finding, cases, nil, 0.80, dir)

	if len(diag.RuleReviewSuggestions) != 1 {
		t.Fatalf("rule review suggestions = %d, want 1", len(diag.RuleReviewSuggestions))
	}
	suggestion := diag.RuleReviewSuggestions[0]
	if suggestion.RuleFile != filepath.ToSlash(rulePath) {
		t.Fatalf("rule file = %q, want %q", suggestion.RuleFile, filepath.ToSlash(rulePath))
	}
	if !strings.Contains(suggestion.OriginalSnippet, `rule_id: "noise-rule"`) {
		t.Fatalf("original snippet missing rule content: %q", suggestion.OriginalSnippet)
	}
	if !strings.Contains(suggestion.SuggestedSnippet, "Benchmark-side evidence") {
		t.Fatalf("suggested snippet missing benchmark-side note: %q", suggestion.SuggestedSnippet)
	}
}

func TestRuleReviewSuggestionIncludesRuleSnippetsForRulePatchCandidate(t *testing.T) {
	dir := t.TempDir()
	rulePath := filepath.Join(dir, "java", "cwe-79-xss", "java-servlet-xss.sf")
	if err := os.MkdirAll(filepath.Dir(rulePath), 0755); err != nil {
		t.Fatal(err)
	}
	ruleContent := `desc(
	title: "Java Servlet XSS"
	rule_id: "rule-xss"
)
*.getParameter*(,*) as $source;
*.println(* #-> * as $sink);
alert $sink for {
	source: $source
}
`
	if err := os.WriteFile(rulePath, []byte(ruleContent), 0644); err != nil {
		t.Fatal(err)
	}
	c := schema.Case{
		CaseID:     "basic-basic1-001",
		Language:   "java",
		SourceCode: "src/securibench/micro/basic/Basic1.java",
		Expectation: &schema.Expectation{
			Type: "must_alert",
			Flow: &schema.Flow{
				Source: &schema.Location{Symbol: "req.getParameter", Line: 36, File: "src/securibench/micro/basic/Basic1.java"},
				Sink:   &schema.Location{Symbol: "writer.println", Line: 39, File: "src/securibench/micro/basic/Basic1.java"},
			},
		},
		Metadata: &schema.Metadata{CWE: "CWE-79"},
	}
	finding := schema.Finding{
		RuleID:   "rule-xss",
		RuleName: "Java Servlet XSS",
		CWE:      "CWE-79",
		Severity: "middle",
		Flow: &schema.Flow{
			Source: &schema.Location{Symbol: "req.getParameter", Line: 36, File: "src/securibench/micro/basic/Basic1.java"},
			Sink:   &schema.Location{Symbol: "response.sendRedirect", Line: 39, File: "src/securibench/micro/basic/Basic1.java"},
		},
	}

	diag := DiagnoseCase(c, []schema.Finding{finding}, nil, 0.80, dir)

	if diag.Category != CategorySinkMethodMismatch {
		t.Fatalf("category = %q, want %q", diag.Category, CategorySinkMethodMismatch)
	}
	if len(diag.RuleReviewSuggestions) != 1 {
		t.Fatalf("rule review suggestions = %d, want 1", len(diag.RuleReviewSuggestions))
	}
	suggestion := diag.RuleReviewSuggestions[0]
	if !suggestion.RulePatchRecommended {
		t.Fatal("expected rule patch recommendation")
	}
	if suggestion.RuleFile != filepath.ToSlash(rulePath) {
		t.Fatalf("rule file = %q, want %q", suggestion.RuleFile, filepath.ToSlash(rulePath))
	}
	if !strings.Contains(suggestion.OriginalSnippet, `rule_id: "rule-xss"`) {
		t.Fatalf("original snippet missing rule content: %q", suggestion.OriginalSnippet)
	}
	if !strings.Contains(suggestion.SuggestedSnippet, "writer.println") {
		t.Fatalf("suggested snippet missing expected sink: %q", suggestion.SuggestedSnippet)
	}
	if len(suggestion.ValidationCommands) == 0 {
		t.Fatal("expected validation commands")
	}
}

func TestBuildReportSummarizesCategories(t *testing.T) {
	cases := []schema.Case{
		{
			CaseID:   "case-1",
			Language: "java",
			Expectation: &schema.Expectation{Type: "must_alert", Flow: &schema.Flow{
				Source: &schema.Location{Symbol: "req.getParameter", Line: 1, File: "A.java"},
				Sink:   &schema.Location{Symbol: "writer.println", Line: 2, File: "A.java"},
			}},
			Metadata: &schema.Metadata{CWE: "CWE-79"},
		},
	}
	findings := []schema.Finding{
		{
			RuleName: "检测Java空Catch块",
			Flow: &schema.Flow{
				Source: &schema.Location{Symbol: "e", Line: 10, File: "B.java"},
				Sink:   &schema.Location{Symbol: "catch", Line: 9, File: "B.java"},
			},
		},
	}
	report := BuildReport(BuildReportInput{
		ProjectID:     "p1",
		ProjectName:   "Project 1",
		Engine:        "yaklang",
		EngineVersion: "dev",
		Cases:         cases,
		Findings:      findings,
	})

	if report.ProjectID != "p1" || report.Engine != "yaklang" {
		t.Fatalf("unexpected report identity: %#v", report)
	}
	if len(report.CaseDiagnoses) != 1 {
		t.Fatalf("case diagnoses = %d, want 1", len(report.CaseDiagnoses))
	}
	if len(report.FindingDiagnoses) != 1 {
		t.Fatalf("finding diagnoses = %d, want 1", len(report.FindingDiagnoses))
	}
	if report.Summary.UnmatchedFindings != 1 {
		t.Fatalf("unmatched findings = %d, want 1", report.Summary.UnmatchedFindings)
	}
	if len(report.CategorySummary) == 0 {
		t.Fatal("expected category summary")
	}
}

func TestBuildDiagnosticBundlePrioritizesReviewsAndCommands(t *testing.T) {
	findingIndex := 3
	report := Report{
		ProjectID:     "p1",
		ProjectName:   "Project 1",
		Engine:        "yaklang",
		EngineVersion: "dev",
		Summary:       Summary{TP: 1, FN: 2, UnmatchedFindings: 3},
		CategorySummary: []CategorySummary{
			{Category: CategorySinkMethodMismatch, Count: 1},
			{Category: CategoryCrossCWEOrNoiseRule, Count: 1},
		},
		CaseDiagnoses: []CaseDiagnosis{
			{
				CaseID:     "case-rule",
				Status:     "fn",
				Category:   CategorySinkMethodMismatch,
				Confidence: string(ConfidenceMedium),
				BestCandidateFinding: &CandidateFinding{
					RuleID:   "rule-xss",
					RuleName: "Java Servlet XSS",
				},
				RuleReviewSuggestions: []RuleReviewSuggestion{{
					SuggestionID:         "s1",
					RulePatchRecommended: true,
					SuggestionType:       "add_sink",
					Confidence:           string(ConfidenceMedium),
					RuleID:               "rule-xss",
					RuleName:             "Java Servlet XSS",
					RuleFile:             "java/cwe-79-xss/java-servlet-xss.sf",
					EvidenceRefs:         []EvidenceRef{{CaseID: "case-rule"}},
					OriginalSnippet:      "alert $sink;",
					SuggestedSnippet:     "alert $sink;\n// Expected sink: writer.println",
					ValidationCommands:   []string{"validate-rule"},
				}},
			},
		},
		FindingDiagnoses: []FindingDiagnosis{
			{
				FindingIndex: findingIndex,
				Category:     CategoryCrossCWEOrNoiseRule,
				Confidence:   string(ConfidenceHigh),
				Finding: schema.Finding{
					RuleID:   "noise-rule",
					RuleName: "检查Java通过PrintStackTrace泄露信息",
				},
				RuleReviewSuggestions: []RuleReviewSuggestion{{
					SuggestionID:         "s2",
					RulePatchRecommended: false,
					SuggestionType:       "exclude_noise_rule",
					Confidence:           string(ConfidenceHigh),
					RuleID:               "noise-rule",
					RuleName:             "检查Java通过PrintStackTrace泄露信息",
					RuleFile:             "java/cwe-209/java-print-stack-trace.sf",
					EvidenceRefs:         []EvidenceRef{{FindingIndex: findingIndex}},
					OriginalSnippet:      "alert $sink;",
					SuggestedSnippet:     "alert $sink;\n// Benchmark-side evidence",
				}},
			},
		},
	}

	bundle := BuildDiagnosticBundle(report, DiagnosticBundleOptions{MaxPriorities: 4, MaxRuleReviews: 4})

	if bundle.ProjectID != "p1" || bundle.Summary.FN != 2 {
		t.Fatalf("unexpected bundle identity or summary: %#v", bundle)
	}
	if len(bundle.Priorities) != 2 {
		t.Fatalf("priorities = %d, want 2: %#v", len(bundle.Priorities), bundle.Priorities)
	}
	if bundle.Priorities[0].Category != CategoryCrossCWEOrNoiseRule {
		t.Fatalf("first priority category = %q, want noise rule", bundle.Priorities[0].Category)
	}
	if bundle.Priorities[0].FindingIndex == nil || *bundle.Priorities[0].FindingIndex != findingIndex {
		t.Fatalf("first priority finding ref missing: %#v", bundle.Priorities[0])
	}
	if len(bundle.RuleReviews) != 2 {
		t.Fatalf("rule reviews = %d, want 2: %#v", len(bundle.RuleReviews), bundle.RuleReviews)
	}
	if bundle.RuleReviews[0].OriginalSnippet == "" || bundle.RuleReviews[0].SuggestedSnippet == "" {
		t.Fatalf("rule review snippets missing: %#v", bundle.RuleReviews[0])
	}
	if len(bundle.Commands) == 0 || !contains(bundle.Commands, "irify-benchmark diagnose p1 --engine yaklang --format bundle") {
		t.Fatalf("bundle commands missing diagnose bundle command: %#v", bundle.Commands)
	}
}
