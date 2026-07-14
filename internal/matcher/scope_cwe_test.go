package matcher

import (
	"testing"

	"github.com/irify/irify-benchmark/pkg/schema"
)

func TestCaseExpectedCWE(t *testing.T) {
	tests := []struct {
		name string
		c    schema.Case
		want string
	}{
		{
			name: "metadata cwe returned as-is",
			c:    schema.Case{Metadata: &schema.Metadata{CWE: "CWE-89"}},
			want: "CWE-89",
		},
		{
			name: "missing metadata yields empty",
			c:    schema.Case{},
			want: "",
		},
		{
			name: "metadata present but cwe empty yields empty",
			c:    schema.Case{Metadata: &schema.Metadata{CWE: ""}},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := caseExpectedCWE(tt.c); got != tt.want {
				t.Errorf("caseExpectedCWE = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCweMatches(t *testing.T) {
	tests := []struct {
		name     string
		caseCWE  string
		findingCWE string
		want     bool
	}{
		{name: "exact match", caseCWE: "CWE-89", findingCWE: "CWE-89", want: true},
		{name: "case-insensitive match", caseCWE: "CWE-89", findingCWE: "cwe-89", want: true},
		{name: "bare number normalised", caseCWE: "CWE-89", findingCWE: "89", want: true},
		{name: "lowercase prefix normalised", caseCWE: "CWE-89", findingCWE: "cwe-89", want: true},
		{name: "mismatch", caseCWE: "CWE-89", findingCWE: "CWE-390", want: false},
		{name: "empty finding cwe is out of scope", caseCWE: "CWE-89", findingCWE: "", want: false},
		{name: "empty case cwe accepts any finding (lenient)", caseCWE: "", findingCWE: "CWE-390", want: true},
		{name: "whitespace trimmed", caseCWE: "CWE-89", findingCWE: "  CWE-89  ", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := cweMatches(tt.caseCWE, tt.findingCWE); got != tt.want {
				t.Errorf("cweMatches(%q, %q) = %v, want %v", tt.caseCWE, tt.findingCWE, got, tt.want)
			}
		})
	}
}

// TestMatch_ScopeFilterExcludesCrossCWEFindings is the regression test for the
// distortion where a code-quality rule (e.g. "empty catch", CWE-390) won the
// best-candidate slot of a SQLi case (CWE-89) purely on file/line proximity,
// producing a misleading MatchedFinding on a false negative.
//
// With scope filtering, the cross-CWE finding is excluded from the candidate
// pool: the SQLi case gets no best candidate (clean FN, finding_index=-1)
// instead of being attributed to an unrelated noise rule.
func TestMatch_ScopeFilterExcludesCrossCWEFindings(t *testing.T) {
	m := &FlowMatcher{}
	annotation := &schema.Annotation{
		BenchmarkID: "sqli-proj",
		Cases: []schema.Case{{
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
		}},
	}

	// A noise finding (empty-catch, CWE-390) that coincidentally shares file
	// and source line proximity with the SQLi case. Before the fix this would
	// score ~0.65 and become the case's MatchedFinding.
	noiseFinding := schema.Finding{
		RuleID:   "empty-catch-rule",
		RuleName: "检测Java空Catch块",
		CWE:      "CWE-390",
		Severity: "low",
		Flow: &schema.Flow{
			Source: &schema.Location{Symbol: "req.getParameter", Line: 40, File: "Basic19.java"},
			Sink:   &schema.Location{Symbol: "e.printStackTrace", Line: 50, File: "Basic19.java"},
		},
	}
	// An in-scope SQLi finding that does NOT match the case (different sink
	// line/symbol) — it scores below threshold but is in-scope, so it is the
	// only legitimate candidate.
	inScopeFinding := schema.Finding{
		RuleID:   "sqli-rule",
		RuleName: "检测Java SQL注入漏洞",
		CWE:      "CWE-89",
		Severity: "high",
		Flow: &schema.Flow{
			Source: &schema.Location{Symbol: "req.getParameter", Line: 40, File: "Other.java"},
			Sink:   &schema.Location{Symbol: "stmt.execute", Line: 100, File: "Other.java"},
		},
	}

	findings := &schema.FindingSet{Engine: "yaklang", Findings: []schema.Finding{noiseFinding, inScopeFinding}}
	result, err := m.Match(annotation, findings)
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if len(result.CaseResults) != 1 {
		t.Fatalf("expected 1 case result, got %d", len(result.CaseResults))
	}
	cr := result.CaseResults[0]
	if cr.Status != "fn" {
		t.Errorf("status = %q, want fn (no SQLi finding matched)", cr.Status)
	}
	// The decisive assertion: the case must NOT be attributed to the noise rule.
	if cr.MatchedFinding != nil && cr.MatchedFinding.RuleName == "检测Java空Catch块" {
		t.Errorf("noise rule should not be the matched finding, got %#v", cr.MatchedFinding)
	}
	// And it should not be attributed to the in-scope non-matching finding either
	// (score below threshold), so the matched finding should be the in-scope one
	// or nil. The key invariant: best candidate, when present, must be in-scope.
	if cr.MatchedFinding != nil && cr.MatchedFinding.CWE != "CWE-89" {
		t.Errorf("matched finding CWE = %q, want CWE-89 (in-scope only)", cr.MatchedFinding.CWE)
	}
}

// TestMatch_ScopeFilterKeepsInScopeTP verifies that a genuine in-scope finding
// still produces a TP when it matches, proving scope filtering does not
// suppress true positives.
func TestMatch_ScopeFilterKeepsInScopeTP(t *testing.T) {
	m := &FlowMatcher{}
	annotation := &schema.Annotation{
		BenchmarkID: "sqli-proj",
		Cases: []schema.Case{{
			CaseID:     "sqli-case-002",
			SourceCode: "Basic21.java",
			Expectation: &schema.Expectation{
				Type: "must_alert",
				Flow: &schema.Flow{
					Source: &schema.Location{Symbol: "req.getParameter", Line: 41, File: "Basic21.java"},
					Sink:   &schema.Location{Symbol: "stmt.executeQuery", Line: 53, File: "Basic21.java"},
				},
			},
			Metadata: &schema.Metadata{CWE: "CWE-89"},
		}},
	}
	tpFinding := schema.Finding{
		RuleID:   "sqli-rule",
		RuleName: "检测Java SQL注入漏洞",
		CWE:      "CWE-89",
		Severity: "high",
		Flow: &schema.Flow{
			Source: &schema.Location{Symbol: "req.getParameter", Line: 41, File: "Basic21.java"},
			Sink:   &schema.Location{Symbol: "stmt.executeQuery", Line: 53, File: "Basic21.java"},
		},
	}
	// Noise present alongside the TP — must not interfere.
	noise := schema.Finding{
		RuleID: "noise", RuleName: "检测Java空Catch块", CWE: "CWE-390", Severity: "low",
		Flow: &schema.Flow{
			Source: &schema.Location{Symbol: "req.getParameter", Line: 41, File: "Basic21.java"},
			Sink:   &schema.Location{Symbol: "e.printStackTrace", Line: 53, File: "Basic21.java"},
		},
	}
	findings := &schema.FindingSet{Engine: "yaklang", Findings: []schema.Finding{noise, tpFinding}}
	result, err := m.Match(annotation, findings)
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if result.CaseResults[0].Status != "tp" {
		t.Errorf("status = %q, want tp", result.CaseResults[0].Status)
	}
	if result.Summary.TP != 1 {
		t.Errorf("summary TP = %d, want 1", result.Summary.TP)
	}
}

// TestMatch_ExactFlowMatchPreferredOverFuzzy verifies that a finding whose
// source/sink precisely cover a case's annotated source/sink (line+method)
// wins the best-candidate slot and produces a TP, even when another in-scope
// finding scores higher on the fuzzy proximity heuristic. This is the
// distortion-B fix: matching is anchored to precise source/sink coverage
// rather than proximity score.
//
// The discriminating setup: the fuzzy finding has a HIGHER fuzzy score
// (matching file + source symbol + tighter line proximity) but its sink does
// NOT precisely cover the case sink (wrong method/line). The precise finding
// has a LOWER fuzzy score (its SSA source symbol does not string-match the
// case's source symbol under the legacy heuristic) but its source AND sink
// both precisely cover the case. Without exact-match priority the fuzzy
// finding would win on proximity and the case would be FN; with it, the
// precise finding wins and the case is TP.
func TestMatch_ExactFlowMatchPreferredOverFuzzy(t *testing.T) {
	m := &FlowMatcher{}
	annotation := &schema.Annotation{
		BenchmarkID: "sqli-proj",
		Cases: []schema.Case{{
			CaseID:     "sqli-tp",
			SourceCode: "Basic21.java",
			Expectation: &schema.Expectation{
				Type: "must_alert",
				Flow: &schema.Flow{
					Source: &schema.Location{Symbol: "req.getParameter", Line: 42, File: "Basic21.java"},
					Sink:   &schema.Location{Symbol: "stmt.executeQuery", Line: 53, File: "Basic21.java"},
				},
			},
			Metadata: &schema.Metadata{CWE: "CWE-89"},
		}},
	}
	// Precise finding: source/sink lines (42/53) and methods (getParameter/
	// executeQuery) align with the case. Its source symbol is SSA-style
	// ("parameter.getParameter") which the legacy fuzzy symbol matcher may
	// not fully credit, giving it a lower fuzzy score than the decoy below.
	precise := schema.Finding{
		RuleID: "sqli-rule", RuleName: "检测Java SQL注入漏洞", CWE: "CWE-89", Severity: "high",
		Kind: schema.FindingKindTaint,
		Flow: &schema.Flow{
			Source: &schema.Location{Symbol: "parameter.getParameter", Line: 42, File: "src/Basic21.java"},
			Sink:   &schema.Location{Symbol: "stmt.executeQuery", Line: 53, File: "src/Basic21.java"},
		},
	}
	// Decoy finding: maximises the fuzzy heuristic (exact source symbol
	// string match + same file + adjacent lines) but its sink is on a
	// different method/line (executeUpdate@49) so it does NOT precisely
	// cover the case sink. The fuzzy score is high; precise match is false.
	decoy := schema.Finding{
		RuleID: "sqli-decoy", RuleName: "其他SQLi", CWE: "CWE-89", Severity: "high",
		Kind: schema.FindingKindTaint,
		Flow: &schema.Flow{
			Source: &schema.Location{Symbol: "req.getParameter", Line: 42, File: "src/Basic21.java"},
			Sink:   &schema.Location{Symbol: "stmt.executeUpdate", Line: 54, File: "src/Basic21.java"},
		},
	}
	findings := &schema.FindingSet{Engine: "yaklang", Findings: []schema.Finding{decoy, precise}}
	result, err := m.Match(annotation, findings)
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	cr := result.CaseResults[0]
	if cr.Status != "tp" {
		t.Errorf("status = %q, want tp (precise match should win over fuzzy decoy)", cr.Status)
	}
	if cr.MatchedFinding == nil || cr.MatchedFinding.RuleID != "sqli-rule" {
		t.Errorf("matched finding = %+v, want sqli-rule (precise, not decoy)", cr.MatchedFinding)
	}
}

// TestMatch_FanInFindingsEachMatchTheirCase is the fan-in regression test.
// yak reports one risk per source->sink path, so when multiple sources flow
// into the same sink (fan-in), multiple findings share the sink location but
// differ by source. Each case annotated with a distinct source should match
// its own finding (precise source coverage), producing one TP per case,
// rather than one finding stealing the slot and leaving the others as FN.
func TestMatch_FanInFindingsEachMatchTheirCase(t *testing.T) {
	m := &FlowMatcher{}
	annotation := &schema.Annotation{
		BenchmarkID: "fan-in-proj",
		Cases: []schema.Case{
			{
				CaseID:     "fan-case-a",
				SourceCode: "Sink.java",
				Expectation: &schema.Expectation{Type: "must_alert", Flow: &schema.Flow{
					Source: &schema.Location{Symbol: "req.getParameter", Line: 10, File: "Sink.java"},
					Sink:   &schema.Location{Symbol: "stmt.executeQuery", Line: 50, File: "Sink.java"},
				}},
				Metadata: &schema.Metadata{CWE: "CWE-89"},
			},
			{
				CaseID:     "fan-case-b",
				SourceCode: "Sink.java",
				Expectation: &schema.Expectation{Type: "must_alert", Flow: &schema.Flow{
					Source: &schema.Location{Symbol: "req.getHeader", Line: 20, File: "Sink.java"},
					Sink:   &schema.Location{Symbol: "stmt.executeQuery", Line: 50, File: "Sink.java"},
				}},
				Metadata: &schema.Metadata{CWE: "CWE-89"},
			},
		},
	}
	// Two findings share the sink (line 50, executeQuery) but have distinct
	// sources (getParameter@10 vs getHeader@20) — classic fan-in.
	findings := &schema.FindingSet{Engine: "yaklang", Findings: []schema.Finding{
		{
			RuleID: "sqli", RuleName: "SQLi", CWE: "CWE-89", Severity: "high", Kind: schema.FindingKindTaint,
			Flow: &schema.Flow{
				Source: &schema.Location{Symbol: "parameter.getParameter", Line: 10, File: "src/Sink.java"},
				Sink:   &schema.Location{Symbol: "stmt.executeQuery", Line: 50, File: "src/Sink.java"},
			},
		},
		{
			RuleID: "sqli", RuleName: "SQLi", CWE: "CWE-89", Severity: "high", Kind: schema.FindingKindTaint,
			Flow: &schema.Flow{
				Source: &schema.Location{Symbol: "req.getHeader", Line: 20, File: "src/Sink.java"},
				Sink:   &schema.Location{Symbol: "stmt.executeQuery", Line: 50, File: "src/Sink.java"},
			},
		},
	}}
	result, err := m.Match(annotation, findings)
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if result.Summary.TP != 2 {
		t.Errorf("summary TP = %d, want 2 (fan-in: each case matches its own finding)", result.Summary.TP)
	}
	for _, cr := range result.CaseResults {
		if cr.Status != "tp" {
			t.Errorf("case %s status = %q, want tp", cr.CaseID, cr.Status)
		}
	}
}