package matcher

import (
	"testing"

	"github.com/irify/irify-benchmark/pkg/schema"
)

func TestScore_ExactMatch(t *testing.T) {
	c := schema.Case{
		CaseID:     "case-001",
		SourceCode: "cases/java/cmdi-001/Hello.java",
		Expectation: &schema.Expectation{
			Type: "must_alert",
			Flow: &schema.Flow{
				Source: &schema.Location{Symbol: "request.getParameter", Line: 12, File: "Hello.java"},
				Sink:   &schema.Location{Symbol: "Runtime.exec", Line: 18, File: "Hello.java"},
			},
		},
	}
	f := schema.Finding{
		RuleID: "java-cmdi-001",
		Flow: &schema.Flow{
			Source: &schema.Location{Symbol: "request.getParameter", Line: 12, File: "Hello.java"},
			Sink:   &schema.Location{Symbol: "Runtime.exec", Line: 18, File: "Hello.java"},
		},
	}

	score := Score(c, f)
	if score.Total < 0.80 {
		t.Errorf("expected score >= 0.80 for exact match, got %.2f", score.Total)
	}
	if !score.SourceMatch {
		t.Error("expected SourceMatch to be true")
	}
	if !score.SinkMatch {
		t.Error("expected SinkMatch to be true")
	}
	if !score.TraceComplete {
		t.Error("expected TraceComplete to be true")
	}
	if score.LineDistance != 0 {
		t.Errorf("expected LineDistance 0, got %d", score.LineDistance)
	}
}

func TestScore_WrongSymbol(t *testing.T) {
	c := schema.Case{
		CaseID:     "case-002",
		SourceCode: "cases/java/cmdi-001/Hello.java",
		Expectation: &schema.Expectation{
			Type: "must_alert",
			Flow: &schema.Flow{
				Source: &schema.Location{Symbol: "request.getParameter", Line: 12, File: "Hello.java"},
				Sink:   &schema.Location{Symbol: "Runtime.exec", Line: 18, File: "Hello.java"},
			},
		},
	}
	f := schema.Finding{
		RuleID: "java-cmdi-001",
		Flow: &schema.Flow{
			Source: &schema.Location{Symbol: "wrong.source", Line: 100, File: "Hello.java"},
			Sink:   &schema.Location{Symbol: "wrong.sink", Line: 200, File: "Hello.java"},
		},
	}

	score := Score(c, f)
	if score.Total >= 0.50 {
		t.Errorf("expected score < 0.50 for wrong symbols, got %.2f", score.Total)
	}
	if score.SourceMatch {
		t.Error("expected SourceMatch to be false")
	}
	if score.SinkMatch {
		t.Error("expected SinkMatch to be false")
	}
}

func TestScore_PartialMatch(t *testing.T) {
	c := schema.Case{
		CaseID:     "case-003",
		SourceCode: "cases/java/cmdi-001/Hello.java",
		Expectation: &schema.Expectation{
			Type: "must_alert",
			Flow: &schema.Flow{
				Source: &schema.Location{Symbol: "request.getParameter", Line: 12, File: "Hello.java"},
				Sink:   &schema.Location{Symbol: "Runtime.exec", Line: 18, File: "Hello.java"},
			},
		},
	}
	f := schema.Finding{
		RuleID: "java-cmdi-001",
		Flow: &schema.Flow{
			Source: &schema.Location{Symbol: "request.getParameter", Line: 13, File: "Hello.java"},
			Sink:   &schema.Location{Symbol: "Other.sink", Line: 25, File: "Hello.java"},
		},
	}

	score := Score(c, f)
	// file (0.30) + source symbol (0.25) + partial line proximity (0.10 because source is close but sink is far)
	expected := 0.65
	if score.Total < expected-0.05 || score.Total > expected+0.05 {
		t.Errorf("expected score ~%.2f for partial match, got %.2f", expected, score.Total)
	}
	if !score.SourceMatch {
		t.Error("expected SourceMatch to be true")
	}
	if score.SinkMatch {
		t.Error("expected SinkMatch to be false")
	}
}

func TestScore_SanitizerMatch(t *testing.T) {
	c := schema.Case{
		CaseID:     "case-004",
		SourceCode: "cases/go/sqli-001/main.go",
		Expectation: &schema.Expectation{
			Type: "must_alert",
			Flow: &schema.Flow{
				Source:     &schema.Location{Symbol: "r.FormValue", Line: 10, File: "main.go"},
				Sanitizers: []schema.Sanitizer{{Location: schema.Location{Symbol: "sanitizeInput", Line: 12, File: "main.go"}}},
				Sink:       &schema.Location{Symbol: "db.Query", Line: 15, File: "main.go"},
			},
		},
	}
	f := schema.Finding{
		RuleID: "go-sqli-001",
		Flow: &schema.Flow{
			Source:     &schema.Location{Symbol: "r.FormValue", Line: 10, File: "main.go"},
			Sanitizers: []schema.Sanitizer{{Location: schema.Location{Symbol: "sanitizeInput", Line: 12, File: "main.go"}}},
			Sink:       &schema.Location{Symbol: "db.Query", Line: 15, File: "main.go"},
		},
	}

	score := Score(c, f)
	if !score.SanitizerMatch {
		t.Error("expected SanitizerMatch to be true")
	}
}

func TestScore_NoOverlap(t *testing.T) {
	c := schema.Case{
		CaseID:     "case-005",
		SourceCode: "cases/java/cmdi-001/Hello.java",
		Expectation: &schema.Expectation{
			Type: "must_alert",
			Flow: &schema.Flow{
				Source: &schema.Location{Symbol: "request.getParameter", Line: 12, File: "Hello.java"},
				Sink:   &schema.Location{Symbol: "Runtime.exec", Line: 18, File: "Hello.java"},
			},
		},
	}
	f := schema.Finding{
		RuleID: "java-cmdi-001",
		Flow: &schema.Flow{
			Source: &schema.Location{Symbol: "request.getParameter", Line: 12, File: "Other.java"},
			Sink:   &schema.Location{Symbol: "Runtime.exec", Line: 18, File: "Other.java"},
		},
	}

	score := Score(c, f)
	// Score itself does not gate on file overlap; the matcher filters candidates.
	// Symbols and lines match, so we expect 0.25 + 0.25 + 0.20 = 0.70 without file path.
	if score.Total < 0.65 || score.Total > 0.75 {
		t.Errorf("expected score ~0.70 for symbol match without file overlap, got %.2f", score.Total)
	}
	if score.SourceMatch != true || score.SinkMatch != true {
		t.Error("expected source and sink symbol matches to be true")
	}
}
