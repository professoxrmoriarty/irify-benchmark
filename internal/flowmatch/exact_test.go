package flowmatch

import (
	"testing"

	"github.com/irify/irify-benchmark/pkg/schema"
)

func TestExactFlowMatch_PreciseTaintTP(t *testing.T) {
	c := schema.Case{
		SourceCode: "securibench/micro/basic/Basic21.java",
		Expectation: &schema.Expectation{
			Type: "must_alert",
			Flow: &schema.Flow{
				Source: &schema.Location{Symbol: "req.getParameter", Line: 42, File: "securibench/micro/basic/Basic21.java"},
				Sink:   &schema.Location{Symbol: "stmt.executeQuery", Line: 53, File: "securibench/micro/basic/Basic21.java"},
			},
		},
	}
	f := schema.Finding{
		Kind: schema.FindingKindTaint,
		Flow: &schema.Flow{
			Source: &schema.Location{Symbol: "ParameterMember-parameter[1].getParameter(Parameter-req,\"name\")", Line: 42, File: "src/securibench/micro/basic/Basic21.java"},
			Sink:   &schema.Location{Symbol: "Undefined-stmt.executeQuery(...)", Line: 53, File: "src/securibench/micro/basic/Basic21.java"},
		},
	}
	if !ExactFlowMatch(c, f) {
		t.Error("expected precise match for source/sink line+method aligned, got false")
	}
}

func TestExactFlowMatch_LineToleranceWindow(t *testing.T) {
	c := schema.Case{
		SourceCode: "Basic21.java",
		Expectation: &schema.Expectation{Flow: &schema.Flow{
			Source: &schema.Location{Symbol: "req.getParameter", Line: 42, File: "Basic21.java"},
			Sink:   &schema.Location{Symbol: "stmt.executeQuery", Line: 53, File: "Basic21.java"},
		}},
	}
	// yak entry node anchored at line 41 (off-by-one from source line 42).
	f := schema.Finding{
		Kind: schema.FindingKindTaint,
		Flow: &schema.Flow{
			Source: &schema.Location{Symbol: "Parameter-req", Line: 41, File: "src/Basic21.java"},
			Sink:   &schema.Location{Symbol: "stmt.executeQuery", Line: 53, File: "src/Basic21.java"},
		},
	}
	// source symbol "req" has no method segment "getParameter" -> should NOT match.
	if ExactFlowMatch(c, f) {
		t.Error("source symbol missing getParameter method should not precise-match")
	}
}

func TestExactFlowMatch_LineToleranceButMethodMatches(t *testing.T) {
	c := schema.Case{
		SourceCode: "Basic21.java",
		Expectation: &schema.Expectation{Flow: &schema.Flow{
			Source: &schema.Location{Symbol: "req.getParameter", Line: 42, File: "Basic21.java"},
			Sink:   &schema.Location{Symbol: "stmt.executeQuery", Line: 53, File: "Basic21.java"},
		}},
	}
	// entry node off-by-one (41 vs 42) but the finding source still carries
	// the getParameter method (e.g. converter picked the real call node on a
	// nearby line). Within tolerance + method matches -> precise match.
	f := schema.Finding{
		Kind: schema.FindingKindTaint,
		Flow: &schema.Flow{
			Source: &schema.Location{Symbol: "parameter[1].getParameter", Line: 41, File: "src/Basic21.java"},
			Sink:   &schema.Location{Symbol: "stmt.executeQuery", Line: 53, File: "src/Basic21.java"},
		},
	}
	if !ExactFlowMatch(c, f) {
		t.Error("expected precise match within line tolerance with method match")
	}
}

func TestExactFlowMatch_SinkLineOutOfTolerance(t *testing.T) {
	c := schema.Case{
		SourceCode: "Basic21.java",
		Expectation: &schema.Expectation{Flow: &schema.Flow{
			Source: &schema.Location{Symbol: "req.getParameter", Line: 42, File: "Basic21.java"},
			Sink:   &schema.Location{Symbol: "stmt.executeQuery", Line: 53, File: "Basic21.java"},
		}},
	}
	f := schema.Finding{
		Kind: schema.FindingKindTaint,
		Flow: &schema.Flow{
			Source: &schema.Location{Symbol: "parameter.getParameter", Line: 42, File: "src/Basic21.java"},
			Sink:   &schema.Location{Symbol: "stmt.executeQuery", Line: 100, File: "src/Basic21.java"},
		},
	}
	if ExactFlowMatch(c, f) {
		t.Error("sink line 100 vs 53 should not match (out of tolerance)")
	}
}

func TestExactFlowMatch_NonTaintFindingNeverMatchesTaintCase(t *testing.T) {
	c := schema.Case{
		SourceCode: "Basic21.java",
		Expectation: &schema.Expectation{Flow: &schema.Flow{
			Source: &schema.Location{Symbol: "req.getParameter", Line: 42, File: "Basic21.java"},
			Sink:   &schema.Location{Symbol: "stmt.executeQuery", Line: 53, File: "Basic21.java"},
		}},
	}
	// path-kind finding (resource leak): has a flow-like structure but not taint.
	f := schema.Finding{
		Kind: schema.FindingKindPath,
		Flow: &schema.Flow{
			Source: &schema.Location{Symbol: "con.createStatement", Line: 48, File: "src/Basic21.java"},
			Sink:   &schema.Location{Symbol: "con.createStatement", Line: 48, File: "src/Basic21.java"},
		},
	}
	if ExactFlowMatch(c, f) {
		t.Error("non-taint finding must not precise-match a taint case")
	}
}

func TestExactFlowMatch_EmptyKindTreatedAsTaint(t *testing.T) {
	c := schema.Case{
		SourceCode: "Basic21.java",
		Expectation: &schema.Expectation{Flow: &schema.Flow{
			Source: &schema.Location{Symbol: "req.getParameter", Line: 42, File: "Basic21.java"},
			Sink:   &schema.Location{Symbol: "stmt.executeQuery", Line: 53, File: "Basic21.java"},
		}},
	}
	f := schema.Finding{
		Kind: "", // legacy finding without Kind
		Flow: &schema.Flow{
			Source: &schema.Location{Symbol: "parameter.getParameter", Line: 42, File: "src/Basic21.java"},
			Sink:   &schema.Location{Symbol: "stmt.executeQuery", Line: 53, File: "src/Basic21.java"},
		},
	}
	if !ExactFlowMatch(c, f) {
		t.Error("empty Kind should be treated as taint for backward compatibility")
	}
}

func TestExactFlowMatch_WrongFileNoMatch(t *testing.T) {
	c := schema.Case{
		SourceCode: "Basic21.java",
		Expectation: &schema.Expectation{Flow: &schema.Flow{
			Source: &schema.Location{Symbol: "req.getParameter", Line: 42, File: "Basic21.java"},
			Sink:   &schema.Location{Symbol: "stmt.executeQuery", Line: 53, File: "Basic21.java"},
		}},
	}
	f := schema.Finding{
		Kind: schema.FindingKindTaint,
		Flow: &schema.Flow{
			Source: &schema.Location{Symbol: "parameter.getParameter", Line: 42, File: "src/Other.java"},
			Sink:   &schema.Location{Symbol: "stmt.executeQuery", Line: 53, File: "src/Other.java"},
		},
	}
	if ExactFlowMatch(c, f) {
		t.Error("wrong file should not match")
	}
}

func TestExactFlowMatch_PartialMethodNoMatch(t *testing.T) {
	c := schema.Case{
		SourceCode: "Basic21.java",
		Expectation: &schema.Expectation{Flow: &schema.Flow{
			Source: &schema.Location{Symbol: "req.getParameter", Line: 42, File: "Basic21.java"},
			Sink:   &schema.Location{Symbol: "stmt.execute", Line: 53, File: "Basic21.java"},
		}},
	}
	// case sink "execute" must not match finding sink "executeQuery" (segment-aware).
	f := schema.Finding{
		Kind: schema.FindingKindTaint,
		Flow: &schema.Flow{
			Source: &schema.Location{Symbol: "parameter.getParameter", Line: 42, File: "src/Basic21.java"},
			Sink:   &schema.Location{Symbol: "stmt.executeQuery", Line: 53, File: "src/Basic21.java"},
		},
	}
	if ExactFlowMatch(c, f) {
		t.Error("'execute' must not match 'executeQuery' (segment-aware method match)")
	}
}