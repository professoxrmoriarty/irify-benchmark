package diagnose

import "testing"

func TestBuildRemediationPlanSplitsRuleAndBenchmarkQueues(t *testing.T) {
	report := Report{
		ProjectID: "p1",
		CaseDiagnoses: []CaseDiagnosis{
			{
				CaseID:     "case-rule",
				Status:     "fn",
				Category:   CategorySinkMethodMismatch,
				Confidence: string(ConfidenceMedium),
				RuleReviewSuggestions: []RuleReviewSuggestion{{
					SuggestionID:         "rule-s1",
					RulePatchRecommended: true,
					RuleID:               "rule-xss",
					RuleFile:             "sfbuildin/java/xss.sf",
				}},
			},
			{
				CaseID:     "case-matcher",
				Status:     "fn",
				Category:   CategoryPathOrPrefixMismatch,
				Confidence: string(ConfidenceHigh),
			},
		},
		FindingDiagnoses: []FindingDiagnosis{{
			FindingIndex: 3,
			Status:       "unmatched_finding",
			Category:     CategoryCrossCWEOrNoiseRule,
			Confidence:   string(ConfidenceHigh),
		}},
	}

	plan := BuildRemediationPlan(report)

	if len(plan.Queues) != 4 {
		t.Fatalf("queues = %d, want 4", len(plan.Queues))
	}
	if queueByID(plan, "syntaxflow-review").Count != 2 {
		t.Fatalf("syntaxflow queue = %#v", queueByID(plan, "syntaxflow-review"))
	}
	if queueByID(plan, "benchmark-or-matcher").Count != 1 {
		t.Fatalf("benchmark queue = %#v", queueByID(plan, "benchmark-or-matcher"))
	}
	if len(plan.RuleChangeGate.RequiredEvidence) == 0 {
		t.Fatalf("expected rule change gate evidence: %#v", plan.RuleChangeGate)
	}
	if plan.RuleChangeGate.AllowAutomaticPatch {
		t.Fatal("rule change gate must not allow automatic patches")
	}
}

func queueByID(plan RemediationPlan, id string) RemediationQueue {
	for _, queue := range plan.Queues {
		if queue.ID == id {
			return queue
		}
	}
	return RemediationQueue{}
}
