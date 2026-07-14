package diagnose

func BuildRemediationPlan(report Report) RemediationPlan {
	queues := map[string]*RemediationQueue{
		"syntaxflow-review": {
			ID:         "syntaxflow-review",
			Label:      "SyntaxFlow Review",
			Owner:      "Rule reviewer",
			Risk:       "high",
			Goal:       "Only review SyntaxFlow changes when evidence points to rule precision or missing sink/source behavior.",
			NextAction: "Open rule review, inspect original rule snippet, ask AI for review-only diff, then run validation commands.",
			Categories: []string{
				string(CategorySinkMethodMismatch),
				string(CategoryRulePrecisionIssue),
				string(CategoryCrossCWEOrNoiseRule),
				string(CategoryNoSameCWEFinding),
			},
		},
		"benchmark-or-matcher": {
			ID:         "benchmark-or-matcher",
			Label:      "Benchmark / Matcher",
			Owner:      "Benchmark maintainer",
			Risk:       "medium",
			Goal:       "Fix benchmark expectation, path normalization, matcher endpoint logic, or converter loss before touching rules.",
			NextAction: "Inspect case expectation, source_root, path prefixes, matcher score, and trace evidence.",
			Categories: []string{
				string(CategoryMatcherEndpointSource),
				string(CategoryPathOrPrefixMismatch),
				string(CategoryConverterLoss),
				string(CategoryPossibleTruthError),
			},
		},
		"dedupe-review": {
			ID:         "dedupe-review",
			Label:      "Dedupe Review",
			Owner:      "Matcher maintainer",
			Risk:       "medium",
			Goal:       "Handle repeated findings without weakening rules prematurely.",
			NextAction: "Check nearest case matching and duplicate suppression before any rule guard change.",
			Categories: []string{string(CategoryDuplicateFindingForCase)},
		},
		"needs-evidence": {
			ID:         "needs-evidence",
			Label:      "Needs Evidence",
			Owner:      "AI + human reviewer",
			Risk:       "unknown",
			Goal:       "Collect enough source, trace, and rule evidence to decide the remediation owner.",
			NextAction: "Generate prompt/manifest, include source snippets and candidate rule content, then validate AI response.",
			Categories: []string{string(CategoryUnknown)},
		},
	}

	for _, diag := range report.CaseDiagnoses {
		queue := queueForCategory(queues, diag.Category)
		queue.Count++
		queue.CaseIDs = append(queue.CaseIDs, diag.CaseID)
	}
	for _, diag := range report.FindingDiagnoses {
		queue := queueForCategory(queues, diag.Category)
		queue.Count++
		queue.FindingRefs = append(queue.FindingRefs, diag.FindingIndex)
	}

	return RemediationPlan{
		Queues: []RemediationQueue{
			*queues["syntaxflow-review"],
			*queues["benchmark-or-matcher"],
			*queues["dedupe-review"],
			*queues["needs-evidence"],
		},
		RuleChangeGate: RuleChangeGate{
			AllowAutomaticPatch: false,
			RequiredEvidence: []string{
				"A rule review queue item with case_id or finding_index evidence references.",
				"Original SyntaxFlow rule snippet and review-only suggested diff.",
				"At least one positive case and one safe/noise case considered before rule changes.",
				"Matcher/path/converter categories ruled out for the same case.",
			},
			ValidationCommands: []string{
				"GOCACHE=/tmp/irify-benchmark-go-build go test ./internal/diagnose ./cmd/irify-benchmark -count=1",
				"irify-benchmark diagnose <project-id> --engine yaklang --format json",
				"irify-benchmark diagnose validate-response --file ai-response.md",
			},
		},
	}
}

func queueForCategory(queues map[string]*RemediationQueue, category Category) *RemediationQueue {
	switch category {
	case CategorySinkMethodMismatch, CategoryRulePrecisionIssue, CategoryCrossCWEOrNoiseRule, CategoryNoSameCWEFinding:
		return queues["syntaxflow-review"]
	case CategoryMatcherEndpointSource, CategoryPathOrPrefixMismatch, CategoryConverterLoss, CategoryPossibleTruthError:
		return queues["benchmark-or-matcher"]
	case CategoryDuplicateFindingForCase:
		return queues["dedupe-review"]
	default:
		return queues["needs-evidence"]
	}
}
