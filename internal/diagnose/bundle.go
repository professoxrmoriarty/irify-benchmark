package diagnose

import (
	"fmt"
	"sort"
)

type DiagnosticBundleOptions struct {
	MaxPriorities  int
	MaxRuleReviews int
}

func BuildDiagnosticBundle(report Report, options DiagnosticBundleOptions) DiagnosticBundle {
	if options.MaxPriorities <= 0 {
		options.MaxPriorities = 12
	}
	if options.MaxRuleReviews <= 0 {
		options.MaxRuleReviews = 8
	}

	bundle := DiagnosticBundle{
		ProjectID:     report.ProjectID,
		ProjectName:   report.ProjectName,
		Engine:        report.Engine,
		EngineVersion: report.EngineVersion,
		Summary:       report.Summary,
		Categories:    report.CategorySummary,
		Commands: []string{
			fmt.Sprintf("irify-benchmark diagnose %s --engine %s --format bundle", report.ProjectID, report.Engine),
			fmt.Sprintf("irify-benchmark diagnose %s --engine %s --format markdown", report.ProjectID, report.Engine),
			fmt.Sprintf("irify-benchmark diagnose %s --engine %s --format json", report.ProjectID, report.Engine),
		},
		Notes: []string{
			"Bundle output is intentionally smaller than the full diagnosis report.",
			"Rule suggestions are review guidance only; they must not be applied without SyntaxFlow validation.",
			"Unmatched findings are FP-like pending review, not final false positives.",
		},
	}

	priorities := buildBundlePriorities(report)
	if len(priorities) > options.MaxPriorities {
		priorities = priorities[:options.MaxPriorities]
	}
	bundle.Priorities = priorities

	reviews := buildBundleRuleReviews(report)
	if len(reviews) > options.MaxRuleReviews {
		reviews = reviews[:options.MaxRuleReviews]
	}
	bundle.RuleReviews = reviews
	return bundle
}

func buildBundlePriorities(report Report) []BundlePriority {
	var items []BundlePriority
	for _, diag := range report.CaseDiagnoses {
		if diag.Category == CategoryMatchedTP {
			continue
		}
		item := BundlePriority{
			Kind:       "case",
			Category:   diag.Category,
			Confidence: diag.Confidence,
			CaseID:     diag.CaseID,
			Reason:     reasonForCategory(diag.Category),
			NextAction: nextActionForCategory(diag.Category),
		}
		if diag.BestCandidateFinding != nil {
			item.RuleID = diag.BestCandidateFinding.RuleID
			item.RuleName = diag.BestCandidateFinding.RuleName
		}
		items = append(items, item)
	}
	for _, diag := range report.FindingDiagnoses {
		item := BundlePriority{
			Kind:         "finding",
			Category:     diag.Category,
			Confidence:   diag.Confidence,
			FindingIndex: intPtr(diag.FindingIndex),
			RuleID:       diag.Finding.RuleID,
			RuleName:     diag.Finding.RuleName,
			Reason:       reasonForCategory(diag.Category),
			NextAction:   nextActionForCategory(diag.Category),
		}
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		if bundlePriorityRank(items[i]) != bundlePriorityRank(items[j]) {
			return bundlePriorityRank(items[i]) > bundlePriorityRank(items[j])
		}
		if confidenceRank(items[i].Confidence) != confidenceRank(items[j].Confidence) {
			return confidenceRank(items[i].Confidence) > confidenceRank(items[j].Confidence)
		}
		if items[i].Kind != items[j].Kind {
			return items[i].Kind < items[j].Kind
		}
		return items[i].CaseID < items[j].CaseID
	})
	for i := range items {
		items[i].Priority = i + 1
	}
	return items
}

func buildBundleRuleReviews(report Report) []BundleRuleReview {
	seen := map[string]bool{}
	var items []BundleRuleReview
	add := func(s RuleReviewSuggestion) {
		key := s.SuggestionID
		if key == "" {
			key = s.RuleID + "|" + s.RuleName + "|" + s.RuleFile + "|" + s.SuggestionType
		}
		if seen[key] {
			return
		}
		seen[key] = true
		items = append(items, BundleRuleReview{
			SuggestionID:         s.SuggestionID,
			RulePatchRecommended: s.RulePatchRecommended,
			SuggestionType:       s.SuggestionType,
			Confidence:           s.Confidence,
			RuleID:               s.RuleID,
			RuleName:             s.RuleName,
			RuleFile:             s.RuleFile,
			EvidenceRefs:         s.EvidenceRefs,
			OriginalSnippet:      s.OriginalSnippet,
			SuggestedSnippet:     s.SuggestedSnippet,
			ReviewComments:       s.ReviewComments,
			ValidationCommands:   s.ValidationCommands,
		})
	}
	for _, diag := range report.CaseDiagnoses {
		for _, suggestion := range diag.RuleReviewSuggestions {
			add(suggestion)
		}
	}
	for _, diag := range report.FindingDiagnoses {
		for _, suggestion := range diag.RuleReviewSuggestions {
			add(suggestion)
		}
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].RulePatchRecommended != items[j].RulePatchRecommended {
			return items[i].RulePatchRecommended
		}
		if confidenceRank(items[i].Confidence) != confidenceRank(items[j].Confidence) {
			return confidenceRank(items[i].Confidence) > confidenceRank(items[j].Confidence)
		}
		return items[i].SuggestionID < items[j].SuggestionID
	})
	return items
}

func bundlePriorityRank(item BundlePriority) int {
	switch item.Category {
	case CategoryCrossCWEOrNoiseRule, CategoryRulePrecisionIssue, CategorySinkMethodMismatch:
		return 5
	case CategoryMatcherEndpointSource, CategoryPathOrPrefixMismatch, CategoryConverterLoss:
		return 4
	case CategoryDuplicateFindingForCase:
		return 3
	case CategoryUnknown:
		return 2
	default:
		return 1
	}
}

func reasonForCategory(category Category) string {
	switch category {
	case CategoryCrossCWEOrNoiseRule:
		return "The finding is likely outside the benchmark target class or caused by a noisy rule."
	case CategorySinkMethodMismatch:
		return "The nearest finding keeps the source context but does not match the expected sink."
	case CategoryMatcherEndpointSource:
		return "Trace evidence suggests the rule may have matched, but benchmark matcher endpoints differ."
	case CategoryPathOrPrefixMismatch:
		return "Source paths or prefixes prevent the finding from matching the benchmark case."
	case CategoryDuplicateFindingForCase:
		return "A nearby case already has a matched finding; this may be a duplicate or dedupe issue."
	case CategoryUnknown:
		return "The current structured evidence is not enough to decide root cause."
	default:
		return "Review the diagnosis evidence before changing benchmark data or SyntaxFlow rules."
	}
}

func nextActionForCategory(category Category) string {
	switch category {
	case CategoryCrossCWEOrNoiseRule:
		return "Review the rule snippet and decide whether to scope the benchmark, suppress noise, or add rule guards."
	case CategorySinkMethodMismatch:
		return "Ask AI to compare expected sink with the SyntaxFlow sink definition and propose a minimal rule diff."
	case CategoryMatcherEndpointSource, CategoryPathOrPrefixMismatch, CategoryConverterLoss:
		return "Inspect matcher, converter output, and benchmark expectation before changing SyntaxFlow."
	case CategoryDuplicateFindingForCase:
		return "Inspect dedupe and nearest-case matching; avoid weakening the rule before confirming duplicate behavior."
	case CategoryUnknown:
		return "Collect source code, trace evidence, and candidate rule content for semantic analysis."
	default:
		return "Use the validation commands in this bundle and re-run diagnosis after any change."
	}
}

func intPtr(value int) *int {
	return &value
}
