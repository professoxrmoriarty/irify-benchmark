package matcher

import (
	"fmt"
	"time"

	"github.com/irify/irify-benchmark/pkg/eval"
	"github.com/irify/irify-benchmark/pkg/schema"
)

// Matcher compares annotations against engine findings and produces evaluation results.
type Matcher interface {
	// Match evaluates findings against the ground-truth annotation set.
	Match(annotation *schema.Annotation, findings *schema.FindingSet) (*schema.Result, error)
}

// FlowMatcher implements a threshold-based flow-aware matching strategy.
type FlowMatcher struct {
	Threshold float64 // default 0.80
}

// Match evaluates each case in the annotation against the provided findings.
// It resolves conflicts when a single finding is the best match for multiple cases
// by assigning the finding to the highest-scoring case.
func (m *FlowMatcher) Match(annotation *schema.Annotation, findings *schema.FindingSet) (*schema.Result, error) {
	if annotation == nil {
		return nil, fmt.Errorf("annotation is nil")
	}
	if findings == nil {
		return nil, fmt.Errorf("findings is nil")
	}

	threshold := m.Threshold
	if threshold == 0 {
		threshold = 0.80
	}

	// First pass: compute best match for each case.
	type caseMatch struct {
		caseIdx        int
		findingIdx     int
		score          MatchScore
		matchedFinding *schema.MatchedFinding
	}

	matches := make([]caseMatch, 0, len(annotation.Cases))
	for i, c := range annotation.Cases {
		best := caseMatch{caseIdx: i, findingIdx: -1}
		for j, f := range findings.Findings {
			score := Score(c, f)
			if score.Total > best.score.Total {
				best.score = score
				best.findingIdx = j
				best.matchedFinding = &schema.MatchedFinding{
					RuleID:   f.RuleID,
					RuleName: f.RuleName,
					Severity: f.Severity,
				}
			}
		}
		matches = append(matches, best)
	}

	// Resolve conflicts: a finding can only match one case.
	// Build a map from findingIdx -> list of case matches, then assign to highest score.
	findingToCases := make(map[int][]*caseMatch)
	for i := range matches {
		if matches[i].findingIdx >= 0 {
			findingToCases[matches[i].findingIdx] = append(findingToCases[matches[i].findingIdx], &matches[i])
		}
	}

	usedFindings := make(map[int]bool)
	for fidx, cms := range findingToCases {
		if len(cms) == 0 {
			continue
		}
		// Pick the case with the highest score for this finding.
		best := cms[0]
		for _, cm := range cms[1:] {
			if cm.score.Total > best.score.Total {
				best = cm
			}
		}
		usedFindings[fidx] = true
		// Clear the finding assignment for other cases that wanted it.
		for _, cm := range cms {
			if cm != best {
				cm.findingIdx = -1
				cm.score = MatchScore{}
				cm.matchedFinding = nil
			}
		}
	}

	// Build case results.
	caseResults := make([]schema.CaseResult, 0, len(annotation.Cases))
	var tp, fn, fp, tn int
	for _, cm := range matches {
		c := annotation.Cases[cm.caseIdx]
		status := determineStatus(c, cm.score.Total, threshold)
		cr := schema.CaseResult{
			CaseID:       c.CaseID,
			Status:       status,
			FindingIndex: cm.findingIdx,
		}
		if cm.findingIdx >= 0 {
			cr.MatchScore = cm.score.Total
			cr.MatchedFinding = cm.matchedFinding
			cr.MatchDetails = &schema.MatchDetails{
				SourceMatch:    cm.score.SourceMatch,
				SinkMatch:      cm.score.SinkMatch,
				SanitizerMatch: cm.score.SanitizerMatch,
				TraceComplete:  cm.score.TraceComplete,
				LineDistance:   cm.score.LineDistance,
			}
		}
		caseResults = append(caseResults, cr)

		switch status {
		case "tp":
			tp++
		case "fn":
			fn++
		case "fp":
			fp++
		case "tn":
			tn++
		}
	}

	recall := eval.ComputeRecall(tp, fn)
	precision := eval.ComputePrecision(tp, fp)
	f1 := eval.ComputeF1(precision, recall)

	result := &schema.Result{
		BenchmarkID:   annotation.BenchmarkID,
		Engine:        findings.Engine,
		EngineVersion: findings.EngineVersion,
		ScanTime:      time.Now().UTC(),
		Summary: &schema.Summary{
			TotalCases: len(annotation.Cases),
			TP:         tp,
			FN:         fn,
			FP:         fp,
			TN:         tn,
			Recall:     recall,
			Precision:  precision,
			F1:         f1,
		},
		CaseResults:   caseResults,
		PendingReview: []schema.PendingItem{},
	}

	return result, nil
}

// determineStatus maps a case expectation and score to a match status.
func determineStatus(c schema.Case, score, threshold float64) string {
	matched := score >= threshold
	typ := ""
	if c.Expectation != nil {
		typ = c.Expectation.Type
	}

	switch typ {
	case "must_alert":
		if matched {
			return "tp"
		}
		return "fn"
	case "must_not_alert":
		if matched {
			return "fp"
		}
		return "tn"
	case "informational_only":
		if matched {
			return "tp"
		}
		return "fn"
	default:
		if matched {
			return "tp"
		}
		return "fn"
	}
}
