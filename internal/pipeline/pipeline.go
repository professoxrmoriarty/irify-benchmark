package pipeline

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/irify/irify-benchmark/pkg/engine"
	"github.com/irify/irify-benchmark/pkg/schema"
	"github.com/irify/irify-benchmark/internal/matcher"
	"github.com/irify/irify-benchmark/internal/reviewer"
	"github.com/irify/irify-benchmark/internal/store"
)

// Pipeline orchestrates the benchmark execution stages.
type Pipeline struct {
	store                store.Store
	engine               engine.Engine
	matcher              matcher.Matcher
	PopulatePendingQueue bool
}

// NewPipeline creates a Pipeline with the given dependencies.
// matcher may be nil until Phase 2.
func NewPipeline(st store.Store, eng engine.Engine, m matcher.Matcher) *Pipeline {
	return &Pipeline{
		store:                st,
		engine:               eng,
		matcher:              m,
		PopulatePendingQueue: true,
	}
}

// Run executes the benchmark pipeline for the given benchmarkID and sourcePath.
func (p *Pipeline) Run(ctx context.Context, benchmarkID, sourcePath string) (*schema.Result, error) {
	// 1. Read annotation from store.
	annotation, err := p.store.ReadAnnotation(benchmarkID)
	if err != nil {
		return nil, fmt.Errorf("pipeline: read annotation: %w", err)
	}

	// 2. Run engine scan.
	req := engine.ScanRequest{
		SourcePath: sourcePath,
	}
	findingSet, err := p.engine.Scan(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("pipeline: engine scan: %w", err)
	}
	findingSet.BenchmarkID = benchmarkID
	findingSet.Engine = p.engine.Name()
	if v, err := p.engine.Version(ctx); err == nil {
		findingSet.EngineVersion = v
	}

	// 3. Save findings to store.
	if err := p.store.WriteFindingSet(findingSet); err != nil {
		return nil, fmt.Errorf("pipeline: write findings: %w", err)
	}
	// 3b. Save raw report if available.
	if len(findingSet.RawReport) > 0 {
		format := "json"
		if err := p.store.SaveRawReport(benchmarkID, findingSet.Engine, findingSet.EngineVersion, format, findingSet.RawReport); err != nil {
			// Non-fatal: raw report is for debugging only.
			_ = err
		}
	}

	// 4. Run matcher if available.
	var result *schema.Result
	if p.matcher != nil {
		result, err = p.matcher.Match(annotation, findingSet)
		if err != nil {
			return nil, fmt.Errorf("pipeline: match: %w", err)
		}
	} else {
		// Return a minimal placeholder result for backward compatibility.
		version, _ := p.engine.Version(ctx)
		result = &schema.Result{
			BenchmarkID:   benchmarkID,
			Engine:        p.engine.Name(),
			EngineVersion: version,
			ScanTime:      time.Now().UTC(),
			Summary: &schema.Summary{
				TotalCases: len(annotation.Cases),
			},
			CaseResults:   []schema.CaseResult{},
			PendingReview: []schema.PendingItem{},
		}
	}

	// 5. Populate pending queue with unmatched findings.
	if p.PopulatePendingQueue && findingSet != nil {
		if err := p.populatePendingQueue(benchmarkID, annotation, findingSet, result); err != nil {
			return nil, fmt.Errorf("pipeline: populate pending queue: %w", err)
		}
	}

	// 6. Save result to store.
	if err := p.store.WriteResult(result); err != nil {
		return nil, fmt.Errorf("pipeline: write result: %w", err)
	}

	return result, nil
}

func (p *Pipeline) populatePendingQueue(benchmarkID string, annotation *schema.Annotation, findingSet *schema.FindingSet, result *schema.Result) error {
	// Determine which findings were matched to cases with status "tp" or "fp".
	type findingKey struct {
		RuleID   string
		RuleName string
	}
	matchedCounts := make(map[findingKey]int)
	for _, cr := range result.CaseResults {
		if cr.Status == "tp" || cr.Status == "fp" {
			if cr.MatchedFinding != nil {
				key := findingKey{RuleID: cr.MatchedFinding.RuleID, RuleName: cr.MatchedFinding.RuleName}
				matchedCounts[key]++
			}
		}
	}

	q, err := reviewer.LoadPendingQueue(p.store, benchmarkID)
	if err != nil {
		return fmt.Errorf("load pending queue: %w", err)
	}

	language := ""
	if len(annotation.Cases) > 0 {
		language = annotation.Cases[0].Language
	}

	var newItems []schema.PendingItem
	for i, f := range findingSet.Findings {
		key := findingKey{RuleID: f.RuleID, RuleName: f.RuleName}
		if matchedCounts[key] > 0 {
			matchedCounts[key]--
			continue
		}

		itemID := fmt.Sprintf("pending-%s-%d", f.RuleID, i)
		proposedCase := schema.Case{
			CaseID:     itemID,
			Language:   language,
			SourceCode: "",
			Expectation: &schema.Expectation{
				Type: "must_alert",
				Flow: f.Flow,
			},
			Metadata: &schema.Metadata{
				CWE: extractCWE(f.RuleName),
			},
		}

		findingCopy := f
		item := schema.PendingItem{
			ItemID:          itemID,
			Source:          "runner",
			Status:          "pending",
			ProposedCase:    &proposedCase,
			OriginalFinding: &findingCopy,
			SubmittedAt:     time.Now().UTC(),
		}

		if err := reviewer.AddItem(q, item); err != nil {
			return fmt.Errorf("add pending item %s: %w", itemID, err)
		}
		newItems = append(newItems, item)
	}

	if len(newItems) > 0 {
		if err := reviewer.SavePendingQueue(p.store, q); err != nil {
			return fmt.Errorf("save pending queue: %w", err)
		}
		result.PendingReview = append(result.PendingReview, newItems...)
	}

	return nil
}

func extractCWE(ruleName string) string {
	upper := strings.ToUpper(ruleName)
	idx := strings.Index(upper, "CWE-")
	if idx < 0 {
		return ""
	}
	start := idx
	end := start + 4
	for end < len(upper) && upper[end] >= '0' && upper[end] <= '9' {
		end++
	}
	if end > start+4 {
		return upper[start:end]
	}
	return ""
}
