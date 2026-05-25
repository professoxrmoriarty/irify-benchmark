package main

import (
	"os"
	"time"

	"github.com/irify/irify-benchmark/internal/reporter"
	"github.com/irify/irify-benchmark/pkg/schema"
)

func main() {
	result := &schema.Result{
		BenchmarkID:   "bench-test",
		Engine:        "yaklang",
		EngineVersion: "1.4.5",
		ScanTime:      time.Now().UTC(),
		Summary: &schema.Summary{
			TotalCases: 2,
			TP:         1,
			TN:         1,
			Recall:     1,
			Precision:  1,
			F1:         1,
		},
		CaseResults: []schema.CaseResult{
			{
				CaseID:     "case-001",
				Status:     "tp",
				MatchScore: 1.0,
				MatchDetails: &schema.MatchDetails{
					SourceMatch:   true,
					SinkMatch:     true,
					TraceComplete: true,
				},
			},
			{
				CaseID: "case-002",
				Status: "tn",
			},
		},
	}

	r := &reporter.HTMLReporter{}
	if err := r.Render(result, os.Stdout); err != nil {
		panic(err)
	}
}
