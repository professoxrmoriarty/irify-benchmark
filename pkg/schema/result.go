package schema

import "time"

// Result is the evaluation output after matching annotations against findings.
type Result struct {
	BenchmarkID   string        `json:"benchmark_id,omitempty"`
	Engine        string        `json:"engine,omitempty"`
	EngineVersion string        `json:"engine_version,omitempty"`
	ScanTime      time.Time     `json:"scan_time,omitempty"`
	Summary       *Summary      `json:"summary,omitempty"`
	CaseResults   []CaseResult  `json:"case_results,omitempty"`
	PendingReview []PendingItem `json:"pending_review,omitempty"`
}

// Summary aggregates evaluation metrics across all cases.
type Summary struct {
	TotalCases int     `json:"total_cases,omitempty"`
	TP         int     `json:"tp,omitempty"`
	FN         int     `json:"fn,omitempty"`
	FP         int     `json:"fp,omitempty"`
	TN         int     `json:"tn,omitempty"`
	Recall     float64 `json:"recall,omitempty"`
	Precision  float64 `json:"precision,omitempty"`
	F1         float64 `json:"f1,omitempty"`
}

// CaseResult captures the evaluation outcome for a single case.
type CaseResult struct {
	CaseID         string          `json:"case_id,omitempty"`
	Status         string          `json:"status,omitempty"`
	MatchedFinding *MatchedFinding `json:"matched_finding,omitempty"`
	MatchScore     float64         `json:"match_score,omitempty"`
	MatchDetails   *MatchDetails   `json:"match_details,omitempty"`
	FindingIndex   int             `json:"finding_index,omitempty"`
}

// MatchedFinding is a minimal subset of Finding embedded in a CaseResult.
type MatchedFinding struct {
	RuleID   string `json:"rule_id,omitempty"`
	RuleName string `json:"rule_name,omitempty"`
	Severity string `json:"severity,omitempty"`
}

// MatchDetails provides fine-grained matching diagnostics.
type MatchDetails struct {
	SourceMatch    bool `json:"source_match,omitempty"`
	SinkMatch      bool `json:"sink_match,omitempty"`
	SanitizerMatch bool `json:"sanitizer_match,omitempty"`
	TraceComplete  bool `json:"trace_complete,omitempty"`
	LineDistance   int  `json:"line_distance,omitempty"`
}

// ResultMeta holds a lightweight summary of a stored result.
type ResultMeta struct {
	ProjectID     string    `json:"project_id"`
	Engine        string    `json:"engine"`
	EngineVersion string    `json:"engine_version"`
	ScanTime      time.Time `json:"scan_time"`
}
