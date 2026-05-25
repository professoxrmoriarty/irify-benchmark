package schema

import "time"

// FindingSet is the output produced by a scanning engine.
type FindingSet struct {
	BenchmarkID   string    `json:"benchmark_id,omitempty"`
	Engine        string    `json:"engine,omitempty"`
	EngineVersion string    `json:"engine_version,omitempty"`
	ScanTime      time.Time `json:"scan_time,omitempty"`
	ProgramName   string    `json:"program_name,omitempty"`
	Findings      []Finding `json:"findings,omitempty"`
	RawReport     []byte    `json:"-"` // Original engine output bytes (not serialized to JSON)
}

// Finding represents a single vulnerability finding reported by an engine.
type Finding struct {
	RuleID     string `json:"rule_id,omitempty"`
	RuleName   string `json:"rule_name,omitempty"`
	Severity   string `json:"severity,omitempty"`
	Confidence string `json:"confidence,omitempty"`
	Flow       *Flow  `json:"flow,omitempty"`
}
