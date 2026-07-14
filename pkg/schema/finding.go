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
	// CWE is the normalised primary weakness identifier, e.g. "CWE-89".
	// Engines may emit multiple CWEs; the converter keeps the first one so the
	// matcher can scope findings to the case's expected vulnerability class.
	CWE        string `json:"cwe,omitempty"`
	// Kind describes the structural form of the finding, which drives how the
	// matcher compares it against a case:
	//   "taint"  — a real source->sink taint flow (data_flow_paths with a
	//              recognisable source API); Flow.Source/Sink are populated.
	//   "path"   — a data-flow path exists but carries no source->sink taint
	//              semantics (e.g. resource-leak rules); Flow is left nil and
	//              only the primary location is meaningful.
	//   "value"  — a pure value match with no data_flow_paths (e.g. hardcoded
	//              secrets); Flow is nil, only the primary location matters.
	// Empty Kind behaves as "taint" for backward compatibility with findings
	// produced before this field existed.
	Kind       string `json:"kind,omitempty"`
	Severity   string `json:"severity,omitempty"`
	Confidence string `json:"confidence,omitempty"`
	Flow       *Flow  `json:"flow,omitempty"`
}

// Finding kind constants.
const (
	FindingKindTaint = "taint"
	FindingKindPath  = "path"
	FindingKindValue  = "value"
)
