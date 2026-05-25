package schema

import "time"

// Annotation represents a complete benchmark annotation set (ground truth).
type Annotation struct {
	BenchmarkID string `json:"benchmark_id,omitempty"`
	Version     string `json:"version,omitempty"`
	CreatedAt   time.Time `json:"created_at,omitempty"`
	Cases       []Case `json:"cases,omitempty"`
}

// Case represents a single benchmark case with expected vulnerability flow.
type Case struct {
	CaseID      string       `json:"case_id,omitempty" yaml:"case_id,omitempty"`
	Name        string       `json:"name,omitempty" yaml:"name,omitempty"`
	Description string       `json:"description,omitempty" yaml:"description,omitempty"`
	VulnDesc    string       `json:"vuln_desc,omitempty" yaml:"vuln_desc,omitempty"`
	Language    string       `json:"language,omitempty" yaml:"language,omitempty"`
	SourceCode  string       `json:"source_code,omitempty" yaml:"source_code,omitempty"`
	Expectation *Expectation `json:"expectation,omitempty" yaml:"expectation,omitempty"`
	Metadata    *Metadata    `json:"metadata,omitempty" yaml:"metadata,omitempty"`
	Notes       string       `json:"notes,omitempty" yaml:"notes,omitempty"`
}

// Expectation defines the expected detection outcome for a case.
type Expectation struct {
	Type string `json:"type,omitempty" yaml:"type,omitempty"`
	Flow *Flow  `json:"flow,omitempty" yaml:"flow,omitempty"`
}

// Flow describes a taint flow from source through optional sanitizers to a sink.
type Flow struct {
	Source     *Location   `json:"source,omitempty" yaml:"source,omitempty"`
	Sanitizers []Sanitizer `json:"sanitizers,omitempty" yaml:"sanitizers,omitempty"`
	Sink       *Location   `json:"sink,omitempty" yaml:"sink,omitempty"`
}

// Location identifies a specific point in source code.
type Location struct {
	Symbol string `json:"symbol,omitempty" yaml:"symbol,omitempty"`
	Line   int    `json:"line,omitempty" yaml:"line,omitempty"`
	Column int    `json:"column,omitempty" yaml:"column,omitempty"`
	File   string `json:"file,omitempty" yaml:"file,omitempty"`
}

// Sanitizer extends Location with an effectiveness flag.
type Sanitizer struct {
	Location
	Effective bool `json:"effective,omitempty" yaml:"effective,omitempty"`
}

// Metadata holds auxiliary classification data for a case.
type Metadata struct {
	CWE       string   `json:"cwe,omitempty" yaml:"cwe,omitempty"`
	Framework string   `json:"framework,omitempty" yaml:"framework,omitempty"`
	Tags      []string `json:"tags,omitempty" yaml:"tags,omitempty"`
}
