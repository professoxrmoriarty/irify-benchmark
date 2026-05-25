package schema

// Project represents a benchmark project containing source code and test cases.
type Project struct {
	ProjectID   string            `json:"project_id" yaml:"project_id"`
	Name        string            `json:"name" yaml:"name"`
	Description string            `json:"description" yaml:"description"`
	Language    string            `json:"language" yaml:"language"`
	Framework   string            `json:"framework" yaml:"framework"`
	SourceRoot  string            `json:"source_root" yaml:"source_root"`
	CreatedAt   string            `json:"created_at" yaml:"created_at"`
	Metadata    map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty"`
}

// CaseSet represents the ground-truth annotations for a single project.
type CaseSet struct {
	ProjectID string `json:"project_id" yaml:"project_id"`
	Version   string `json:"version" yaml:"version"`
	Cases     []Case `json:"cases" yaml:"cases"`
}

// CaseWithProject enriches a Case with its parent project info.
type CaseWithProject struct {
	Case
	Project Project `json:"project" yaml:"project"`
}

// CaseFilter defines query parameters for searching cases.
type CaseFilter struct {
	ProjectID string `json:"project_id,omitempty"`
	Keyword   string `json:"keyword,omitempty"`
	CWE       string `json:"cwe,omitempty"`
	Language  string `json:"language,omitempty"`
	Tag       string `json:"tag,omitempty"`
}
