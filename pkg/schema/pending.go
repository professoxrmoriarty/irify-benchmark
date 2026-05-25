package schema

import "time"

// PendingQueue holds cases awaiting human review before merging into the canonical annotation.
type PendingQueue struct {
	BenchmarkID string        `json:"benchmark_id,omitempty"`
	Items       []PendingItem `json:"items,omitempty"`
}

// PendingItem represents a single entry in the review queue.
type PendingItem struct {
	ItemID          string     `json:"item_id,omitempty"`
	Source          string     `json:"source,omitempty"`
	Status          string     `json:"status,omitempty"`
	ProjectID       string     `json:"project_id,omitempty"`
	ProposedCase    *Case      `json:"proposed_case,omitempty"`
	OriginalFinding *Finding   `json:"original_finding,omitempty"`
	SubmittedAt     time.Time  `json:"submitted_at,omitempty"`
	ReviewedAt      *time.Time `json:"reviewed_at,omitempty"`
	Reviewer        *string    `json:"reviewer,omitempty"`
	ReviewNotes     *string    `json:"review_notes,omitempty"`
}
