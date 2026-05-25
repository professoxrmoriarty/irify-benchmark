package reviewer

import (
	"fmt"
	"time"

	"github.com/irify/irify-benchmark/pkg/schema"
	"github.com/irify/irify-benchmark/internal/store"
)

// Reviewer manages the review workflow for a single benchmark.
type Reviewer struct {
	Store       store.Store
	BenchmarkID string
}

// Approve moves a pending item into the canonical annotation.
// Steps:
// 1. Load pending queue
// 2. Find item by ID, verify status is "pending"
// 3. Load annotation
// 4. Append item.ProposedCase to annotation.Cases
// 5. Save annotation
// 6. Update item status to "approved", set ReviewedAt to now
// 7. Save pending queue
// Returns the updated annotation.
func (r *Reviewer) Approve(itemID string, reviewerName string, notes string) (*schema.Annotation, error) {
	q, err := LoadPendingQueue(r.Store, r.BenchmarkID)
	if err != nil {
		return nil, fmt.Errorf("approve: %w", err)
	}

	item, err := GetItem(q, itemID)
	if err != nil {
		return nil, fmt.Errorf("approve: %w", err)
	}
	if item.Status != "pending" {
		return nil, fmt.Errorf("approve: item %q is not pending (status=%s)", itemID, item.Status)
	}

	annotation, err := r.Store.ReadAnnotation(r.BenchmarkID)
	if err != nil {
		return nil, fmt.Errorf("approve: read annotation: %w", err)
	}

	if item.ProposedCase != nil {
		annotation.Cases = append(annotation.Cases, *item.ProposedCase)
	}

	if err := r.Store.WriteAnnotation(annotation); err != nil {
		return nil, fmt.Errorf("approve: write annotation: %w", err)
	}

	now := time.Now().UTC()
	item.Status = "approved"
	item.ReviewedAt = &now
	if reviewerName != "" {
		item.Reviewer = &reviewerName
	}
	if notes != "" {
		item.ReviewNotes = &notes
	}

	if err := SavePendingQueue(r.Store, q); err != nil {
		return nil, fmt.Errorf("approve: %w", err)
	}

	return annotation, nil
}

// Reject marks a pending item as rejected.
// Steps:
// 1. Load pending queue
// 2. Find item by ID, verify status is "pending"
// 3. Update item status to "rejected", set ReviewedAt to now, set Reviewer and ReviewNotes
// 4. Save pending queue
func (r *Reviewer) Reject(itemID string, reviewerName string, reason string) error {
	q, err := LoadPendingQueue(r.Store, r.BenchmarkID)
	if err != nil {
		return fmt.Errorf("reject: %w", err)
	}

	item, err := GetItem(q, itemID)
	if err != nil {
		return fmt.Errorf("reject: %w", err)
	}
	if item.Status != "pending" {
		return fmt.Errorf("reject: item %q is not pending (status=%s)", itemID, item.Status)
	}

	now := time.Now().UTC()
	item.Status = "rejected"
	item.ReviewedAt = &now
	if reviewerName != "" {
		item.Reviewer = &reviewerName
	}
	if reason != "" {
		item.ReviewNotes = &reason
	}

	if err := SavePendingQueue(r.Store, q); err != nil {
		return fmt.Errorf("reject: %w", err)
	}

	return nil
}
