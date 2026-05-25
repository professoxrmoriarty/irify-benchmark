package reviewer

import (
	"fmt"

	"github.com/irify/irify-benchmark/pkg/schema"
	"github.com/irify/irify-benchmark/internal/store"
)

// LoadPendingQueue reads the pending queue from store.
func LoadPendingQueue(st store.Store, benchmarkID string) (*schema.PendingQueue, error) {
	q, err := st.ReadPendingQueue(benchmarkID)
	if err != nil {
		return nil, fmt.Errorf("load pending queue: %w", err)
	}
	return q, nil
}

// SavePendingQueue writes the pending queue to store.
func SavePendingQueue(st store.Store, q *schema.PendingQueue) error {
	if err := st.WritePendingQueue(q); err != nil {
		return fmt.Errorf("save pending queue: %w", err)
	}
	return nil
}

// AddItem appends a new pending item to the queue.
// Returns an error if the item ID already exists in the queue.
func AddItem(q *schema.PendingQueue, item schema.PendingItem) error {
	for _, existing := range q.Items {
		if existing.ItemID == item.ItemID {
			return fmt.Errorf("item with ID %q already exists in queue", item.ItemID)
		}
	}
	q.Items = append(q.Items, item)
	return nil
}

// ListPending returns all items with status "pending".
func ListPending(q *schema.PendingQueue) []schema.PendingItem {
	var pending []schema.PendingItem
	for _, item := range q.Items {
		if item.Status == "pending" {
			pending = append(pending, item)
		}
	}
	return pending
}

// GetItem retrieves a single item by ID.
func GetItem(q *schema.PendingQueue, itemID string) (*schema.PendingItem, error) {
	for i := range q.Items {
		if q.Items[i].ItemID == itemID {
			return &q.Items[i], nil
		}
	}
	return nil, fmt.Errorf("item %q not found in queue", itemID)
}
