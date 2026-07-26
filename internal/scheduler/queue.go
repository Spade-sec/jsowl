package scheduler

import (
	"sync"

	"github.com/youmulijiang/jsowl/internal/model"
)

// Item describes one canonical resource waiting to be collected.
type Item struct {
	URL       string
	Kind      model.ResourceType
	SourceURL string
	Depth     int
}

// Queue is a bounded, deduplicating FIFO used by one target scan.
type Queue struct {
	mu       sync.Mutex
	items    []Item
	seen     map[string]struct{}
	maxItems int
	maxDepth int
}

// New creates a queue with hard resource and recursion limits.
func New(maxItems, maxDepth int) *Queue {
	return &Queue{
		seen:     make(map[string]struct{}, maxItems),
		maxItems: maxItems,
		maxDepth: maxDepth,
	}
}

// Add appends a unique in-budget item and reports whether it was accepted.
func (q *Queue) Add(item Item) bool {
	q.mu.Lock()
	defer q.mu.Unlock()

	if item.URL == "" || item.Depth > q.maxDepth || len(q.seen) >= q.maxItems {
		return false
	}
	if _, duplicate := q.seen[item.URL]; duplicate {
		return false
	}
	q.seen[item.URL] = struct{}{}
	q.items = append(q.items, item)
	return true
}

// MarkSeen imports canonical URLs collected by an earlier scan phase without
// enqueueing them, preserving one combined resource budget.
func (q *Queue) MarkSeen(urls []string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for _, raw := range urls {
		if raw == "" {
			continue
		}
		if _, exists := q.seen[raw]; exists {
			continue
		}
		if len(q.seen) >= q.maxItems {
			return
		}
		q.seen[raw] = struct{}{}
	}
}

// Take removes up to limit items while preserving insertion order.
func (q *Queue) Take(limit int) []Item {
	q.mu.Lock()
	defer q.mu.Unlock()

	if limit <= 0 || len(q.items) == 0 {
		return nil
	}
	if limit > len(q.items) {
		limit = len(q.items)
	}
	batch := append([]Item(nil), q.items[:limit]...)
	q.items = append(q.items[:0], q.items[limit:]...)
	return batch
}

// Len returns the number of queued, not-yet-taken items.
func (q *Queue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.items)
}
