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
	head     int
	seen     map[string]struct{}
	maxItems int
	maxDepth int
}

// New creates a queue with recursion and, when maxItems > 0, resource limits.
// maxItems <= 0 leaves the item count uncapped.
func New(maxItems, maxDepth int) *Queue {
	return &Queue{
		seen:     make(map[string]struct{}, maxItems),
		maxItems: maxItems,
		maxDepth: maxDepth,
	}
}

// Add appends a unique in-budget item and reports whether it was accepted.
func (q *Queue) Add(item Item) bool {
	return q.AddDetailed(item) == Added
}

// AddOutcome reports why an item was or was not enqueued.
type AddOutcome int

const (
	// Added: the item was enqueued.
	Added AddOutcome = iota
	// Duplicate: the URL was already seen (queued, taken, or marked seen).
	Duplicate
	// Rejected: the item exceeded the depth or the resource limit.
	Rejected
)

// AddDetailed is Add with a rejection reason, so callers can tell a resource
// the queue already knows from one the limits excluded.
func (q *Queue) AddDetailed(item Item) AddOutcome {
	q.mu.Lock()
	defer q.mu.Unlock()

	if item.URL == "" || item.Depth > q.maxDepth ||
		(q.maxItems > 0 && len(q.seen) >= q.maxItems) {
		return Rejected
	}
	if _, duplicate := q.seen[item.URL]; duplicate {
		return Duplicate
	}
	q.seen[item.URL] = struct{}{}
	q.items = append(q.items, item)
	return Added
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
		if q.maxItems > 0 && len(q.seen) >= q.maxItems {
			return
		}
		q.seen[raw] = struct{}{}
	}
}

// Take removes up to limit items while preserving insertion order.
func (q *Queue) Take(limit int) []Item {
	q.mu.Lock()
	defer q.mu.Unlock()

	available := len(q.items) - q.head
	if limit <= 0 || available == 0 {
		return nil
	}
	if limit > available {
		limit = available
	}
	batch := append([]Item(nil), q.items[q.head:q.head+limit]...)
	q.consumeLocked(limit)
	return batch
}

// TakeOne removes the oldest queued item. The queue keeps a head index instead
// of shifting the remaining slice on every take, so draining thousands of
// resources stays linear.
func (q *Queue) TakeOne() (Item, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.head >= len(q.items) {
		return Item{}, false
	}
	item := q.items[q.head]
	q.consumeLocked(1)
	return item, true
}

// consumeLocked advances the head, releases the consumed slots and compacts
// the slice once the dead prefix dominates.
func (q *Queue) consumeLocked(count int) {
	end := q.head + count
	for index := q.head; index < end; index++ {
		q.items[index] = Item{}
	}
	q.head = end
	switch {
	case q.head == len(q.items):
		q.items = q.items[:0]
		q.head = 0
	case q.head >= 1024 && q.head*2 >= len(q.items):
		remaining := copy(q.items, q.items[q.head:])
		for index := remaining; index < len(q.items); index++ {
			q.items[index] = Item{}
		}
		q.items = q.items[:remaining]
		q.head = 0
	}
}

// Len returns the number of queued, not-yet-taken items.
func (q *Queue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.items) - q.head
}

// Pending returns a copy of the queued, not-yet-taken items in insertion
// order. The drain coordinator uses it to account for resources collection
// stopped before dispatching.
func (q *Queue) Pending() []Item {
	q.mu.Lock()
	defer q.mu.Unlock()
	remaining := q.items[q.head:]
	return append([]Item(nil), remaining...)
}
