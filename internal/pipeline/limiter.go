package pipeline

import (
	"context"
	"runtime"
)

// Limiter bounds how many bodies are analyzed at the same time. Each analysis
// pass holds one slot; the limit is process-wide when a Scanner shares one
// Limiter across its targets, so a batch scan cannot multiply the analysis
// concurrency by the number of targets.
//
// The capacity is an internal default derived from GOMAXPROCS: analysis is CPU
// bound (the regex engine dominates), so more slots than cores only increase
// peak memory. Callers that need a different bound can construct their own.
type Limiter struct {
	slots chan struct{}
}

// NewLimiter creates a limiter with the given capacity. A non-positive size
// falls back to GOMAXPROCS (at least one slot).
func NewLimiter(size int) *Limiter {
	if size <= 0 {
		size = runtime.GOMAXPROCS(0)
	}
	if size < 1 {
		size = 1
	}
	return &Limiter{slots: make(chan struct{}, size)}
}

// Capacity reports how many analyses may run at the same time.
func (l *Limiter) Capacity() int {
	return cap(l.slots)
}

// Acquire takes a slot, waiting for one to free up or for ctx to be cancelled.
func (l *Limiter) Acquire(ctx context.Context) error {
	select {
	case l.slots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Release returns one slot.
func (l *Limiter) Release() {
	<-l.slots
}
