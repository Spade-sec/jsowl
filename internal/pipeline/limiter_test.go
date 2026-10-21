package pipeline

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestLimiterBoundsConcurrency(t *testing.T) {
	limiter := NewLimiter(2)
	ctx := context.Background()
	var current, peak int32
	var wait sync.WaitGroup
	for index := 0; index < 8; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if err := limiter.Acquire(ctx); err != nil {
				t.Error(err)
				return
			}
			running := atomic.AddInt32(&current, 1)
			for {
				observed := atomic.LoadInt32(&peak)
				if running <= observed || atomic.CompareAndSwapInt32(&peak, observed, running) {
					break
				}
			}
			time.Sleep(10 * time.Millisecond)
			atomic.AddInt32(&current, -1)
			limiter.Release()
		}()
	}
	wait.Wait()
	if peak > int32(limiter.Capacity()) {
		t.Fatalf("peak concurrency = %d, capacity = %d", peak, limiter.Capacity())
	}
	if peak < 2 {
		t.Fatalf("peak concurrency = %d, expected the limiter to allow 2", peak)
	}
}

func TestLimiterAcquireHonorsCancellation(t *testing.T) {
	limiter := NewLimiter(1)
	if err := limiter.Acquire(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := limiter.Acquire(ctx); err == nil {
		t.Fatal("Acquire on a full limiter ignored cancellation")
	}
	limiter.Release()
}

func TestNewLimiterFallsBackToAtLeastOneSlot(t *testing.T) {
	if got := NewLimiter(0).Capacity(); got < 1 {
		t.Fatalf("capacity = %d", got)
	}
	if got := NewLimiter(-5).Capacity(); got < 1 {
		t.Fatalf("capacity = %d", got)
	}
}
