package scheduler

import (
	"strconv"
	"testing"
)

func TestQueueDeduplicatesAndHonorsDepthAndResourceLimit(t *testing.T) {
	queue := New(2, 2)

	if !queue.Add(Item{URL: "https://example.test/a.js", Depth: 1}) {
		t.Fatal("first Add() = false")
	}
	if queue.Add(Item{URL: "https://example.test/a.js", Depth: 1}) {
		t.Fatal("duplicate Add() = true")
	}
	if !queue.Add(Item{URL: "https://example.test/b.js", Depth: 2}) {
		t.Fatal("second unique Add() = false")
	}
	if queue.Add(Item{URL: "https://example.test/c.js", Depth: 1}) {
		t.Fatal("Add() ignored resource limit")
	}

	depthQueue := New(10, 2)
	if depthQueue.Add(Item{URL: "https://example.test/deep.js", Depth: 3}) {
		t.Fatal("Add() ignored depth limit")
	}
}

func TestQueueTakePreservesOrderAcrossDynamicAdds(t *testing.T) {
	queue := New(10, 5)
	queue.Add(Item{URL: "https://example.test/one.js"})
	queue.Add(Item{URL: "https://example.test/two.js"})

	first := queue.Take(1)
	if len(first) != 1 || first[0].URL != "https://example.test/one.js" {
		t.Fatalf("first Take() = %#v", first)
	}
	queue.Add(Item{URL: "https://example.test/three.js", Depth: 1})

	second := queue.Take(10)
	if len(second) != 2 ||
		second[0].URL != "https://example.test/two.js" ||
		second[1].URL != "https://example.test/three.js" {
		t.Fatalf("second Take() = %#v", second)
	}
	if queue.Len() != 0 {
		t.Fatalf("Len() = %d, want 0", queue.Len())
	}
}

func TestQueueMarkSeenPreventsCrossPhaseDuplicates(t *testing.T) {
	queue := New(3, 2)
	if !queue.Add(Item{URL: "https://example.test/"}) {
		t.Fatal("root was not added")
	}
	queue.MarkSeen([]string{"https://example.test/app.js"})
	if queue.Add(Item{URL: "https://example.test/app.js", Depth: 1}) {
		t.Fatal("previously collected script was added again")
	}
	if !queue.Add(Item{URL: "https://example.test/new.js", Depth: 1}) {
		t.Fatal("new script was not added within combined resource budget")
	}
	if queue.Add(Item{URL: "https://example.test/overflow.js", Depth: 1}) {
		t.Fatal("combined resource budget was exceeded")
	}
}

// TestQueueTakeOneKeepsFIFOAcrossCompaction drains a queue big enough to
// trigger the internal compaction path and checks ordering survives it.
func TestQueueTakeOneKeepsFIFOAcrossCompaction(t *testing.T) {
	const count = 5000
	queue := New(0, 5)
	for index := 0; index < count; index++ {
		url := "https://example.test/" + strconv.Itoa(index)
		if !queue.Add(Item{URL: url, Depth: 1}) {
			t.Fatalf("Add(%d) = false", index)
		}
	}
	for index := 0; index < count; index++ {
		item, ok := queue.TakeOne()
		if !ok {
			t.Fatalf("TakeOne() = false at %d", index)
		}
		if want := "https://example.test/" + strconv.Itoa(index); item.URL != want {
			t.Fatalf("item %d = %q, want %q", index, item.URL, want)
		}
		if got := queue.Len(); got != count-index-1 {
			t.Fatalf("Len() = %d at %d, want %d", got, index, count-index-1)
		}
	}
	if _, ok := queue.TakeOne(); ok {
		t.Fatal("TakeOne() returned an item from an empty queue")
	}
	if queue.Len() != 0 {
		t.Fatalf("Len() = %d, want 0", queue.Len())
	}
}
