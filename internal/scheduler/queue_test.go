package scheduler

import "testing"

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
