package pipeline

import (
	"context"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/youmulijiang/jsowl/internal/analyze"
	"github.com/youmulijiang/jsowl/internal/collect"
	"github.com/youmulijiang/jsowl/internal/model"
)

// gatedGetter serves a fixed route table and lets a test hold one path open.
// Every request start is published on started so the test can observe
// scheduling without racing on a plain slice.
type gatedGetter struct {
	responses   map[string]collect.Response
	started     chan string
	held        chan struct{}
	heldPaths   map[string]struct{}
	mu          sync.Mutex
	requests    map[string]int
	releaseOnce sync.Once
}

func (g *gatedGetter) Get(
	ctx context.Context, target *url.URL, _ http.Header,
) (collect.Response, error) {
	g.mu.Lock()
	if g.requests == nil {
		g.requests = map[string]int{}
	}
	g.requests[target.Path]++
	g.mu.Unlock()
	select {
	case g.started <- target.Path:
	default:
	}
	if _, held := g.heldPaths[target.Path]; held {
		select {
		case <-g.held:
		case <-ctx.Done():
			return collect.Response{}, ctx.Err()
		}
	}
	response, ok := g.responses[target.Path]
	if !ok {
		return collect.Response{}, context.Canceled
	}
	return response, nil
}

func newGatedPipeline(
	t *testing.T,
	config model.Config,
	getter collect.Getter,
) (*Pipeline, *analyze.Engine) {
	t.Helper()
	engine, err := analyze.New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	config.Output.Directory = t.TempDir()
	return New(Options{Getter: getter, Analyzer: engine, Config: config}), engine
}

func jsResponse(path string, body string) collect.Response {
	return collect.Response{
		URL: "http://stub.test" + path, StatusCode: 200,
		Header: http.Header{"Content-Type": []string{"application/javascript"}},
		Body:   []byte(body),
	}
}

// TestDrainDoesNotWaitForSlowRequests pins the continuous-pool behavior: a
// resource that finishes early is merged (and its discoveries enqueued)
// while a slower sibling is still in flight. Under the previous batch barrier
// the child request could only start after the slow request finished.
func TestDrainDoesNotWaitForSlowRequests(t *testing.T) {
	getter := &gatedGetter{
		responses: map[string]collect.Response{
			"/": {URL: "http://stub.test/", StatusCode: 200,
				Header: http.Header{"Content-Type": []string{"text/html"}},
				Body: []byte(
					`<script src="/slow.js"></script><script src="/fast.js"></script>`,
				)},
			"/slow.js":        jsResponse("/slow.js", `fetch("/api/slow")`),
			"/fast.js":        jsResponse("/fast.js", `fetch("/api/fast-child")`),
			"/api/slow":       jsonResponse("/api/slow"),
			"/api/fast-child": jsonResponse("/api/fast-child"),
		},
		started:   make(chan string, 64),
		held:      make(chan struct{}),
		heldPaths: map[string]struct{}{"/slow.js": {}},
	}
	config := model.DefaultConfig()
	config.Mode = model.ModeDirect
	pipeline, _ := newGatedPipeline(t, config, getter)

	type outcome struct {
		result *model.Result
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		result, _, err := pipeline.RunDetailed(
			context.Background(), model.Target{URL: "http://stub.test"},
			http.Header{}, nil, nil, nil,
		)
		done <- outcome{result: result, err: err}
	}()

	deadline := time.After(5 * time.Second)
	released := false
	for !released {
		select {
		case path := <-getter.started:
			if path == "/api/fast-child" {
				close(getter.held)
				released = true
			}
		case <-deadline:
			close(getter.held)
			t.Fatal("child resource was not requested before the slow request finished")
		}
	}
	select {
	case finished := <-done:
		if finished.err != nil {
			t.Fatal(finished.err)
		}
		if len(finished.result.Resources) < 3 {
			t.Fatalf("resources = %d, want at least 3", len(finished.result.Resources))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("scan did not finish after releasing the slow request")
	}
}

func jsonResponse(path string) collect.Response {
	return collect.Response{
		URL: "http://stub.test" + path, StatusCode: 200,
		Header: http.Header{"Content-Type": []string{"application/json"}},
		Body:   []byte(`{"ok":true}`),
	}
}

// TestDrainFollowsDynamicTaskChain verifies the termination condition: a
// chain discovered one level at a time must be fully drained, and the pool
// must stop only when the queue is empty and nothing is in flight.
func TestDrainFollowsDynamicTaskChain(t *testing.T) {
	getter := &gatedGetter{
		responses: map[string]collect.Response{
			"/": {URL: "http://stub.test/", StatusCode: 200,
				Header: http.Header{"Content-Type": []string{"text/html"}},
				Body:   []byte(`<script src="/a.js"></script>`)},
			"/a.js": jsResponse("/a.js", `import("/b.js")`),
			"/b.js": jsResponse("/b.js", `import("/c.js")`),
			"/c.js": jsResponse("/c.js", `import("/d.js")`),
			"/d.js": jsResponse("/d.js", `var done = true`),
		},
		started:   make(chan string, 64),
		held:      make(chan struct{}),
		heldPaths: map[string]struct{}{},
	}
	config := model.DefaultConfig()
	config.Mode = model.ModeDirect
	pipeline, _ := newGatedPipeline(t, config, getter)

	done := make(chan error, 1)
	go func() {
		_, _, err := pipeline.RunDetailed(
			context.Background(), model.Target{URL: "http://stub.test"},
			http.Header{}, nil, nil, nil,
		)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("dynamic task chain deadlocked")
	}
	getter.mu.Lock()
	defer getter.mu.Unlock()
	for _, path := range []string{"/a.js", "/b.js", "/c.js", "/d.js"} {
		if getter.requests[path] != 1 {
			t.Fatalf("%s requested %d times, want 1", path, getter.requests[path])
		}
	}
}

// TestDrainHonorsResourceBudgetUnderConcurrency verifies that continuous
// refill does not let the queue admit more resources than the configured cap.
func TestDrainHonorsResourceBudgetUnderConcurrency(t *testing.T) {
	body := ""
	for index := 0; index < 20; index++ {
		body += `<script src="/chunk-` + string(rune('a'+index)) + `.js"></script>`
	}
	responses := map[string]collect.Response{
		"/": {URL: "http://stub.test/", StatusCode: 200,
			Header: http.Header{"Content-Type": []string{"text/html"}},
			Body:   []byte(body)},
	}
	for index := 0; index < 20; index++ {
		path := "/chunk-" + string(rune('a'+index)) + ".js"
		responses[path] = jsResponse(path, `var x = 1`)
	}
	getter := &gatedGetter{
		responses: responses,
		started:   make(chan string, 128),
		held:      make(chan struct{}),
		heldPaths: map[string]struct{}{},
	}
	config := model.DefaultConfig()
	config.Mode = model.ModeDirect
	config.Limits.MaxResources = 5
	pipeline, _ := newGatedPipeline(t, config, getter)

	result, _, err := pipeline.RunDetailed(
		context.Background(), model.Target{URL: "http://stub.test"},
		http.Header{}, nil, nil, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Resources) > config.Limits.MaxResources {
		t.Fatalf("resources = %d, budget = %d",
			len(result.Resources), config.Limits.MaxResources)
	}
}
