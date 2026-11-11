package pipeline

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/youmulijiang/jsowl/internal/analyze"
	"github.com/youmulijiang/jsowl/internal/collect"
	"github.com/youmulijiang/jsowl/internal/model"
)

// countingRouteGetter serves canned GET responses and records every request,
// so tests can assert that a queued task was actually requested.
type countingRouteGetter struct {
	mu    sync.Mutex
	paths map[string]int
	// PlainDocument serves an entry page without script references, so tests
	// that feed their own seeds do not inherit an extra discovered script.
	PlainDocument bool
}

func (g *countingRouteGetter) record(path string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.paths == nil {
		g.paths = map[string]int{}
	}
	g.paths[path]++
}

func (g *countingRouteGetter) count(path string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.paths[path]
}

func (g *countingRouteGetter) Get(
	_ context.Context,
	target *url.URL,
	_ http.Header,
) (collect.Response, error) {
	g.record(target.Path)
	body := "var ok = 1"
	if strings.HasSuffix(target.Path, ".js") {
		body = `var api = "/api/ast-only";fetch(api)`
	} else if strings.HasPrefix(target.Path, "/api/") {
		body = `{"ok":true}`
	}
	contentType := "application/javascript"
	if !strings.HasSuffix(target.Path, ".js") {
		contentType = "application/json"
		if target.Path == "/" {
			contentType = "text/html"
			body = `<script src="/app.js"></script>`
			if g.PlainDocument {
				body = `<html><body></body></html>`
			}
		}
	}
	return collect.Response{
		URL: target.String(), StatusCode: http.StatusOK,
		Header: http.Header{"Content-Type": {contentType}},
		Body:   []byte(body),
	}, nil
}

// TestDeferredDiscoveryIsDrainedWithoutBasePaths pins the loop contract: a
// task that only the deferred AST analysis can discover (the regex URL rules
// need a literal, so `fetch(variable)` is invisible during collection) must
// actually be processed, even with ExploreBasePaths disabled.
func TestDeferredDiscoveryIsDrainedWithoutBasePaths(t *testing.T) {
	config := model.DefaultConfig()
	config.Mode = model.ModeDirect
	config.Scope.ExploreBasePaths = false
	config.Output.Directory = t.TempDir()
	engine, err := analyze.New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	getter := &countingRouteGetter{}
	p := New(Options{Getter: getter, Analyzer: engine, Config: config})
	result, _, err := p.RunDetailed(
		context.Background(), model.Target{URL: "http://stub.test"}, http.Header{},
		nil, nil, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := getter.count("/api/ast-only"); got != 1 {
		t.Fatalf("/api/ast-only requested %d times, want 1: the analysis-discovered task was left queued", got)
	}
	if !endpointProbed(result, "/api/ast-only", http.StatusOK) {
		t.Errorf("endpoint missing or unprobed: %+v", result.Endpoints)
	}
}

// TestEntryPeekDoesNotDropQueuedTasks pins the drain contract: the entry
// snapshot must only ever take the queue head when it IS the entry document.
// A second drain round starts at an ordinary task, and the old
// take-then-check dropped that task on the floor.
func TestEntryPeekDoesNotDropQueuedTasks(t *testing.T) {
	config := model.DefaultConfig()
	config.Mode = model.ModeDirect
	config.Scope.ExploreBasePaths = false
	config.Output.Directory = t.TempDir()
	engine, err := analyze.New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	getter := &countingRouteGetter{}
	p := New(Options{Getter: getter, Analyzer: engine, Config: config})
	entry := collect.Response{
		URL: "http://stub.test/", StatusCode: http.StatusOK,
		Header: http.Header{"Content-Type": {"text/html; charset=utf-8"}},
		Body:   []byte(`<script src="/app.js"></script>`),
	}
	result, _, err := p.RunDetailed(
		context.Background(), model.Target{URL: "http://stub.test"}, http.Header{},
		&entry, nil, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := getter.count("/app.js"); got != 1 {
		t.Fatalf("/app.js requested %d times, want 1 (no duplicate, no loss)", got)
	}
	// The probe is discovered by the deferred analysis; reaching it requires
	// a second drain round, whose queue head is an ordinary task.
	if got := getter.count("/api/ast-only"); got != 1 {
		t.Fatalf("/api/ast-only requested %d times, want 1: the second drain round dropped the queued task", got)
	}
	if !endpointProbed(result, "/api/ast-only", http.StatusOK) {
		t.Errorf("endpoint missing or unprobed: %+v", result.Endpoints)
	}
}

func endpointRecorded(result *model.Result, path string) bool {
	for _, endpoint := range result.Endpoints {
		if strings.HasSuffix(endpoint.URL, path) {
			return true
		}
	}
	return false
}

func endpointProbed(result *model.Result, path string, status int) bool {
	for _, endpoint := range result.Endpoints {
		if strings.HasSuffix(endpoint.URL, path) && endpoint.StatusCode == status {
			return true
		}
	}
	return false
}

// probeGateGetter serves canned GETs and blocks the first POST until the
// caller's context ends, so a test can make the POST-probe stage the first
// place a cancellation or budget expiry ever fires.
type probeGateGetter struct {
	gets map[string]collect.Response

	postStarted sync.Once
	started     chan struct{}
}

func (g *probeGateGetter) Get(
	_ context.Context,
	target *url.URL,
	_ http.Header,
) (collect.Response, error) {
	if response, ok := g.gets[target.Path]; ok {
		return response, nil
	}
	return collect.Response{
		URL: target.String(), StatusCode: http.StatusNotFound,
		Header: http.Header{"Content-Type": {"application/json"}},
	}, nil
}

func (g *probeGateGetter) Post(
	ctx context.Context,
	target *url.URL,
	_ http.Header,
	_ []byte,
) (collect.Response, error) {
	g.postStarted.Do(func() { close(g.started) })
	<-ctx.Done()
	return collect.Response{}, ctx.Err()
}

func newProbeGatePipeline(
	t *testing.T,
	parent context.Context,
	networkTimeout time.Duration,
) (*Pipeline, *probeGateGetter, context.CancelFunc) {
	t.Helper()
	config := model.DefaultConfig()
	config.Mode = model.ModeDirect
	config.Scope.ExploreBasePaths = false
	config.Output.Directory = t.TempDir()
	engine, err := analyze.New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	getter := &probeGateGetter{
		gets: map[string]collect.Response{
			"/": {URL: "http://stub.test/", StatusCode: http.StatusOK,
				Header: http.Header{"Content-Type": {"text/html"}},
				Body:   []byte(`<script src="/app.js"></script>`)},
			"/app.js": {URL: "http://stub.test/app.js", StatusCode: http.StatusOK,
				Header: http.Header{"Content-Type": {"application/javascript"}},
				// The AST-only POST call site: invisible to the regex rules,
				// discovered and probe-eligible only after deferred analysis.
				Body: []byte(`axios.post("/api/write", {a: 1})`)},
			"/api/write": {URL: "http://stub.test/api/write", StatusCode: http.StatusOK,
				Header: http.Header{"Content-Type": {"application/json"}},
				Body:   []byte(`{"ok":true}`)},
		},
		started: make(chan struct{}),
	}
	// The network context derives from the caller's context, exactly the way
	// Scanner.Scan derives it, so a caller cancellation propagates into the
	// probes.
	networkCtx, cancelNetwork := context.WithTimeout(parent, networkTimeout)
	p := New(Options{
		Getter: getter, Analyzer: engine, Config: config,
		NetworkContext: networkCtx,
	})
	return p, getter, cancelNetwork
}

// TestPostProbeCancellationReachesFinalState pins the contract that a stop
// first firing during the POST-probe stage returns the caller's error (with
// errors.Is intact), marks the collection incomplete, and keeps every result
// produced before the probes.
func TestPostProbeCancellationReachesFinalState(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p, getter, _ := newProbeGatePipeline(t, ctx, time.Minute)
	go func() {
		<-getter.started
		cancel()
	}()
	result, _, err := p.RunDetailed(
		ctx, model.Target{URL: "http://stub.test"}, http.Header{},
		nil, nil, nil,
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("RunDetailed() error = %v, want context canceled", err)
	}
	if result == nil {
		t.Fatal("RunDetailed() returned no result")
	}
	if !endpointRecorded(result, "/api/write") {
		t.Error("the endpoint discovered before the probes was lost")
	}
	completeness := result.Completeness
	if completeness == nil || completeness.Collection.Complete {
		t.Errorf("collection should be incomplete after a probe-stage cancellation: %+v", completeness)
	}
	if coverage := completeness.Coverage; coverage.Analyzed != 1 || coverage.Fetched != 1 {
		t.Errorf("fetched JS coverage = %+v, want app.js fetched and analyzed", coverage)
	}
	foundIssue := false
	for _, issue := range result.Issues {
		if issue.Code == "post_probe_skipped" {
			foundIssue = true
		}
	}
	if !foundIssue {
		t.Errorf("unprobed POST endpoint not recorded: %+v", result.Issues)
	}
}

// TestPostProbeBudgetExpiryReachesFinalState is the budget twin of the
// cancellation test: the collection budget expires while the first POST probe
// is in flight, and the run must return the deadline error with the results
// kept and the collection marked incomplete.
func TestPostProbeBudgetExpiryReachesFinalState(t *testing.T) {
	p, getter, _ := newProbeGatePipeline(t, context.Background(), 300*time.Millisecond)
	result, _, err := p.RunDetailed(
		context.Background(), model.Target{URL: "http://stub.test"}, http.Header{},
		nil, nil, nil,
	)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("RunDetailed() error = %v, want context deadline exceeded", err)
	}
	if result == nil {
		t.Fatal("RunDetailed() returned no result")
	}
	if !endpointRecorded(result, "/api/write") {
		t.Error("the endpoint discovered before the probes was lost")
	}
	completeness := result.Completeness
	if completeness == nil || completeness.Collection.Complete {
		t.Errorf("collection should be incomplete after budget expiry: %+v", completeness)
	}
	select {
	case <-getter.started:
	default:
		t.Fatal("the POST probe never ran; the test did not exercise the probe stage")
	}
}

// TestSeedsCountOnlyJavaScriptInCoverage pins the coverage scope: authorized
// API seeds and route seeds are recorded as endpoints but never enter the JS
// coverage counts, where they would otherwise show up as unfetched scripts.
func TestSeedsCountOnlyJavaScriptInCoverage(t *testing.T) {
	config := model.DefaultConfig()
	config.Mode = model.ModeDirect
	config.Output.Directory = t.TempDir()
	engine, err := analyze.New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	getter := &countingRouteGetter{PlainDocument: true}
	p := New(Options{Getter: getter, Analyzer: engine, Config: config})
	seeds := []Seed{
		{URL: "http://stub.test/seed.js", Kind: model.ResourceTypeScript,
			Evidence: model.EvidenceRuntime, Source: "cdp"},
		{URL: "http://stub.test/api/from-seed", Kind: model.ResourceTypeAPI,
			Evidence: model.EvidenceRuntime, Source: "cdp"},
		{URL: "http://stub.test/#/admin", Kind: model.ResourceTypeRoute,
			Evidence: model.EvidenceRuntime, Source: "cdp-runtime"},
	}
	result, _, err := p.RunDetailed(
		context.Background(), model.Target{URL: "http://stub.test"}, http.Header{},
		nil, seeds, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	coverage := result.Completeness.Coverage
	if coverage.Discovered != 1 {
		t.Errorf("discovered = %d, want 1 (the script seed only, no API or route): %+v",
			coverage.Discovered, coverage)
	}
	if coverage.Fetched != 1 || coverage.Analyzed != 1 {
		t.Errorf("coverage = %+v, want the seed script fetched and analyzed", coverage)
	}
	if !endpointProbed(result, "/api/from-seed", http.StatusOK) {
		t.Error("the API seed should still be recorded and probed like before")
	}
	routeFound := false
	for _, endpoint := range result.Endpoints {
		if endpoint.Type == "route" && strings.HasSuffix(endpoint.URL, "#/admin") {
			routeFound = true
		}
	}
	if !routeFound {
		t.Error("the route seed should still be recorded as a route endpoint")
	}
}
