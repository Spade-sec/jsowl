package pipeline

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/youmulijiang/jsowl/internal/analyze"
	"github.com/youmulijiang/jsowl/internal/collect"
	"github.com/youmulijiang/jsowl/internal/collect/direct"
	"github.com/youmulijiang/jsowl/internal/discover"
	"github.com/youmulijiang/jsowl/internal/extract"
	"github.com/youmulijiang/jsowl/internal/model"
	"github.com/youmulijiang/jsowl/internal/scheduler"
	"github.com/youmulijiang/jsowl/internal/scope"
)

// newInterruptionState builds a minimal run state for driving computeBatch
// and mergeDeferred directly, the way RunDetailed wires them.
func newInterruptionState(t *testing.T, p *Pipeline) *runState {
	t.Helper()
	root, err := url.Parse("http://stub.test")
	if err != nil {
		t.Fatal(err)
	}
	targetScope, err := scope.New(root, p.options.Config.Scope)
	if err != nil {
		t.Fatal(err)
	}
	spa := discover.SPAEvidence{}
	return &runState{
		result: &model.Result{
			Target:    "http://stub.test",
			Resources: []model.Resource{},
			Endpoints: []model.Endpoint{},
			Findings:  []model.Finding{},
			Issues:    []model.Issue{},
		},
		queue:          scheduler.New(0, 5),
		endpointIndex:  map[string]int{},
		findingSeen:    map[string]struct{}{},
		paramSeen:      map[string]struct{}{},
		prefixEligible: map[string]struct{}{},
		hosts: extract.NewAggregator(
			p.hostExtractor, model.HostOriginContent,
		),
		spa:         &spa,
		targetScope: targetScope,
		root:        root,
		coverage:    p.coverage,
	}
}

func sourceOf(raw string) *url.URL {
	parsed, _ := url.Parse(raw)
	return parsed
}

// TestComputeBatchCancellationKeepsFinishedAnalyses pins the merge-before-
// error contract: analyses that finished before the caller cancelled stay
// merged, and the cancelled ones are recorded as un-analyzed instead of
// being dropped or reported as failures.
func TestComputeBatchCancellationKeepsFinishedAnalyses(t *testing.T) {
	p, _ := newGatedPipeline(t, model.DefaultConfig(), &gatedGetter{
		responses: map[string]collect.Response{},
		started:   make(chan string, 8),
		held:      make(chan struct{}),
	})
	state := newInterruptionState(t, p)

	// First batch runs to completion under a live context.
	first := []deferredJS{
		{source: sourceOf("http://stub.test/one.js"), key: "http://stub.test/one.js",
			body: []byte(`var one = "/api/from-one";`)},
		{source: sourceOf("http://stub.test/two.js"), key: "http://stub.test/two.js",
			body: []byte(`var two = "/api/from-two";`)},
	}
	for _, analysis := range p.computeBatch(context.Background(), first, state) {
		// In the real flow every deferred item was fetched before analysis;
		// mirror that invariant here.
		state.coverage.fetched(analysis.item.key)
		p.mergeDeferred(state, analysis)
	}
	if got := state.coverage.snapshot().Analyzed; got != 2 {
		t.Fatalf("first batch analyzed = %d, want 2", got)
	}

	// The second batch is dispatched under a cancelled context: every item
	// carries an explicit cancellation instead of a zero value.
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	second := []deferredJS{
		{source: sourceOf("http://stub.test/three.js"), key: "http://stub.test/three.js",
			body: []byte(`var three = 1;`)},
	}
	for _, analysis := range p.computeBatch(cancelled, second, state) {
		state.coverage.fetched(analysis.item.key)
		p.mergeDeferred(state, analysis)
	}

	coverage := state.coverage.snapshot()
	if coverage.Analyzed != 2 {
		t.Errorf("analyzed = %d, want 2 (first batch kept)", coverage.Analyzed)
	}
	if coverage.AnalysisPending != 1 {
		t.Errorf("pending = %d, want 1 (second batch cancelled)", coverage.AnalysisPending)
	}
	if coverage.AnalysisFailed != 0 {
		t.Errorf("failed = %d, want 0: a cancellation is not a file failure", coverage.AnalysisFailed)
	}
	for _, issue := range state.result.Issues {
		if issue.Code == "js_analysis_failed" {
			t.Errorf("cancelled analysis produced a failure issue: %+v", issue)
		}
	}
}

// TestComputeBatchSingleFileFailureDoesNotBlockOthers pins the isolation
// contract: one unreadable file is recorded as a failed analysis with its
// reason, and the rest of the batch is unaffected.
func TestComputeBatchSingleFileFailureDoesNotBlockOthers(t *testing.T) {
	p, _ := newGatedPipeline(t, model.DefaultConfig(), &gatedGetter{
		responses: map[string]collect.Response{},
		started:   make(chan string, 8),
		held:      make(chan struct{}),
	})
	reportDirectory := t.TempDir()
	state := newInterruptionState(t, p)
	state.reportDirectory = reportDirectory

	batch := []deferredJS{
		// Points at a file that was never saved: the read fails.
		{source: sourceOf("http://stub.test/broken.js"), key: "http://stub.test/broken.js",
			path: "js/does-not-exist.js"},
		{source: sourceOf("http://stub.test/healthy.js"), key: "http://stub.test/healthy.js",
			body: []byte(`fetch("/api/healthy")`)},
	}
	for _, analysis := range p.computeBatch(context.Background(), batch, state) {
		state.coverage.fetched(analysis.item.key)
		p.mergeDeferred(state, analysis)
	}

	coverage := state.coverage.snapshot()
	if coverage.Analyzed != 1 {
		t.Errorf("analyzed = %d, want 1", coverage.Analyzed)
	}
	if coverage.AnalysisFailed != 1 {
		t.Errorf("failed = %d, want 1", coverage.AnalysisFailed)
	}
	foundIssue := false
	for _, issue := range state.result.Issues {
		if issue.Code == "js_analysis_failed" &&
			strings.Contains(issue.URL, "broken.js") && issue.Message != "" {
			foundIssue = true
		}
	}
	if !foundIssue {
		t.Errorf("broken.js failure not recorded: %+v", state.result.Issues)
	}
	foundUnfinished := false
	for _, item := range coverage.Unfinished {
		if item.State == "analysis_failed" && strings.Contains(item.URL, "broken.js") {
			foundUnfinished = true
		}
	}
	if !foundUnfinished {
		t.Errorf("broken.js missing from unfinished list: %+v", coverage.Unfinished)
	}
	if !endpointCandidateRecorded(state, "/api/healthy") {
		t.Error("healthy.js endpoints were lost when its sibling failed")
	}
}

func endpointCandidateRecorded(state *runState, path string) bool {
	for _, endpoint := range state.result.Endpoints {
		if strings.HasSuffix(endpoint.URL, path) {
			return true
		}
	}
	return false
}

// countingGetter records every GET and POST target path.
type countingGetter struct {
	mu    sync.Mutex
	paths map[string]int
}

func (g *countingGetter) Get(
	ctx context.Context,
	target *url.URL,
	_ http.Header,
) (collect.Response, error) {
	g.mu.Lock()
	if g.paths == nil {
		g.paths = map[string]int{}
	}
	g.paths[target.Path]++
	g.mu.Unlock()
	<-ctx.Done()
	return collect.Response{}, ctx.Err()
}

func (g *countingGetter) Post(
	ctx context.Context,
	target *url.URL,
	_ http.Header,
	_ []byte,
) (collect.Response, error) {
	g.mu.Lock()
	if g.paths == nil {
		g.paths = map[string]int{}
	}
	g.paths["POST "+target.Path]++
	g.mu.Unlock()
	<-ctx.Done()
	return collect.Response{}, ctx.Err()
}

func (g *countingGetter) total() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	total := 0
	for _, count := range g.paths {
		total += count
	}
	return total
}

// TestExhaustedBudgetRecordsDiscoveryWithoutRequests pins the no-reopen rule:
// once the collection budget is gone, analysis-time discoveries are recorded
// (the script as unfetched, the interface as unprobed) and no network request
// is dispatched.
func TestExhaustedBudgetRecordsDiscoveryWithoutRequests(t *testing.T) {
	getter := &countingGetter{}
	config := model.DefaultConfig()
	config.Output.Directory = t.TempDir()
	engine, err := analyze.New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	networkCtx, cancel := context.WithCancel(context.Background())
	cancel()
	p := New(Options{
		Getter: getter, Analyzer: engine, Config: config,
		NetworkContext: networkCtx,
	})
	entry := collect.Response{
		URL: "http://stub.test/", StatusCode: http.StatusOK,
		Header: http.Header{"Content-Type": {"text/html; charset=utf-8"}},
		Body: []byte(`<script src="/app.js"></script>` +
			`<div onclick="fetch('/api/from-entry')"></div>`),
	}
	result, _, err := p.RunDetailed(
		context.Background(), model.Target{URL: "http://stub.test"},
		http.Header{}, &entry, nil, nil,
	)
	// The budget context here is a pre-cancelled WithCancel, so its error is
	// context.Canceled; the pipeline wraps and preserves it unchanged.
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("RunDetailed() error = %v, want the budget context error", err)
	}
	if got := getter.total(); got != 0 {
		t.Errorf("getter served %d request(s), want 0 after budget expiry", got)
	}
	if result.Completeness == nil || result.Completeness.Collection.Complete {
		t.Errorf("collection should be incomplete: %+v", result.Completeness)
	}
	coverage := result.Completeness.Coverage
	if coverage.Discovered != 1 || coverage.FetchNotAttempted != 1 {
		t.Errorf("coverage = %+v, want app.js discovered and not attempted", coverage)
	}
	if !endpointRecordedUnprobed(result, "/api/from-entry") {
		t.Errorf("entry-discovered endpoint missing or probed: %+v", result.Endpoints)
	}
}

func endpointRecordedUnprobed(result *model.Result, path string) bool {
	for _, endpoint := range result.Endpoints {
		if strings.HasSuffix(endpoint.URL, path) && endpoint.StatusCode == 0 {
			return true
		}
	}
	return false
}

// TestDeferredVendorBundleSkipsAnalysis pins the policy contract in
// download-first mode: a third-party bundle is still saved and reported as a
// resource, but its analysis is skipped and counted as a policy skip, exactly
// like the inline mode.
func TestDeferredVendorBundleSkipsAnalysis(t *testing.T) {
	vendorBody := "/*! jQuery JavaScript Library v3.6.0\n" +
		" * https://jquery.org/\n * Released under the MIT license\n */\n" +
		`fetch("/api/vendor-endpoint");`
	server := httptest.NewServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		if request.URL.Path == "/lib.js" {
			writer.Header().Set("Content-Type", "application/javascript")
			_, _ = writer.Write([]byte(vendorBody))
			return
		}
		writer.Header().Set("Content-Type", "text/html")
		_, _ = writer.Write([]byte(`<script src="/lib.js"></script>`))
	}))
	defer server.Close()

	config := model.DefaultConfig()
	config.Mode = model.ModeDirect
	config.Scope.SkipLibraryBundles = true
	config.Output.Directory = t.TempDir()
	engine, err := analyze.New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	p := New(Options{
		Getter: getterForServer(t, server), Analyzer: engine, Config: config,
	})
	result, _, err := p.RunDetailed(
		context.Background(), model.Target{URL: server.URL}, http.Header{},
		nil, nil, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	saved := false
	for _, resource := range result.Resources {
		if strings.HasSuffix(resource.URL, "/lib.js") {
			saved = resource.LocalPath != ""
		}
	}
	if !saved {
		t.Error("vendor bundle should still be saved for manual inspection")
	}
	if endpointCandidateRecordedIn(result, "/api/vendor-endpoint") {
		t.Error("vendor bundle was analyzed despite the skip policy")
	}
	if result.Completeness == nil ||
		result.Completeness.Coverage.AnalysisSkipped != 1 ||
		result.Completeness.Coverage.Analyzed != 0 {
		t.Errorf("coverage should count one policy-skipped analysis: %+v",
			result.Completeness)
	}
	if !result.Completeness.Analysis.Complete {
		t.Error("a policy skip is a terminal state, not an incomplete analysis")
	}
}

func endpointCandidateRecordedIn(result *model.Result, path string) bool {
	for _, endpoint := range result.Endpoints {
		if strings.HasSuffix(endpoint.URL, path) {
			return true
		}
	}
	return false
}

// getterForServer wraps an httptest server URL in a direct client so pipeline
// tests can run against a real HTTP endpoint.
func getterForServer(t *testing.T, server *httptest.Server) collect.Getter {
	t.Helper()
	config := model.DefaultConfig()
	jar := &inMemoryJar{}
	client, err := direct.New(config.Request, config.Limits.MaxBodySize, jar)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// TestRunLocalCountsPolicySkipsAndCancellation pins local-mode coverage:
// third-party files count as analysis_skipped, and a cancelled run keeps the
// files already analyzed and reports the rest as un-analyzed.
func TestRunLocalCountsPolicySkipsAndCancellation(t *testing.T) {
	config := model.DefaultConfig()
	config.Scope.SkipLibraryBundles = true
	config.Output.Directory = t.TempDir()
	engine, err := analyze.New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	p := New(Options{
		Getter: &countingGetter{}, Analyzer: engine, Config: config,
	})
	input := LocalInput{
		Target: "local-test",
		Files: []LocalFile{
			{URL: "file:///stub/app.js", Body: []byte(`fetch("/api/local-app")`)},
			{URL: "file:///stub/lib.js", Body: []byte(
				"/*! jQuery JavaScript Library v3.6.0 */\nvar jq = 1;")},
		},
	}
	result, _, err := p.RunLocal(context.Background(), input, http.Header{})
	if err != nil {
		t.Fatal(err)
	}
	coverage := result.Completeness.Coverage
	if coverage.Discovered != 2 || coverage.Fetched != 2 {
		t.Errorf("coverage = %+v, want both files discovered and fetched", coverage)
	}
	if coverage.Analyzed != 1 || coverage.AnalysisSkipped != 1 {
		t.Errorf("coverage = %+v, want 1 analyzed and 1 policy-skipped", coverage)
	}
	if !result.Completeness.Analysis.Complete ||
		!result.Completeness.Collection.Complete {
		t.Errorf("a complete local run should be complete: %+v", result.Completeness)
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	// A fresh pipeline keeps the coverage per run; the Scanner creates one
	// pipeline per target for exactly this reason.
	partialPipeline := New(Options{
		Getter: &countingGetter{}, Analyzer: engine, Config: config,
	})
	partial, _, err := partialPipeline.RunLocal(cancelled, input, http.Header{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("RunLocal() error = %v, want context canceled", err)
	}
	if partial == nil {
		t.Fatal("RunLocal() returned no result on cancellation")
	}
	if partial.Completeness == nil {
		t.Fatal("cancelled run carries no completeness record")
	}
	cancelledCoverage := partial.Completeness.Coverage
	// The files are registered before analysis starts, so a cancellation
	// makes them analysis-pending instead of making them vanish.
	if cancelledCoverage.Discovered != 2 || cancelledCoverage.Fetched != 2 {
		t.Errorf("coverage = %+v, want both files registered as fetched", cancelledCoverage)
	}
	if cancelledCoverage.Analyzed != 0 || cancelledCoverage.AnalysisPending != 2 {
		t.Errorf("coverage = %+v, want nothing analyzed and both pending", cancelledCoverage)
	}
	if partial.Completeness.Analysis.Complete {
		t.Error("analysis should be incomplete when files were never processed")
	}
}
