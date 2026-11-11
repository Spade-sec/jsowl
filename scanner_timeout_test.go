package jsowl

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/youmulijiang/jsowl/internal/collect"
	"github.com/youmulijiang/jsowl/internal/model"
)

// endpointExists reports whether any recorded endpoint resolves to the path,
// whatever its probe status is.
func endpointExists(result *Result, path string) bool {
	for _, endpoint := range result.Endpoints {
		if urlPath(endpoint.URL) == path {
			return true
		}
	}
	return false
}

// TestCollectionTimeoutStillAnalyzesFetchedJS pins the core contract: the
// network collection budget (request.target_timeout) may expire mid-download,
// but every JS that was already fetched must still be analyzed and reported,
// with the result marking collection incomplete and local analysis complete.
func TestCollectionTimeoutStillAnalyzesFetchedJS(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		switch request.URL.Path {
		case "/":
			writer.Header().Set("Content-Type", "text/html")
			_, _ = writer.Write([]byte(
				`<script src="/a.js"></script><script src="/b.js"></script>` +
					`<script src="/slow.js"></script>`))
		case "/slow.js":
			// Holds the request open until the scan's budget cancels it.
			<-request.Context().Done()
		default:
			writer.Header().Set("Content-Type", "application/javascript")
			_, _ = writer.Write([]byte(
				`fetch("/api/from-script", {method: "POST", json: {}})`))
		}
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Mode = ModeDirect
	config.Request.TargetTimeout = 300 * time.Millisecond
	tempOutputRedirects(t, &config)
	scanner, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	result, err := scanner.Scan(context.Background(), Target{URL: server.URL})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Scan() error = %v, want context deadline exceeded", err)
	}
	if result == nil {
		t.Fatal("Scan() returned no result; fetched JS was lost")
	}
	if !endpointExists(result, "/api/from-script") {
		t.Fatal("endpoints discovered in fetched scripts were lost")
	}
	completeness := result.Completeness
	if completeness == nil {
		t.Fatal("result carries no completeness record")
	}
	if completeness.Collection.Complete {
		t.Error("collection should be incomplete after the budget expired")
	}
	if !completeness.Analysis.Complete {
		t.Errorf("analysis of fetched JS should be complete: %+v", completeness.Analysis)
	}
	coverage := completeness.Coverage
	if coverage.Discovered != 3 {
		t.Errorf("discovered = %d, want 3 (a.js, b.js, slow.js)", coverage.Discovered)
	}
	if coverage.Fetched != 2 || coverage.FetchFailed != 1 {
		t.Errorf("fetch states = fetched %d / failed %d, want 2 / 1",
			coverage.Fetched, coverage.FetchFailed)
	}
	if coverage.Fetched+coverage.FetchFailed+coverage.FetchSkipped+
		coverage.FetchNotAttempted != coverage.Discovered {
		t.Errorf("fetch states do not partition discovered: %+v", coverage)
	}
	if coverage.Analyzed != 2 || coverage.AnalysisPending != 0 {
		t.Errorf("analysis states = analyzed %d / pending %d, want 2 / 0",
			coverage.Analyzed, coverage.AnalysisPending)
	}
}

// TestUserCancelKeepsCompletedResults pins caller-cancellation semantics:
// a Ctrl+C (or caller ctx cancel) stops remaining work promptly, yet every
// already-merged result survives and the cancelled work is recorded as such,
// never as success.
func TestUserCancelKeepsCompletedResults(t *testing.T) {
	hangRequested := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		switch request.URL.Path {
		case "/":
			writer.Header().Set("Content-Type", "text/html")
			_, _ = writer.Write([]byte(
				`<script src="/first.js"></script><script src="/hang.js"></script>`))
		case "/hang.js":
			// With one worker, this request arriving proves first.js was
			// already fetched and merged, so the assertions below are
			// synchronized on it instead of on sleeps.
			close(hangRequested)
			<-request.Context().Done()
		default:
			writer.Header().Set("Content-Type", "application/javascript")
			_, _ = writer.Write([]byte(`fetch("/api/kept")`))
		}
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Mode = ModeDirect
	config.Concurrency.ResourcesPerTarget = 1
	config.Request.TargetTimeout = time.Minute
	tempOutputRedirects(t, &config)
	scanner, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-hangRequested
		cancel()
	}()
	result, err := scanner.Scan(ctx, Target{URL: server.URL})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Scan() error = %v, want context canceled", err)
	}
	if result == nil {
		t.Fatal("Scan() returned no result; completed work was lost")
	}
	if !endpointExists(result, "/api/kept") {
		t.Error("endpoints from the merged download were lost")
	}
	completeness := result.Completeness
	if completeness == nil {
		t.Fatal("result carries no completeness record")
	}
	if completeness.Collection.Complete {
		t.Error("collection should be incomplete after caller cancellation")
	}
	coverage := completeness.Coverage
	if coverage.Fetched != 1 || coverage.FetchFailed != 1 {
		t.Errorf("fetch states = fetched %d / failed %d, want 1 / 1",
			coverage.Fetched, coverage.FetchFailed)
	}
	if coverage.AnalysisPending != 1 || coverage.Analyzed != 0 {
		t.Errorf("analysis states = pending %d / analyzed %d, want 1 / 0",
			coverage.AnalysisPending, coverage.Analyzed)
	}
	if completeness.Analysis.Complete {
		t.Error("analysis should be incomplete: one fetched JS was never analyzed")
	}
	found := false
	for _, item := range coverage.Unfinished {
		if item.State == "fetch_failed" && strings.Contains(item.URL, "/hang.js") {
			found = true
		}
	}
	if !found {
		t.Errorf("hang.js missing from the unfinished list: %+v", coverage.Unfinished)
	}
}

// TestAutoKeepsStaticResultsWhenBrowserStageTimesOut pins auto-mode behavior:
// a browser stage that runs into the collection budget must not discard the
// direct pass results, and the error must keep identifying the deadline.
func TestAutoKeepsStaticResultsWhenBrowserStageTimesOut(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		switch request.URL.Path {
		case "/":
			writer.Header().Set("Content-Type", "text/html")
			_, _ = writer.Write([]byte(
				`<div id="app"></div><script src="/app.js"></script>`))
		case "/app.js":
			writer.Header().Set("Content-Type", "application/javascript")
			_, _ = writer.Write([]byte(`fetch("/api/static-evidence")`))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Mode = ModeAuto
	config.Request.TargetTimeout = 300 * time.Millisecond
	tempOutputRedirects(t, &config)
	scanner, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	scanner.browserFactory = func(model.BrowserConfig) (collect.BrowserCollector, error) {
		return blockingBrowser{}, nil
	}
	result, err := scanner.Scan(context.Background(), Target{URL: server.URL})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Scan() error = %v, want context deadline exceeded", err)
	}
	if result == nil {
		t.Fatal("Scan() returned no result; the static pass results were lost")
	}
	if !endpointExists(result, "/api/static-evidence") {
		t.Error("static pass endpoints were lost")
	}
	if !result.BrowserStatus.Degraded {
		t.Error("browser stage should be recorded as degraded")
	}
	if completeness := result.Completeness; completeness == nil ||
		completeness.Collection.Complete {
		t.Errorf("collection should be incomplete after the browser stage stopped: %+v",
			result.Completeness)
	}
}
