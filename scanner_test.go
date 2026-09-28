package jsowl

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/youmulijiang/jsowl/internal/collect"
	"github.com/youmulijiang/jsowl/internal/model"
)

func TestScannerDirectRecursivelyCollectsChunkEndpointAndSensitiveFinding(t *testing.T) {
	var mu sync.Mutex
	requests := make(map[string]int)
	methods := make(map[string]string)

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		mu.Lock()
		requests[request.URL.Path]++
		methods[request.URL.Path] = request.Method
		mu.Unlock()

		switch request.URL.Path {
		case "/":
			writer.Header().Set("Content-Type", "text/html")
			_, _ = writer.Write([]byte(`<div id="app"></div><script src="/runtime.js"></script>`))
		case "/runtime.js":
			writer.Header().Set("Content-Type", "application/javascript")
			_, _ = writer.Write([]byte(
				`n.p="/static/";var chunks={"1":"users.hash"};` +
					`function load(i){return n.p+chunks[i]+".js"}`,
			))
		case "/static/users.hash.js":
			writer.Header().Set("Content-Type", "application/javascript")
			_, _ = writer.Write([]byte(
				`fetch('/api/users');` +
					`const token='eyJhbGciOiJIUzI1NiJ9.abcdefghijklmno.abcdefghijklmnop';`,
			))
		case "/api/users":
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(`{"next":"/api/roles"}`))
		case "/api/roles":
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(`{"roles":["admin"]}`))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Mode = ModeDirect
	config.Concurrency.ResourcesPerTarget = 8
	config.Limits.MaxResources = 40
	tempOutputRedirects(t, &config)
	scanner, err := New(config)
	if err != nil {
		t.Fatal(err)
	}

	result, err := scanner.Scan(context.Background(), Target{URL: server.URL})
	if err != nil {
		t.Fatal(err)
	}

	if !containsResource(result, "/static/users.hash.js", ResourceTypeChunk) {
		t.Fatalf("chunk resource missing: %#v", result.Resources)
	}
	if !containsEndpoint(result, "/api/users", http.StatusOK) ||
		!containsEndpoint(result, "/api/roles", http.StatusOK) {
		t.Fatalf("endpoints missing: %#v", result.Endpoints)
	}
	if !containsFinding(result, "hae.密钥凭证.jwt-token") {
		t.Fatalf("JWT finding missing: %#v", result.Findings)
	}
	for path, count := range requests {
		if count != 1 {
			t.Errorf("requests[%q] = %d, want 1", path, count)
		}
		if methods[path] != http.MethodGet {
			t.Errorf("method[%q] = %q, want GET", path, methods[path])
		}
	}
}

func TestScannerKeepsPartialResultWhenNestedResourceFails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/" {
			_, _ = writer.Write([]byte(`<script src="/missing.js"></script>`))
			return
		}
		http.Error(writer, "missing", http.StatusNotFound)
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Mode = ModeDirect
	tempOutputRedirects(t, &config)
	scanner, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	result, err := scanner.Scan(context.Background(), Target{URL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Resources) < 2 {
		t.Fatalf("resources = %#v", result.Resources)
	}
}

type fakeBrowser struct {
	result collect.BrowserResult
	err    error
	calls  atomic.Int32
}

func (f *fakeBrowser) Collect(
	context.Context,
	*url.URL,
	http.Header,
) (collect.BrowserResult, error) {
	f.calls.Add(1)
	return f.result, f.err
}

func TestScannerModeSelectionAndAutoDegradation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		_ *http.Request,
	) {
		writer.Header().Set("Content-Type", "text/html")
		_, _ = writer.Write([]byte(`<main id="app"></main><script src="/app.js"></script>`))
	}))
	defer server.Close()

	t.Run("direct never calls browser", func(t *testing.T) {
		browser := &fakeBrowser{err: errors.New("must not be called")}
		config := DefaultConfig()
		config.Mode = ModeDirect
		tempOutputRedirects(t, &config)
		scanner, err := New(config)
		if err != nil {
			t.Fatal(err)
		}
		scanner.browserFactory = func(model.BrowserConfig) (collect.BrowserCollector, error) {
			return browser, nil
		}

		if _, err := scanner.Scan(context.Background(), Target{URL: server.URL}); err != nil {
			t.Fatal(err)
		}
		if browser.calls.Load() != 0 {
			t.Fatalf("browser calls = %d, want 0", browser.calls.Load())
		}
	})

	t.Run("auto preserves direct result when browser fails", func(t *testing.T) {
		browser := &fakeBrowser{err: errors.New("chrome missing")}
		config := DefaultConfig()
		config.Mode = ModeAuto
		tempOutputRedirects(t, &config)
		scanner, err := New(config)
		if err != nil {
			t.Fatal(err)
		}
		scanner.browserFactory = func(model.BrowserConfig) (collect.BrowserCollector, error) {
			return browser, nil
		}

		result, err := scanner.Scan(context.Background(), Target{URL: server.URL})
		if err != nil {
			t.Fatal(err)
		}
		if !result.BrowserStatus.Attempted || !result.BrowserStatus.Degraded {
			t.Fatalf("browser status = %#v", result.BrowserStatus)
		}
		if len(result.Resources) == 0 {
			t.Fatal("direct result was lost during browser degradation")
		}
	})

	t.Run("browser mode returns collector failure", func(t *testing.T) {
		browser := &fakeBrowser{err: errors.New("chrome missing")}
		config := DefaultConfig()
		config.Mode = ModeBrowser
		scanner, err := New(config)
		if err != nil {
			t.Fatal(err)
		}
		scanner.browserFactory = func(model.BrowserConfig) (collect.BrowserCollector, error) {
			return browser, nil
		}
		if _, err := scanner.Scan(
			context.Background(),
			Target{URL: server.URL},
		); err == nil {
			t.Fatal("Scan() error = nil, want browser failure")
		}
	})
}

func TestAutoMergesBrowserResourcesWithoutDuplicates(t *testing.T) {
	var runtimeRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		switch request.URL.Path {
		case "/":
			writer.Header().Set("Content-Type", "text/html")
			_, _ = writer.Write([]byte(`<main id="app"></main>`))
		case "/runtime.js":
			runtimeRequests.Add(1)
			writer.Header().Set("Content-Type", "application/javascript")
			_, _ = writer.Write([]byte(`fetch("/api/runtime")`))
		case "/api/runtime":
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(`{"secret":"/api/hidden"}`))
		case "/api/hidden":
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(`{"ok":true}`))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	browser := &fakeBrowser{result: collect.BrowserResult{
		HTML: []byte(`<main id="app"></main><script src="/runtime.js"></script>`),
		URLs: []string{server.URL + "/runtime.js", server.URL + "/api/runtime"},
		Network: []collect.NetworkRecord{
			{URL: server.URL + "/runtime.js", ContentType: "application/javascript", ResourceType: "Script"},
			{URL: server.URL + "/api/runtime", ContentType: "application/json", ResourceType: "Fetch"},
		},
	}}
	config := DefaultConfig()
	config.Mode = ModeAuto
	tempOutputRedirects(t, &config)
	scanner, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	scanner.browserFactory = func(model.BrowserConfig) (collect.BrowserCollector, error) {
		return browser, nil
	}

	result, err := scanner.Scan(context.Background(), Target{URL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if !result.BrowserStatus.Used || result.BrowserStatus.Degraded {
		t.Fatalf("browser status = %#v", result.BrowserStatus)
	}
	if !containsResource(result, "/runtime.js", ResourceTypeScript) {
		t.Fatalf("runtime script missing: %#v", result.Resources)
	}
	if !containsEndpoint(result, "/api/runtime", http.StatusOK) {
		t.Fatalf("runtime API missing: %#v", result.Endpoints)
	}
	resourceURLs := make(map[string]struct{})
	for _, resource := range result.Resources {
		if _, duplicate := resourceURLs[resource.URL]; duplicate {
			t.Fatalf("duplicate resource URL %q in %#v", resource.URL, result.Resources)
		}
		resourceURLs[resource.URL] = struct{}{}
	}
	if runtimeRequests.Load() != 1 {
		t.Fatalf("runtime.js requests = %d, want 1", runtimeRequests.Load())
	}
}

func TestAutoDoesNotRefetchDirectResourcesDuringBrowserMerge(t *testing.T) {
	var scriptRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		switch request.URL.Path {
		case "/":
			writer.Header().Set("Content-Type", "text/html")
			_, _ = writer.Write([]byte(
				`<main id="app"></main><script src="/app.js"></script>`,
			))
		case "/app.js":
			scriptRequests.Add(1)
			writer.Header().Set("Content-Type", "application/javascript")
			_, _ = writer.Write([]byte(`window.applicationLoaded = true`))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	browser := &fakeBrowser{result: collect.BrowserResult{
		HTML: []byte(`<main id="app"></main><script src="/app.js"></script>`),
		URLs: []string{server.URL + "/app.js"},
		Network: []collect.NetworkRecord{{
			URL: server.URL + "/app.js", ResourceType: "Script",
		}},
	}}
	config := DefaultConfig()
	config.Mode = ModeAuto
	tempOutputRedirects(t, &config)
	scanner, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	scanner.browserFactory = func(model.BrowserConfig) (collect.BrowserCollector, error) {
		return browser, nil
	}
	if _, err := scanner.Scan(context.Background(), Target{URL: server.URL}); err != nil {
		t.Fatal(err)
	}
	if scriptRequests.Load() != 1 {
		t.Fatalf("app.js requests = %d, want 1", scriptRequests.Load())
	}
}

func TestScanBatchBoundsTargetConcurrencyAndClosesOnCancellation(t *testing.T) {
	var active atomic.Int32
	var maximum atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		_ *http.Request,
	) {
		current := active.Add(1)
		defer active.Add(-1)
		for {
			previous := maximum.Load()
			if current <= previous || maximum.CompareAndSwap(previous, current) {
				break
			}
		}
		time.Sleep(75 * time.Millisecond)
		_, _ = writer.Write([]byte(`<html></html>`))
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Mode = ModeDirect
	config.Concurrency.Targets = 2
	scanner, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	targets := make([]Target, 6)
	for index := range targets {
		targets[index] = Target{URL: server.URL + "/?target=" + string(rune('a'+index))}
	}
	count := 0
	for item := range scanner.ScanBatch(context.Background(), targets) {
		if item.Err != nil {
			t.Fatal(item.Err)
		}
		count++
	}
	if count != len(targets) {
		t.Fatalf("batch results = %d, want %d", count, len(targets))
	}
	if maximum.Load() != 2 {
		t.Fatalf("maximum target concurrency = %d, want 2", maximum.Load())
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	for range scanner.ScanBatch(cancelled, targets) {
	}
}

func TestScannerOptionallyStoresOnlyJavaScript(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		switch request.URL.Path {
		case "/":
			writer.Header().Set("Content-Type", "text/html")
			_, _ = writer.Write([]byte(`<script src="/app.js"></script>`))
		case "/app.js":
			writer.Header().Set("Content-Type", "application/javascript")
			_, _ = writer.Write([]byte(`fetch("/api/data")`))
		case "/api/data":
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(`{"sensitive":"body"}`))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Mode = ModeDirect
	config.Output.Directory = t.TempDir()
	config.Output.DownloadJS = true
	scanner, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	result, err := scanner.Scan(context.Background(), Target{URL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	var scriptPath string
	for _, resource := range result.Resources {
		if resource.Type == ResourceTypeScript {
			scriptPath = resource.LocalPath
		}
		if resource.Type == ResourceTypeAPI && resource.LocalPath != "" {
			t.Fatalf("API body was persisted at %q", resource.LocalPath)
		}
	}
	if scriptPath == "" {
		t.Fatal("script LocalPath is empty")
	}
	if _, err := os.Stat(filepath.Join(
		config.Output.Directory,
		filepath.FromSlash(scriptPath),
	)); err != nil {
		t.Fatalf("stored script: %v", err)
	}
}

// TestScannerDownloadsAllJSBeforeAnalysis verifies the fetch-first pipeline:
// with download_js enabled every script is fetched before the regex and AST
// analysis of any downloaded script runs (the probe of an endpoint extracted
// from script 1 must happen after script 2 has been fetched).
func TestScannerDownloadsAllJSBeforeAnalysis(t *testing.T) {
	var mu sync.Mutex
	var order []string

	server := httptest.NewServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		mu.Lock()
		order = append(order, request.URL.Path)
		mu.Unlock()
		switch request.URL.Path {
		case "/":
			writer.Header().Set("Content-Type", "text/html")
			_, _ = writer.Write([]byte(
				`<script src="/one.js"></script>` +
					`<script src="/two.js"></script>`,
			))
		case "/one.js":
			writer.Header().Set("Content-Type", "application/javascript")
			_, _ = writer.Write([]byte(
				`fetch("/api/from-one");const access_key = "AKIAJSOWLTEST123";`,
			))
		case "/two.js":
			writer.Header().Set("Content-Type", "application/javascript")
			_, _ = writer.Write([]byte(`window.two = true;`))
		case "/api/from-one":
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(`{"ok":true}`))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Mode = ModeDirect
	config.Output.Directory = t.TempDir()
	config.Output.DownloadJS = true
	scanner, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	result, err := scanner.Scan(context.Background(), Target{URL: server.URL})
	if err != nil {
		t.Fatal(err)
	}

	var findingValues []string
	for _, finding := range result.Findings {
		findingValues = append(findingValues, finding.Value)
	}
	if !slices.Contains(findingValues, "AKIAJSOWLTEST123") {
		t.Fatalf("deferred regex analysis missed finding, values: %v", findingValues)
	}

	var endpoint *Endpoint
	for index := range result.Endpoints {
		if result.Endpoints[index].Raw == "/api/from-one" {
			endpoint = &result.Endpoints[index]
		}
	}
	if endpoint == nil {
		t.Fatal("deferred AST analysis missed /api/from-one endpoint")
	}
	if endpoint.StatusCode != 200 {
		t.Fatalf("deferred endpoint probe status = %d, want 200", endpoint.StatusCode)
	}

	mu.Lock()
	defer mu.Unlock()
	lastScript, firstProbe := -1, -1
	for index, path := range order {
		if path == "/two.js" {
			lastScript = index
		}
		if path == "/api/from-one" && firstProbe == -1 {
			firstProbe = index
		}
	}
	if lastScript == -1 || firstProbe == -1 || firstProbe < lastScript {
		t.Fatalf("analysis ran before all scripts were downloaded, order: %v", order)
	}
}

func TestScannerDoesNotForwardTargetHeadersToExternalScripts(t *testing.T) {
	var externalAuthorization atomic.Value
	external := httptest.NewServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		externalAuthorization.Store(request.Header.Get("Authorization"))
		writer.Header().Set("Content-Type", "application/javascript")
		_, _ = writer.Write([]byte(`window.externalLoaded = true`))
	}))
	defer external.Close()

	target := httptest.NewServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		_ *http.Request,
	) {
		writer.Header().Set("Content-Type", "text/html")
		_, _ = writer.Write([]byte(
			`<script src="` + external.URL + `/external.js"></script>`,
		))
	}))
	defer target.Close()

	config := DefaultConfig()
	config.Mode = ModeDirect
	config.Request.Headers["Authorization"] = "Bearer target-secret"
	config.Request.Headers["X-API-Key"] = "target-key"
	tempOutputRedirects(t, &config)
	scanner, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := scanner.Scan(context.Background(), Target{URL: target.URL}); err != nil {
		t.Fatal(err)
	}
	if got, _ := externalAuthorization.Load().(string); got != "" {
		t.Fatalf("external script received Authorization %q", got)
	}
}

func TestScannerPropagatesNestedResourceDeadline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		if request.URL.Path == "/" {
			writer.Header().Set("Content-Type", "text/html")
			_, _ = writer.Write([]byte(`<script src="/slow.js"></script>`))
			return
		}
		<-request.Context().Done()
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Mode = ModeDirect
	config.Request.TargetTimeout = 40 * time.Millisecond
	scanner, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	_, err = scanner.Scan(context.Background(), Target{URL: server.URL})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Scan() error = %v, want context deadline exceeded", err)
	}
}

type blockingBrowser struct{}

func (blockingBrowser) Collect(
	ctx context.Context,
	_ *url.URL,
	_ http.Header,
) (collect.BrowserResult, error) {
	<-ctx.Done()
	return collect.BrowserResult{}, ctx.Err()
}

func TestAutoDoesNotDegradeTargetDeadline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		_ *http.Request,
	) {
		_, _ = writer.Write([]byte(`<main id="app"></main>`))
	}))
	defer server.Close()
	config := DefaultConfig()
	config.Mode = ModeAuto
	config.Request.TargetTimeout = 30 * time.Millisecond
	scanner, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	scanner.browserFactory = func(model.BrowserConfig) (collect.BrowserCollector, error) {
		return blockingBrowser{}, nil
	}
	_, err = scanner.Scan(context.Background(), Target{URL: server.URL})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Scan() error = %v, want context deadline exceeded", err)
	}
}

func TestScannerDeepCopiesConfiguration(t *testing.T) {
	var authorization atomic.Value
	server := httptest.NewServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		authorization.Store(request.Header.Get("Authorization"))
		_, _ = writer.Write([]byte("<html></html>"))
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Mode = ModeDirect
	config.Request.Headers["Authorization"] = "Bearer original"
	scanner, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	config.Request.Headers["Authorization"] = "Bearer mutated"
	config.Scope.AllowDomains = append(config.Scope.AllowDomains, "mutated.test")
	if _, err := scanner.Scan(context.Background(), Target{URL: server.URL}); err != nil {
		t.Fatal(err)
	}
	if got, _ := authorization.Load().(string); got != "Bearer original" {
		t.Fatalf("Authorization = %q, want immutable original", got)
	}
}

func TestBrowserCookiesFlowBackToSurfResourceGETs(t *testing.T) {
	var scriptCookie atomic.Value
	server := httptest.NewServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		if request.URL.Path == "/app.js" {
			scriptCookie.Store(request.Header.Get("Cookie"))
			writer.Header().Set("Content-Type", "application/javascript")
			_, _ = writer.Write([]byte(`window.ok = true`))
			return
		}
		_, _ = writer.Write([]byte("<html></html>"))
	}))
	defer server.Close()

	browser := &fakeBrowser{result: collect.BrowserResult{
		HTML: []byte(`<script src="/app.js"></script>`),
		URLs: []string{server.URL + "/app.js"},
		Cookies: []*http.Cookie{{
			Name: "runtime", Value: "updated", Path: "/",
		}},
	}}
	config := DefaultConfig()
	config.Mode = ModeBrowser
	tempOutputRedirects(t, &config)
	scanner, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	scanner.browserFactory = func(model.BrowserConfig) (collect.BrowserCollector, error) {
		return browser, nil
	}
	if _, err := scanner.Scan(context.Background(), Target{URL: server.URL}); err != nil {
		t.Fatal(err)
	}
	if got, _ := scriptCookie.Load().(string); !strings.Contains(got, "runtime=updated") {
		t.Fatalf("Surf script Cookie = %q", got)
	}
}

func TestScannerSkipsSensitiveAnalysisForBinaryBodies(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		switch request.URL.Path {
		case "/":
			writer.Header().Set("Content-Type", "text/html")
			_, _ = writer.Write([]byte(`<script src="/app.js"></script>`))
		case "/app.js":
			writer.Header().Set("Content-Type", "application/javascript")
			_, _ = writer.Write([]byte(`fetch("/api/binary")`))
		case "/api/binary":
			writer.Header().Set("Content-Type", "application/octet-stream")
			_, _ = writer.Write([]byte(`password="binary-secret"`))
		}
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Mode = ModeDirect
	tempOutputRedirects(t, &config)
	scanner, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	result, err := scanner.Scan(context.Background(), Target{URL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range result.Findings {
		if urlPath(finding.SourceURL) == "/api/binary" {
			t.Fatalf("binary response produced finding %#v", finding)
		}
	}
}

func containsResource(result *Result, path string, resourceType ResourceType) bool {
	for _, resource := range result.Resources {
		if resource.Type == resourceType && urlPath(resource.URL) == path {
			return true
		}
	}
	return false
}

// tempOutputRedirects points config.Output.Directory at a per-test temp dir
// so DownloadJS never writes reports into the repository during go test.
func tempOutputRedirects(t *testing.T, config *Config) {
	t.Helper()
	config.Output.Directory = t.TempDir()
}

func containsEndpoint(result *Result, path string, status int) bool {
	for _, endpoint := range result.Endpoints {
		if urlPath(endpoint.URL) == path && endpoint.StatusCode == status {
			return true
		}
	}
	return false
}

func containsFinding(result *Result, ruleID string) bool {
	for _, finding := range result.Findings {
		if finding.RuleID == ruleID {
			return true
		}
	}
	return false
}

func urlPath(raw string) string {
	request, err := http.NewRequest(http.MethodGet, raw, nil)
	if err != nil {
		return ""
	}
	return request.URL.Path
}
