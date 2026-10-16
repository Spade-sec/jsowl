package pipeline

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/youmulijiang/jsowl/internal/analyze"
	"github.com/youmulijiang/jsowl/internal/collect"
	"github.com/youmulijiang/jsowl/internal/collect/direct"
	"github.com/youmulijiang/jsowl/internal/model"
	"github.com/youmulijiang/jsowl/internal/storage"
)

func newTestPipeline(t *testing.T, config model.Config, server *httptest.Server) *Pipeline {
	t.Helper()
	jar := &inMemoryJar{}
	client, err := direct.New(config.Request, config.Limits.MaxBodySize, jar)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	engine, err := analyze.New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	config.Output.Directory = t.TempDir()
	return New(Options{Getter: client, Analyzer: engine, Config: config})
}

type inMemoryJar struct{}

func (jar *inMemoryJar) SetCookies(*url.URL, []*http.Cookie) {}
func (jar *inMemoryJar) Cookies(*url.URL) []*http.Cookie     { return nil }

func TestRunDetailedRecordsRouteSeedsWithoutProbing(t *testing.T) {
	var probedMutex sync.Mutex
	var probedPaths []string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		probedMutex.Lock()
		probedPaths = append(probedPaths, request.URL.Path)
		probedMutex.Unlock()
		writer.Header().Set("Content-Type", "text/html")
		_, _ = writer.Write([]byte(`<div id="app"></div>`))
	}))
	defer server.Close()

	config := model.DefaultConfig()
	config.Mode = model.ModeDirect
	pipeline := newTestPipeline(t, config, server)
	target := model.Target{URL: server.URL}

	result, _, err := pipeline.RunDetailed(context.Background(), target, http.Header{}, nil,
		[]Seed{
			{URL: server.URL + "/admin/users", Kind: model.ResourceTypeRoute,
				Source: "cdp-runtime", Evidence: model.EvidenceRuntime},
			{URL: server.URL + "/api/users", Kind: model.ResourceTypeAPI,
				Source: "cdp", Evidence: model.EvidenceRuntime},
		}, nil)
	if err != nil {
		t.Fatal(err)
	}

	var routeSeen, apiSeen bool
	for _, endpoint := range result.Endpoints {
		switch endpoint.Type {
		case "route":
			routeSeen = true
			if endpoint.URL != server.URL+"/admin/users" || endpoint.Source != "cdp-runtime" {
				t.Fatalf("route endpoint = %#v", endpoint)
			}
		case "api":
			apiSeen = true
		}
	}
	if !routeSeen || !apiSeen {
		t.Fatalf("route=%v api=%v endpoints=%#v", routeSeen, apiSeen, result.Endpoints)
	}
	for _, path := range probedPaths {
		if strings.Contains(path, "/admin/users") {
			t.Fatalf("route was probed: %v", probedPaths)
		}
	}
}

// Hash-router routes must keep their fragment: two distinct hash routes
// would otherwise collapse into the same index URL.
func TestRunDetailedKeepsHashRouteFragment(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "text/html")
		_, _ = writer.Write([]byte(`<div id="app"></div>`))
	}))
	defer server.Close()

	config := model.DefaultConfig()
	config.Mode = model.ModeDirect
	pipeline := newTestPipeline(t, config, server)

	result, _, err := pipeline.RunDetailed(context.Background(),
		model.Target{URL: server.URL}, http.Header{}, nil,
		[]Seed{
			{URL: server.URL + "/#/admin", Kind: model.ResourceTypeRoute,
				Source: "cdp-runtime", Evidence: model.EvidenceRuntime},
			{URL: server.URL + "/#/users", Kind: model.ResourceTypeRoute,
				Source: "cdp-runtime", Evidence: model.EvidenceRuntime},
		}, nil)
	if err != nil {
		t.Fatal(err)
	}

	routes := make(map[string]bool)
	for _, endpoint := range result.Endpoints {
		if endpoint.Type == "route" {
			routes[endpoint.URL] = true
		}
	}
	for _, want := range []string{server.URL + "/#/admin", server.URL + "/#/users"} {
		if !routes[want] {
			t.Fatalf("hash route %q missing from %#v", want, routes)
		}
	}
}

func TestProbeRoutesSeparatesServerRoutesFromSPAFallback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "text/html")
		switch request.URL.Path {
		case "/admin":
			_, _ = writer.Write([]byte(`<html>real admin page</html>`))
		default:
			_, _ = writer.Write([]byte(`<html>spa shell</html>`))
		}
	}))
	defer server.Close()

	config := model.DefaultConfig()
	config.Mode = model.ModeDirect
	config.Scope.ProbeRoutes = true
	pipeline := newTestPipeline(t, config, server)

	result, _, err := pipeline.RunDetailed(context.Background(),
		model.Target{URL: server.URL}, http.Header{}, nil,
		[]Seed{
			{URL: server.URL + "/admin", Kind: model.ResourceTypeRoute, Source: "cdp-runtime"},
			{URL: server.URL + "/dashboard", Kind: model.ResourceTypeRoute, Source: "cdp-runtime"},
		}, nil)
	if err != nil {
		t.Fatal(err)
	}

	probes := map[string]string{}
	for _, endpoint := range result.Endpoints {
		if endpoint.Type == "route" {
			probes[strings.TrimPrefix(endpoint.URL, server.URL)] = endpoint.Probe
		}
	}
	if probes["/admin"] != "server" {
		t.Fatalf("/admin probe = %q, want server (%v)", probes["/admin"], probes)
	}
	if probes["/dashboard"] != "static" {
		t.Fatalf("/dashboard probe = %q, want static (%v)", probes["/dashboard"], probes)
	}
}

const deferredScriptBody = "fetch('/api/from-deferred')"

// stubGetter serves fixed responses per path without a live server.
type stubGetter struct {
	responses map[string]collect.Response
	requests  []string
}

func (stub *stubGetter) Get(
	_ context.Context, target *url.URL, _ http.Header,
) (collect.Response, error) {
	stub.requests = append(stub.requests, target.Path)
	response, ok := stub.responses[target.Path]
	if !ok {
		return collect.Response{}, errors.New("unexpected URL: " + target.String())
	}
	return response, nil
}

func newStubPipeline(t *testing.T, config model.Config, getter collect.Getter) (*Pipeline, string) {
	t.Helper()
	engine, err := analyze.New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	config.Output.Directory = t.TempDir()
	return New(Options{Getter: getter, Analyzer: engine, Config: config}),
		config.Output.Directory
}

func findEndpointURLs(result *model.Result) []string {
	urls := make([]string, 0, len(result.Endpoints))
	for _, endpoint := range result.Endpoints {
		if endpoint.Type == "api" {
			urls = append(urls, endpoint.URL)
		}
	}
	return urls
}

func TestDeferredAnalysisPersistsToDiskAndFindsEndpoints(t *testing.T) {
	getter := &stubGetter{responses: map[string]collect.Response{
		"/": {URL: "http://stub.test/", StatusCode: 200,
			Header: http.Header{"Content-Type": []string{"text/html"}},
			Body:   []byte(`<script src="/app.js"></script>`)},
		"/app.js": {URL: "http://stub.test/app.js", StatusCode: 200,
			Header: http.Header{"Content-Type": []string{"application/javascript"}},
			Body:   []byte(deferredScriptBody)},
		"/api/from-deferred": {URL: "http://stub.test/api/from-deferred", StatusCode: 200,
			Header: http.Header{"Content-Type": []string{"application/json"}},
			Body:   []byte(`{"ok":true}`)},
	}}
	config := model.DefaultConfig()
	config.Mode = model.ModeDirect
	pipeline, outputDirectory := newStubPipeline(t, config, getter)

	result, _, err := pipeline.RunDetailed(context.Background(),
		model.Target{URL: "http://stub.test"}, http.Header{}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(strings.Join(findEndpointURLs(result), ","), "/api/from-deferred") {
		t.Fatalf("deferred endpoint missing: %v", findEndpointURLs(result))
	}
	var saved []string
	for _, resource := range result.Resources {
		if resource.LocalPath != "" {
			saved = append(saved, resource.LocalPath)
		}
	}
	if len(saved) == 0 {
		t.Fatal("no JS resource was persisted")
	}
	// LocalPath is relative to the target's report directory, so the recorded
	// path resolves next to the report that references it.
	reportDirectory, err := storage.TargetDirectory(outputDirectory, "http://stub.test")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range saved {
		if _, err := os.Stat(
			filepath.Join(reportDirectory, filepath.FromSlash(path)),
		); err != nil {
			t.Fatalf("saved file missing: %v", err)
		}
		if _, err := storage.LoadJS(reportDirectory, path); err != nil {
			t.Fatalf("saved file is not readable from the report directory: %v", err)
		}
	}
	if len(result.Issues) != 0 {
		t.Fatalf("unexpected issues: %v", result.Issues)
	}
}

func TestDeferredAnalysisFallsBackToMemoryWhenSaveFails(t *testing.T) {
	getter := &stubGetter{responses: map[string]collect.Response{
		"/": {URL: "http://stub.test/", StatusCode: 200,
			Header: http.Header{"Content-Type": []string{"text/html"}},
			Body:   []byte(`<script src="/app.js"></script>`)},
		"/app.js": {URL: "http://stub.test/app.js", StatusCode: 200,
			Header: http.Header{"Content-Type": []string{"application/javascript"}},
			Body:   []byte(deferredScriptBody)},
		"/api/from-deferred": {URL: "http://stub.test/api/from-deferred", StatusCode: 200,
			Header: http.Header{"Content-Type": []string{"application/json"}},
			Body:   []byte(`{"ok":true}`)},
	}}
	config := model.DefaultConfig()
	config.Mode = model.ModeDirect
	pipeline, outputDirectory := newStubPipeline(t, config, getter)
	// Pre-create the hash-suffixed destination as a directory so SaveJSIn's
	// destination inspection fails (any non-ErrNotExist read error aborts it).
	blocker := filepath.Join(outputDirectory, "stub.test", "js", "app.147d4857.js")
	if err := os.MkdirAll(blocker, 0o750); err != nil {
		t.Fatal(err)
	}

	result, _, err := pipeline.RunDetailed(context.Background(),
		model.Target{URL: "http://stub.test"}, http.Header{}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(strings.Join(findEndpointURLs(result), ","), "/api/from-deferred") {
		t.Fatalf("endpoints lost when save failed: %v", findEndpointURLs(result))
	}
	if len(result.Issues) == 0 || result.Issues[0].Code != "js_save_failed" {
		t.Fatalf("expected js_save_failed issue, got %v", result.Issues)
	}
}

func TestDeferredAnalysisEmitsProbeEventsWithoutBlocking(t *testing.T) {
	getter := &stubGetter{responses: map[string]collect.Response{
		"/": {URL: "http://stub.test/", StatusCode: 200,
			Header: http.Header{"Content-Type": []string{"text/html"}},
			Body:   []byte(`<script src="/app.js"></script>`)},
		"/app.js": {URL: "http://stub.test/app.js", StatusCode: 200,
			Header: http.Header{"Content-Type": []string{"application/javascript"}},
			Body:   []byte(deferredScriptBody)},
		"/api/from-deferred": {URL: "http://stub.test/api/from-deferred", StatusCode: 200,
			Header: http.Header{"Content-Type": []string{"application/json"}},
			Body:   []byte(`{"ok":true}`)},
	}}
	config := model.DefaultConfig()
	config.Mode = model.ModeDirect
	engine, err := analyze.New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	config.Output.Directory = t.TempDir()
	events := make(chan model.ProbeEvent, 1)
	pipeline := New(Options{
		Getter: getter, Analyzer: engine, Config: config, ProbeEvents: events,
	})

	result, _, err := pipeline.RunDetailed(context.Background(),
		model.Target{URL: "http://stub.test"}, http.Header{}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	close(events)
	var received []model.ProbeEvent
	for event := range events {
		received = append(received, event)
	}
	if len(received) != 1 {
		t.Fatalf("probe events = %#v", received)
	}
	event := received[0]
	if event.URL != "http://stub.test/api/from-deferred" ||
		event.StatusCode != 200 || event.Target != "http://stub.test/" {
		t.Fatalf("probe event = %#v", event)
	}
	for _, endpoint := range result.Endpoints {
		if endpoint.URL == event.URL && endpoint.StatusCode != event.StatusCode {
			t.Fatalf("event/report mismatch: %d vs %d",
				event.StatusCode, endpoint.StatusCode)
		}
	}
}

func TestDeferredAnalysisDropsProbeEventsWhenConsumerIsSlow(t *testing.T) {
	getter := &stubGetter{responses: map[string]collect.Response{
		"/": {URL: "http://stub.test/", StatusCode: 200,
			Header: http.Header{"Content-Type": []string{"text/html"}},
			Body:   []byte(`<script src="/app.js"></script>`)},
		"/app.js": {URL: "http://stub.test/app.js", StatusCode: 200,
			Header: http.Header{"Content-Type": []string{"application/javascript"}},
			Body:   []byte(deferredScriptBody)},
		"/api/from-deferred": {URL: "http://stub.test/api/from-deferred", StatusCode: 200,
			Header: http.Header{"Content-Type": []string{"application/json"}},
			Body:   []byte(`{"ok":true}`)},
	}}
	config := model.DefaultConfig()
	config.Mode = model.ModeDirect
	engine, err := analyze.New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	config.Output.Directory = t.TempDir()
	events := make(chan model.ProbeEvent) // unbuffered, never drained
	pipeline := New(Options{
		Getter: getter, Analyzer: engine, Config: config, ProbeEvents: events,
	})

	result, _, err := pipeline.RunDetailed(context.Background(),
		model.Target{URL: "http://stub.test"}, http.Header{}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(findEndpointURLs(result), ","), "/api/from-deferred") {
		t.Fatalf("endpoint missing with attached sink: %v", findEndpointURLs(result))
	}
}

func TestDeferredAnalysisFallsBackToMemoryWhenTruncated(t *testing.T) {
	getter := &stubGetter{responses: map[string]collect.Response{
		"/": {URL: "http://stub.test/", StatusCode: 200,
			Header: http.Header{"Content-Type": []string{"text/html"}},
			Body:   []byte(`<script src="/app.js"></script>`)},
		"/app.js": {URL: "http://stub.test/app.js", StatusCode: 200,
			Header:    http.Header{"Content-Type": []string{"application/javascript"}},
			Body:      []byte(deferredScriptBody),
			Truncated: true},
	}}
	config := model.DefaultConfig()
	config.Mode = model.ModeDirect
	pipeline, _ := newStubPipeline(t, config, getter)

	result, _, err := pipeline.RunDetailed(context.Background(),
		model.Target{URL: "http://stub.test"}, http.Header{}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(strings.Join(findEndpointURLs(result), ","), "/api/from-deferred") {
		t.Fatalf("endpoints lost when truncated: %v", findEndpointURLs(result))
	}
	codes := make([]string, 0, len(result.Issues))
	for _, issue := range result.Issues {
		codes = append(codes, issue.Code)
	}
	if len(codes) == 0 || !strings.Contains(strings.Join(codes, ","), "js_not_saved") {
		t.Fatalf("expected js_not_saved issue, got %v", result.Issues)
	}
}
