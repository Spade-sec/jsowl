package jsowl

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// localRequestRecorder records every path a local analysis requested.
type localRequestRecorder struct {
	mutex   sync.Mutex
	paths   []string
	methods []string
	headers []http.Header
}

func (r *localRequestRecorder) add(request *http.Request) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.paths = append(r.paths, request.URL.Path)
	r.methods = append(r.methods, request.Method)
	r.headers = append(r.headers, request.Header.Clone())
}

func (r *localRequestRecorder) methodsSnapshot() []string {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return append([]string(nil), r.methods...)
}

func (r *localRequestRecorder) snapshot() ([]string, []http.Header) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return append([]string(nil), r.paths...), append([]http.Header(nil), r.headers...)
}

func findEndpointByURL(result *Result, rawURL string) *Endpoint {
	for index := range result.Endpoints {
		if result.Endpoints[index].URL == rawURL {
			return &result.Endpoints[index]
		}
	}
	return nil
}

func hasIssueCode(result *Result, code string) bool {
	for _, issue := range result.Issues {
		if issue.Code == code {
			return true
		}
	}
	return false
}

// TestAnalyzeLocationProbesAbsoluteAPIWithoutTarget verifies the core change:
// a local file may request the absolute APIs it contains, without -u, while
// remote documents, scripts, chunks and maps are never crawled.
func TestAnalyzeLocationProbesAbsoluteAPIWithoutTarget(t *testing.T) {
	recorder := &localRequestRecorder{}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		recorder.add(request)
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"name":"alice","role":"admin"}`))
	}))
	defer server.Close()

	root := t.TempDir()
	file := filepath.Join(root, "app.js")
	writeLocalScript(t, file, fmt.Sprintf(`
const lazy = import(%q);
const worker = %q;
fetch(%q);
`, server.URL+"/chunk.js", server.URL+"/worker.js", server.URL+"/users"))

	config := DefaultConfig()
	config.Output.Directory = t.TempDir()
	result, err := AnalyzeLocation(context.Background(), config, file)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := findEndpointByURL(result, server.URL+"/users")
	if endpoint == nil {
		t.Fatalf("absolute endpoint missing: %#v", result.Endpoints)
	}
	if !endpoint.Authorized || endpoint.StatusCode != http.StatusOK {
		t.Fatalf("endpoint = %#v", endpoint)
	}
	if !strings.HasPrefix(endpoint.SourceURL, "file://") {
		t.Fatalf("source = %q", endpoint.SourceURL)
	}
	if !containsString(endpoint.ResponseParams, "name") {
		t.Fatalf("response params = %#v", endpoint.ResponseParams)
	}
	paths, _ := recorder.snapshot()
	for _, path := range paths {
		if path != "/users" {
			t.Fatalf("unexpected remote fetch: %v", paths)
		}
	}
}

// TestAnalyzeLocationResolvesRelativeAPIWithBaseURL covers --base-url prefix
// semantics and confirms configured headers reach the probe. It also checks
// that an already-prefixed path is not joined twice.
func TestAnalyzeLocationResolvesRelativeAPIWithBaseURL(t *testing.T) {
	recorder := &localRequestRecorder{}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		recorder.add(request)
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"id":1}`))
	}))
	defer server.Close()

	root := t.TempDir()
	file := filepath.Join(root, "app.js")
	writeLocalScript(t, file, `
fetch("/users");
fetch("/api/profile");
`)
	config := DefaultConfig()
	config.Output.Directory = t.TempDir()
	config.Request.Headers["X-Api-Key"] = "test-key"

	result, err := AnalyzeLocationWithBase(
		context.Background(), config, file, server.URL+"/api",
	)
	if err != nil {
		t.Fatal(err)
	}
	users := findEndpointByURL(result, server.URL+"/api/users")
	if users == nil || !users.Authorized || users.StatusCode != http.StatusOK {
		t.Fatalf("users endpoint = %#v, all = %#v", users, result.Endpoints)
	}
	if users.SourceURL == "" || !strings.HasPrefix(users.SourceURL, "file://") {
		t.Fatalf("source = %q", users.SourceURL)
	}
	if findEndpointByURL(result, server.URL+"/api/api/users") != nil {
		t.Fatal("base URL was joined twice")
	}
	if findEndpointByURL(result, server.URL+"/api/profile") == nil {
		t.Fatalf("already-prefixed endpoint missing: %#v", result.Endpoints)
	}
	_, headers := recorder.snapshot()
	if len(headers) == 0 || headers[0].Get("X-Api-Key") != "test-key" {
		t.Fatalf("request headers = %#v", headers)
	}
}

// TestAnalyzeLocationUsesCallSiteAbsoluteBaseURL checks the per-candidate
// fallback: an absolute axios baseURL recovered at this call site resolves the
// relative path, without becoming a directory-wide base.
func TestAnalyzeLocationUsesCallSiteAbsoluteBaseURL(t *testing.T) {
	recorder := &localRequestRecorder{}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		recorder.add(request)
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	root := t.TempDir()
	file := filepath.Join(root, "app.js")
	writeLocalScript(t, file, fmt.Sprintf(`
const api = axios.create({ baseURL: %q });
api.get("/items");
function other() { return "/elsewhere"; }
`, server.URL+"/v1"))

	config := DefaultConfig()
	config.Output.Directory = t.TempDir()
	result, err := AnalyzeLocation(context.Background(), config, file)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := findEndpointByURL(result, server.URL+"/v1/items")
	if endpoint == nil {
		t.Fatalf("call-site base endpoint missing: %#v", result.Endpoints)
	}
	if !endpoint.Authorized || endpoint.StatusCode != http.StatusOK {
		t.Fatalf("endpoint = %#v", endpoint)
	}
	if findEndpointByURL(result, server.URL+"/v1/elsewhere") != nil {
		t.Fatal("the call-site base leaked onto an unrelated path")
	}
	paths, _ := recorder.snapshot()
	if len(paths) != 1 || paths[0] != "/v1/items" {
		t.Fatalf("requested paths = %v", paths)
	}
}

// TestAnalyzeLocationKeepsUnresolvedRelativeAPIStatic covers the no-base case.
// Nothing is requested; the reference survives with a diagnostic.
func TestAnalyzeLocationKeepsUnresolvedRelativeAPIStatic(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "app.js")
	writeLocalScript(t, file, `
fetch("/users");
axios.get("/login");
`)
	config := DefaultConfig()
	config.Output.Directory = t.TempDir()
	result, err := AnalyzeLocation(context.Background(), config, file)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"/users", "/login"} {
		endpoint := findLocalEndpoint(result, raw)
		if endpoint == nil {
			t.Fatalf("%s missing: %#v", raw, result.Endpoints)
		}
		if endpoint.URL != raw || endpoint.Authorized {
			t.Fatalf("%s = %#v", raw, endpoint)
		}
		if strings.HasPrefix(endpoint.URL, "file://") {
			t.Fatalf("%s used file:// as an HTTP base", raw)
		}
	}
	if !hasIssueCode(result, "local_endpoint_unresolved") {
		t.Fatalf("diagnostic missing: %#v", result.Issues)
	}
}

// TestAnalyzeLocationRespectsRestrictedDomains makes sure explicit absolute
// APIs do not bypass the configured scope.
func TestAnalyzeLocationRespectsRestrictedDomains(t *testing.T) {
	recorder := &localRequestRecorder{}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		recorder.add(request)
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{}`))
	}))
	defer server.Close()

	root := t.TempDir()
	file := filepath.Join(root, "app.js")
	writeLocalScript(t, file, fmt.Sprintf(`fetch(%q);`, server.URL+"/users"))

	config := DefaultConfig()
	config.Output.Directory = t.TempDir()
	config.Scope.RestrictDomains = []string{"allowed.example.test"}
	result, err := AnalyzeLocation(context.Background(), config, file)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := findEndpointByURL(result, server.URL+"/users")
	if endpoint == nil {
		t.Fatalf("endpoint missing: %#v", result.Endpoints)
	}
	if endpoint.Authorized {
		t.Fatalf("restricted endpoint was authorized: %#v", endpoint)
	}
	paths, _ := recorder.snapshot()
	if len(paths) != 0 {
		t.Fatalf("restricted host was requested: %v", paths)
	}
}

// TestAnalyzeLocationResponseCannotTriggerRemoteCrawl verifies that script
// references found in an API response are recorded, not downloaded.
func TestAnalyzeLocationResponseCannotTriggerRemoteCrawl(t *testing.T) {
	recorder := &localRequestRecorder{}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		recorder.add(request)
		writer.Header().Set("Content-Type", "application/javascript")
		_, _ = writer.Write([]byte(`import("./response-chunk.js");`))
	}))
	defer server.Close()

	root := t.TempDir()
	file := filepath.Join(root, "app.js")
	writeLocalScript(t, file, fmt.Sprintf(`fetch(%q);`, server.URL+"/users"))

	config := DefaultConfig()
	config.Output.Directory = t.TempDir()
	if _, err := AnalyzeLocation(context.Background(), config, file); err != nil {
		t.Fatal(err)
	}
	paths, _ := recorder.snapshot()
	if len(paths) != 1 || paths[0] != "/users" {
		t.Fatalf("requested paths = %v", paths)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
