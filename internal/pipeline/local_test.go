package pipeline

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/youmulijiang/jsowl/internal/model"
)

type localPathRecorder struct {
	mutex sync.Mutex
	paths []string
}

func (r *localPathRecorder) record(request *http.Request) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.paths = append(r.paths, request.URL.Path)
}

func (r *localPathRecorder) snapshot() []string {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return append([]string(nil), r.paths...)
}

// TestRunLocalProbesOnlyAPIs verifies that local input reuses the normal probe
// flow and that scripts, chunks and source maps discovered in a script or an
// API response are never scheduled.
func TestRunLocalProbesOnlyAPIs(t *testing.T) {
	recorder := &localPathRecorder{}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		recorder.record(request)
		if request.URL.Path == "/api/users" {
			writer.Header().Set("Content-Type", "application/javascript")
			_, _ = writer.Write([]byte(fmt.Sprintf(
				`import(%q);`, serverURL(request)+"/response-chunk.js",
			)))
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{}`))
	}))
	defer server.Close()

	config := model.DefaultConfig()
	config.Output.Directory = t.TempDir()
	resourcePipeline := newTestPipeline(t, config, server)
	body := fmt.Sprintf(`
const lazy = import(%q);
const worker = %q;
fetch(%q);
`, server.URL+"/chunk.js", server.URL+"/worker.js", server.URL+"/api/users")

	result, _, err := resourcePipeline.RunLocal(context.Background(), LocalInput{
		Target: "app.js",
		Files: []LocalFile{{
			URL: "file:///tmp/app.js", Body: []byte(body),
		}},
	}, http.Header{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Mode != model.ModeLocal {
		t.Fatalf("mode = %q", result.Mode)
	}
	urls := findEndpointURLs(result)
	if !containsLocalURL(urls, server.URL+"/api/users") {
		t.Fatalf("API endpoint missing: %#v", result.Endpoints)
	}
	for _, endpoint := range result.Endpoints {
		if endpoint.URL == server.URL+"/api/users" {
			if !endpoint.Authorized || endpoint.StatusCode != http.StatusOK {
				t.Fatalf("API probe was not recorded: %#v", endpoint)
			}
		}
	}
	paths := recorder.snapshot()
	if len(paths) != 1 || paths[0] != "/api/users" {
		t.Fatalf("requested paths = %v", paths)
	}
}

// TestRunLocalResolvesRelativeAgainstBaseURL checks the explicit-base branch
// in the shared candidate handler.
func TestRunLocalResolvesRelativeAgainstBaseURL(t *testing.T) {
	recorder := &localPathRecorder{}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		recorder.record(request)
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	config := model.DefaultConfig()
	config.Output.Directory = t.TempDir()
	resourcePipeline := newTestPipeline(t, config, server)
	result, _, err := resourcePipeline.RunLocal(context.Background(), LocalInput{
		Target:  "app.js",
		BaseURL: server.URL + "/v1",
		Files: []LocalFile{{
			URL: "file:///tmp/app.js", Body: []byte(`fetch("/users");`),
		}},
	}, http.Header{})
	if err != nil {
		t.Fatal(err)
	}
	urls := findEndpointURLs(result)
	if !containsLocalURL(urls, server.URL+"/v1/users") {
		t.Fatalf("base-resolved endpoint missing: %#v", result.Endpoints)
	}
	paths := recorder.snapshot()
	if len(paths) != 1 || paths[0] != "/v1/users" {
		t.Fatalf("requested paths = %v", paths)
	}
}

func serverURL(request *http.Request) string {
	scheme := "http"
	if request.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + request.Host
}

func containsLocalURL(urls []string, want string) bool {
	for _, url := range urls {
		if url == want {
			return true
		}
	}
	return false
}
