package browser

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-rod/rod/lib/launcher"
	"github.com/youmulijiang/jsowl/internal/model"
)

// collectRoutes drives the injected collector against one page and returns the
// route paths it reported.
func collectRoutes(t *testing.T, body string) []string {
	t.Helper()
	bin, found := launcher.LookPath()
	if !found {
		t.Skip("local Chromium-compatible browser is not installed")
	}
	server := httptest.NewServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		if request.URL.Path != "/app" {
			http.NotFound(writer, request)
			return
		}
		writer.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(writer, "<!doctype html><html><body><div id=\"app\"></div><script>%s</script></body></html>", body)
	}))
	defer server.Close()

	collector, err := New(model.BrowserConfig{
		Path:      bin,
		Headless:  true,
		NoSandbox: true,
		Idle:      50 * time.Millisecond,
		Wait:      300 * time.Millisecond,
		Timeout:   10 * time.Second,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	target, err := url.Parse(server.URL + "/app")
	if err != nil {
		t.Fatal(err)
	}
	rendered, err := collector.Collect(t.Context(), target, http.Header{})
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	paths := make([]string, 0, len(rendered.Routes))
	for _, route := range rendered.Routes {
		paths = append(paths, route.Path)
	}
	return paths
}

// TestCollectorCapturesASinglePushedRoute is the regression test for a history
// hook that recorded the location before applying the navigation: a route
// pushed once, with nothing navigating afterwards, was never reported.
func TestCollectorCapturesASinglePushedRoute(t *testing.T) {
	paths := collectRoutes(t, `history.pushState({}, "", "/app/dashboard");`)
	if !hasRoute(paths, "/app/dashboard") {
		t.Fatalf("a single pushed route was not captured, got %v", paths)
	}
}

// TestCollectorCapturesReplacedAndHashedRoutes covers the other history-mode
// navigations a router performs.
func TestCollectorCapturesReplacedAndHashedRoutes(t *testing.T) {
	paths := collectRoutes(t, `
history.pushState({}, "", "/app/dashboard");
setTimeout(() => history.replaceState({}, "", "/app/settings"), 20);
setTimeout(() => { location.hash = "#/reports"; }, 40);
`)
	if !hasRoute(paths, "/app/settings") {
		t.Errorf("a replaced route was not captured, got %v", paths)
	}
	found := false
	for _, path := range paths {
		if strings.Contains(path, "#/reports") {
			found = true
		}
	}
	if !found {
		t.Errorf("a hash route was not captured, got %v", paths)
	}
	// The pushed route stays visible even though the page moved on.
	if !hasRoute(paths, "/app/dashboard") {
		t.Errorf("an earlier pushed route was dropped, got %v", paths)
	}
}

func hasRoute(paths []string, want string) bool {
	for _, path := range paths {
		if path == want {
			return true
		}
	}
	return false
}
