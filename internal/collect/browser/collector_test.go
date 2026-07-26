package browser

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-rod/rod/lib/launcher"
	"github.com/youmulijiang/jsowl/internal/model"
)

func TestNewCombinesCustomAndEmbeddedCollectorScripts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "collect_resource_urls.js")
	const marker = `window.__customCollectorLoaded = true;`
	if err := os.WriteFile(path, []byte(marker), 0o600); err != nil {
		t.Fatal(err)
	}
	collector, err := New(model.BrowserConfig{CollectorScript: path})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(collector.script, "__jsowlCollector") ||
		!strings.Contains(collector.script, marker) {
		t.Fatalf("combined collector script = %q", collector.script)
	}
}

func TestCollectorCapturesDynamicResourceURLs(t *testing.T) {
	bin, found := launcher.LookPath()
	if !found {
		t.Skip("local Chromium-compatible browser is not installed")
	}

	mux := http.NewServeMux()
	var mainAuthorization atomic.Bool
	var mainCookie atomic.Value
	var externalAuthorization atomic.Value
	var fetchCompleted atomic.Bool
	external := httptest.NewServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		externalAuthorization.Store(request.Header.Get("Authorization"))
		writer.Header().Set("Content-Type", "application/javascript")
		fmt.Fprint(writer, `window.__externalLoaded = true`)
	}))
	defer external.Close()
	server := httptest.NewServer(mux)
	defer server.Close()

	mux.HandleFunc("/", func(w http.ResponseWriter, request *http.Request) {
		mainAuthorization.Store(request.Header.Get("Authorization") == "Bearer target-secret")
		mainCookie.Store(request.Header.Get("Cookie"))
		w.Header().Set("Content-Type", "text/html")
		http.SetCookie(w, &http.Cookie{Name: "runtime", Value: "updated", Path: "/"})
		fmt.Fprintf(w, `<!doctype html><html><body><main id="app"></main><script src=%q></script><script>
fetch(%q);
const xhr = new XMLHttpRequest();
xhr.open("GET", %q);
xhr.send();
setTimeout(() => {
  const script = document.createElement("script");
  script.src = %q;
  document.body.appendChild(script);
}, 75);
</script></body></html>`, external.URL+"/external.js", server.URL+"/fetch", server.URL+"/xhr", server.URL+"/late.js")
	})
	mux.HandleFunc("/fetch", func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(400 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"api":"/from-fetch"}`)
		fetchCompleted.Store(true)
	})
	mux.HandleFunc("/xhr", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"api":"/from-xhr"}`)
	})
	mux.HandleFunc("/late.js", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprint(w, `window.__lateLoaded = true`)
	})

	collector, err := New(model.BrowserConfig{
		Path:     bin,
		Headless: true,
		Idle:     50 * time.Millisecond,
		Wait:     200 * time.Millisecond,
		Timeout:  10 * time.Second,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	result, err := collector.Collect(
		context.Background(),
		target,
		http.Header{
			"User-Agent":    {"JsOwl-Test"},
			"Authorization": {"Bearer target-secret"},
			"X-API-Key":     {"target-key"},
			"Cookie":        {"session=configured"},
		},
	)
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if len(result.HTML) == 0 {
		t.Fatal("Collect() returned empty rendered HTML")
	}
	for _, want := range []string{
		server.URL + "/fetch",
		server.URL + "/xhr",
		server.URL + "/late.js",
	} {
		if !slices.Contains(result.URLs, want) {
			t.Errorf("Collect() URLs do not contain %q: %#v", want, result.URLs)
		}
	}
	if !mainAuthorization.Load() {
		t.Fatal("same-origin document did not receive target Authorization")
	}
	if got, _ := mainCookie.Load().(string); !strings.Contains(got, "session=configured") {
		t.Fatalf("same-origin document Cookie = %q", got)
	}
	if got, _ := externalAuthorization.Load().(string); got != "" {
		t.Fatalf("external script received Authorization %q", got)
	}
	if !fetchCompleted.Load() {
		t.Fatal("Collect() returned before an in-flight fetch completed")
	}
	if !containsCookie(result.Cookies, "runtime", "updated") {
		t.Fatalf("browser cookies = %#v", result.Cookies)
	}
}

func containsCookie(cookies []*http.Cookie, name, value string) bool {
	for _, cookie := range cookies {
		if cookie.Name == name && cookie.Value == value {
			return true
		}
	}
	return false
}
