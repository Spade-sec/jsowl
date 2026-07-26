package browser

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/go-rod/rod/lib/launcher"
	"github.com/youmulijiang/jsowl/internal/model"
)

func TestCollectorCapturesDynamicResourceURLs(t *testing.T) {
	bin, found := launcher.LookPath()
	if !found {
		t.Skip("local Chromium-compatible browser is not installed")
	}

	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()

	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<!doctype html><html><body><main id="app"></main><script>
fetch(%q);
const xhr = new XMLHttpRequest();
xhr.open("GET", %q);
xhr.send();
setTimeout(() => {
  const script = document.createElement("script");
  script.src = %q;
  document.body.appendChild(script);
}, 75);
</script></body></html>`, server.URL+"/fetch", server.URL+"/xhr", server.URL+"/late.js")
	})
	mux.HandleFunc("/fetch", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"api":"/from-fetch"}`)
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
		http.Header{"User-Agent": {"JsOwl-Test"}},
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
}
