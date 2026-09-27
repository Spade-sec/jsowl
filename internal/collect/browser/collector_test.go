package browser

import (
	"context"
	"errors"
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
	"github.com/youmulijiang/jsowl/internal/collect"
	"github.com/youmulijiang/jsowl/internal/model"
)

func TestTransientBrowserRetryIsLimitedToPreNavigationFailures(t *testing.T) {
	transient := fmt.Errorf(
		"%w: %w",
		errPreNavigation,
		errors.New("wsarecv: use of closed network connection"),
	)
	if !isTransientPreNavigation(transient) {
		t.Fatal("pre-navigation closed connection should be retried")
	}
	if isTransientPreNavigation(errors.New("use of closed network connection")) {
		t.Fatal("post-navigation closed connection must not be retried")
	}
	if isTransientPreNavigation(fmt.Errorf(
		"%w: invalid user agent",
		errPreNavigation,
	)) {
		t.Fatal("non-transient pre-navigation failure must not be retried")
	}
}

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
	var fetchMethod atomic.Value
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
fetch(%q, {method: "POST", body: "page-native-request"});
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
	mux.HandleFunc("/fetch", func(w http.ResponseWriter, request *http.Request) {
		fetchMethod.Store(request.Method)
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
		Path:      bin,
		Headless:  true,
		NoSandbox: true,
		Idle:      50 * time.Millisecond,
		Wait:      200 * time.Millisecond,
		Timeout:   10 * time.Second,
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
	if got, _ := fetchMethod.Load().(string); got != http.MethodPost {
		t.Fatalf("page-native fetch method = %q, want POST", got)
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

// A polling SPA keeps the network busy forever, so WaitRequestIdle alone
// would block until Timeout; IdleMax must abandon the wait and still let
// the injected collector deliver its snapshot.
func TestCollectorAbandonsIdleWaitOnPollingApp(t *testing.T) {
	bin, found := launcher.LookPath()
	if !found {
		t.Skip("local Chromium-compatible browser is not installed")
	}

	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!doctype html><html><body><div id="app"></div><script>
const el = document.getElementById("app");
const router = { getRoutes: () => [{ path: "/polled/dashboard", name: "dash" }] };
Object.defineProperty(el, "__vue_app__", {
  value: { _context: { config: { globalProperties: { $router: router } } } },
});
fetch("/api/poll-items");
setInterval(() => fetch("/heartbeat?t=" + Date.now()), 500);
</script></body></html>`)
	})

	collector, err := New(model.BrowserConfig{
		Path: bin, Headless: true, NoSandbox: true,
		Idle:    800 * time.Millisecond,
		IdleMax: 2 * time.Second,
		Wait:    300 * time.Millisecond,
		Timeout: 15 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	started := time.Now()
	result, err := collector.Collect(context.Background(), target, http.Header{})
	elapsed := time.Since(started)
	if err != nil {
		t.Fatalf("Collect() after %v error = %v", elapsed, err)
	}
	if elapsed >= 10*time.Second {
		t.Fatalf("Collect() blocked %v instead of abandoning the idle wait", elapsed)
	}
	foundRoute := slices.ContainsFunc(result.Routes, func(
		route collect.BrowserRoute,
	) bool {
		return strings.Contains(route.Path, "dashboard")
	})
	if !foundRoute {
		t.Errorf("routes missing /polled/dashboard: %#v", result.Routes)
	}
	foundAPI := slices.ContainsFunc(result.URLs, func(raw string) bool {
		return strings.Contains(raw, "/api/poll-items")
	})
	if !foundAPI {
		t.Errorf("URLs missing /api/poll-items: %#v", result.URLs)
	}
}

// Regular site navigation anchors must not be reported as framework routes;
// only SPA hash anchors (a[href^="#/"]) are treated as routes.
func TestCollectorExcludesPlainAnchorsFromRoutes(t *testing.T) {
	bin, found := launcher.LookPath()
	if !found {
		t.Skip("local Chromium-compatible browser is not installed")
	}

	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!doctype html><html><body><div id="app"></div>
<a href="/login?redirect_to_url=/">登录</a>
<a href="https://other.example.com/">外部</a>
<a href="#/admin/users">hash 路由</a>
</body></html>`)
	})

	collector, err := New(model.BrowserConfig{
		Path: bin, Headless: true, NoSandbox: true,
		Idle: 50 * time.Millisecond, Wait: 200 * time.Millisecond,
		Timeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	result, err := collector.Collect(context.Background(), target, http.Header{})
	if err != nil {
		t.Fatal(err)
	}

	hasHashRoute := slices.ContainsFunc(result.Routes, func(route collect.BrowserRoute) bool {
		return route.Path == "/#/admin/users"
	})
	if !hasHashRoute {
		t.Errorf("hash anchor route missing its fragment: %#v", result.Routes)
	}
	for _, route := range result.Routes {
		if strings.Contains(route.Path, "login") {
			t.Errorf("plain navigation anchor leaked as route: %#v", route)
		}
		if strings.Contains(route.Path, "other.example.com") {
			t.Errorf("external anchor leaked as route: %#v", route)
		}
	}
}

func TestFillValueRules(t *testing.T) {
	cases := []struct {
		info controlInfo
		want string
	}{
		{controlInfo{Type: "email", Name: "mail"}, "jsowl@example.org"},
		{controlInfo{Type: "password"}, "JsOwlP@ssw0rd1"},
		{controlInfo{Type: "tel"}, "13800138000"},
		{controlInfo{Type: "text", Name: "phone"}, "13800138000"},
		{controlInfo{Type: "text", Name: "captcha"}, "123456"},
		{controlInfo{Type: "number"}, "1"},
		{controlInfo{Type: "text", Placeholder: "请输入"}, "请输入"},
		{controlInfo{Type: "text", Value: "keep", Name: "user"}, ""},
		{controlInfo{Type: "text", Name: "unknown"}, "jsowl"},
	}
	for _, want := range cases {
		if got := fillValue(want.info); got != want.want {
			t.Fatalf("fillValue(%+v) = %q, want %q", want.info, got, want.want)
		}
	}
}
