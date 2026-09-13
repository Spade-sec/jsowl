package pipeline

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/youmulijiang/jsowl/internal/analyze"
	"github.com/youmulijiang/jsowl/internal/collect/direct"
	"github.com/youmulijiang/jsowl/internal/model"
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
	var probedPaths []string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		probedPaths = append(probedPaths, request.URL.Path)
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
