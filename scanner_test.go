package jsowl

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
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
	config.Concurrency.ResourcesPerTarget = 2
	config.Limits.MaxResources = 20
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
	if !containsFinding(result, "secret.jwt") {
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

func containsResource(result *Result, path string, resourceType ResourceType) bool {
	for _, resource := range result.Resources {
		if resource.Type == resourceType && urlPath(resource.URL) == path {
			return true
		}
	}
	return false
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
