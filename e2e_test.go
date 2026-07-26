package jsowl

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
)

func TestEndToEndLibraryAndCLIWorkflow(t *testing.T) {
	server := newFixtureServer(t)
	defer server.Close()

	config := DefaultConfig()
	config.Mode = ModeDirect
	config.Limits.MaxResources = 20
	config.Output.Directory = t.TempDir()
	scanner, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	result, err := scanner.Scan(context.Background(), Target{URL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if result.Statistics.Chunks != 1 {
		t.Fatalf("chunks = %d, want 1", result.Statistics.Chunks)
	}
	if !containsEndpoint(result, "/api/users", http.StatusOK) {
		t.Fatalf("/api/users missing: %#v", result.Endpoints)
	}
	if !containsFinding(result, "secret.jwt") {
		t.Fatalf("JWT finding missing: %#v", result.Findings)
	}
	if !slices.IsSortedFunc(result.Resources, func(a, b Resource) int {
		if a.URL < b.URL {
			return -1
		}
		if a.URL > b.URL {
			return 1
		}
		return 0
	}) {
		t.Fatalf("resources are not stably sorted: %#v", result.Resources)
	}

	if testing.Short() {
		t.Skip("skipping CLI build in short mode")
	}
	output := t.TempDir()
	binary := filepath.Join(t.TempDir(), "jsowl")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	build := exec.Command("go", "build", "-o", binary, "./cmd/jsowl")
	build.Dir = "."
	if data, buildErr := build.CombinedOutput(); buildErr != nil {
		t.Fatalf("build CLI: %v\n%s", buildErr, data)
	}
	command := exec.Command(
		binary,
		"-u", server.URL,
		"-m", "direct",
		"-o", output,
	)
	if data, runErr := command.CombinedOutput(); runErr != nil {
		t.Fatalf("run CLI: %v\n%s", runErr, data)
	}
	jsonReports, err := filepath.Glob(filepath.Join(output, "*", "report.json"))
	if err != nil || len(jsonReports) != 1 {
		t.Fatalf("JSON reports = %#v, error = %v", jsonReports, err)
	}
	htmlReports, err := filepath.Glob(filepath.Join(output, "*", "report.html"))
	if err != nil || len(htmlReports) != 1 {
		t.Fatalf("HTML reports = %#v, error = %v", htmlReports, err)
	}
	data, err := os.ReadFile(jsonReports[0])
	if err != nil {
		t.Fatal(err)
	}
	var cliResult Result
	if err := json.Unmarshal(data, &cliResult); err != nil {
		t.Fatal(err)
	}
	if !containsFinding(&cliResult, "secret.jwt") {
		t.Fatalf("CLI JSON finding missing: %#v", cliResult.Findings)
	}
}

func newFixtureServer(t *testing.T) *httptest.Server {
	t.Helper()
	readFixture := func(name string) []byte {
		t.Helper()
		data, err := os.ReadFile(filepath.Join("testdata", "site", name))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	index := readFixture("index.html")
	runtimeJS := readFixture("runtime.js")
	chunk := readFixture("chunk-users.js")
	return httptest.NewServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		switch request.URL.Path {
		case "/":
			writer.Header().Set("Content-Type", "text/html")
			_, _ = writer.Write(index)
		case "/runtime.js":
			writer.Header().Set("Content-Type", "application/javascript")
			_, _ = writer.Write(runtimeJS)
		case "/static/users.hash.js":
			writer.Header().Set("Content-Type", "application/javascript")
			_, _ = writer.Write(chunk)
		case "/api/users":
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(`{"next":"/api/roles"}`))
		case "/api/roles":
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(`{"role":"admin"}`))
		default:
			http.NotFound(writer, request)
		}
	}))
}
