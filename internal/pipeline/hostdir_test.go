package pipeline

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/youmulijiang/jsowl/internal/collect"
	"github.com/youmulijiang/jsowl/internal/model"
	"github.com/youmulijiang/jsowl/internal/storage"
)

// TestScriptsAreSavedInsideTheReportDirectory is the regression test for the
// split where a target carrying a path or query got its reports in
// "<host>-<hash>/" while its scripts landed in "<host>/js/": the two must be
// the same folder, and nothing may be written to the sibling.
func TestScriptsAreSavedInsideTheReportDirectory(t *testing.T) {
	getter := &stubGetter{responses: map[string]collect.Response{
		"/app": {URL: "http://stub.test/app", StatusCode: 200,
			Header: http.Header{"Content-Type": []string{"text/html"}},
			Body:   []byte(`<script src="/app/main.js"></script>`)},
		"/app/main.js": {URL: "http://stub.test/app/main.js", StatusCode: 200,
			Header: http.Header{"Content-Type": []string{"application/javascript"}},
			Body:   []byte(deferredScriptBody)},
		"/api/from-deferred": {URL: "http://stub.test/api/from-deferred", StatusCode: 200,
			Header: http.Header{"Content-Type": []string{"application/json"}},
			Body:   []byte(`{"ok":true}`)},
	}}
	config := model.DefaultConfig()
	config.Mode = model.ModeDirect
	runner, outputDirectory := newStubPipeline(t, config, getter)

	target := "http://stub.test/app"
	result, _, err := runner.RunDetailed(context.Background(),
		model.Target{URL: target}, http.Header{}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	reportDirectory, err := storage.TargetDirectory(outputDirectory, target)
	if err != nil {
		t.Fatal(err)
	}
	// A target with a path gets a hashed report directory, which is exactly the
	// case that used to split the report and its scripts.
	if filepath.Base(reportDirectory) == "stub.test" {
		t.Fatalf("report directory %q should carry the target hash", reportDirectory)
	}

	var saved int
	for _, resource := range result.Resources {
		if resource.LocalPath == "" {
			continue
		}
		saved++
		if strings.Contains(resource.LocalPath, "stub.test") {
			t.Fatalf("local path %q still carries the host directory", resource.LocalPath)
		}
		absolute := filepath.Join(reportDirectory, filepath.FromSlash(resource.LocalPath))
		if _, err := os.Stat(absolute); err != nil {
			t.Fatalf("script was not saved into the report directory: %v", err)
		}
		if _, err := storage.LoadJS(reportDirectory, resource.LocalPath); err != nil {
			t.Fatalf("script is not readable from the report directory: %v", err)
		}
	}
	if saved == 0 {
		t.Fatal("no script was persisted")
	}
	// The old layout's sibling folder must not exist anymore.
	if _, err := os.Stat(filepath.Join(outputDirectory, "stub.test")); !os.IsNotExist(err) {
		t.Fatalf("a sibling host directory was created: %v", err)
	}
}

// TestTargetDirectoryNamesEveryTarget pins the naming contract shared by the
// report writers and the scanner.
func TestTargetDirectoryNamesEveryTarget(t *testing.T) {
	root := t.TempDir()
	cases := []struct {
		target   string
		wantBase string
		// wantHash marks targets that must get the stable hash suffix.
		wantHash bool
	}{
		{target: "https://example.test", wantBase: "example.test"},
		{target: "https://example.test/", wantBase: "example.test"},
		{target: "https://example.test:8443", wantBase: "example.test_8443"},
		{target: "https://example.test:8443?q=1", wantBase: "example.test_8443", wantHash: true},
		{target: "https://example.test/app", wantBase: "example.test", wantHash: true},
	}
	for _, testCase := range cases {
		directory, err := storage.TargetDirectory(root, testCase.target)
		if err != nil {
			t.Fatalf("TargetDirectory(%q): %v", testCase.target, err)
		}
		if filepath.Dir(directory) != root {
			t.Errorf("TargetDirectory(%q) left the root: %q", testCase.target, directory)
		}
		base := filepath.Base(directory)
		if !strings.HasPrefix(base, testCase.wantBase) {
			t.Errorf("TargetDirectory(%q) = %q, want base %q",
				testCase.target, base, testCase.wantBase)
		}
		suffix := strings.TrimPrefix(base, testCase.wantBase)
		switch {
		case testCase.wantHash && !looksLikeHashSuffix(suffix):
			t.Errorf("TargetDirectory(%q) = %q, want an 8-hex hash suffix",
				testCase.target, base)
		case !testCase.wantHash && suffix != "":
			t.Errorf("TargetDirectory(%q) = %q, want no hash suffix",
				testCase.target, base)
		}
	}
	// A fragment never splits one target into two directories.
	bare, err := storage.TargetDirectory(root, "https://example.test/app")
	if err != nil {
		t.Fatal(err)
	}
	withFragment, err := storage.TargetDirectory(root, "https://example.test/app#/route")
	if err != nil {
		t.Fatal(err)
	}
	if bare != withFragment {
		t.Fatalf("a fragment changed the directory: %q vs %q", bare, withFragment)
	}
	// A host-less target has no directory at all.
	if _, err := storage.TargetDirectory(root, "not-a-url"); err == nil {
		t.Fatal("TargetDirectory accepted a host-less target")
	}
}

// looksLikeHashSuffix reports whether a directory-name suffix is the 8-hex
// stable hash the derivation appends.
func looksLikeHashSuffix(suffix string) bool {
	if len(suffix) != 9 || !strings.HasPrefix(suffix, "-") {
		return false
	}
	for _, char := range suffix[1:] {
		if !strings.ContainsRune("0123456789abcdef", char) {
			return false
		}
	}
	return true
}

// TestRunDetailedExploresDeclaredBasePaths covers the automatic exploration:
// a prefix the JavaScript declares is joined to every relative reference and
// probed, so the prefix the application really serves is discovered rather
// than assumed.
func TestRunDetailedExploresDeclaredBasePaths(t *testing.T) {
	getter := &stubGetter{responses: map[string]collect.Response{
		"/": {URL: "http://app.test/", StatusCode: 200,
			Header: http.Header{"Content-Type": []string{"text/html"}},
			Body:   []byte(`<script src="/app.js"></script>`)},
		"/app.js": {URL: "http://app.test/app.js", StatusCode: 200,
			Header: http.Header{"Content-Type": []string{"application/javascript"}},
			Body: []byte(`
const api = axios.create({ baseURL: "/api" });
fetch("/users");
`)},
		"/api/users": {URL: "http://app.test/api/users", StatusCode: 200,
			Header: http.Header{"Content-Type": []string{"application/json"}},
			Body:   []byte(`{"ok":true}`)},
	}}
	config := model.DefaultConfig()
	config.Mode = model.ModeDirect
	config.Output.Directory = t.TempDir()
	config.Output.JSON = false
	config.Output.HTML = false
	runner, _ := newStubPipeline(t, config, getter)

	result, _, err := runner.RunDetailed(context.Background(),
		model.Target{URL: "http://app.test/"}, http.Header{}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	byURL := map[string]model.Endpoint{}
	for _, endpoint := range result.Endpoints {
		byURL[endpoint.URL] = endpoint
	}
	joined, ok := byURL["http://app.test/api/users"]
	if !ok {
		t.Fatalf("the declared prefix was not tried: %v", byURL)
	}
	if joined.Source != "prefix" {
		t.Errorf("endpoint extractor = %q, want prefix", joined.Source)
	}
	if joined.StatusCode != 200 {
		t.Errorf("the prefix-derived endpoint was not probed: status %d", joined.StatusCode)
	}
	// The reference as written is still reported, so a reader sees both the
	// literal path and the prefix the application actually serves.
	if _, ok := byURL["http://app.test/users"]; !ok {
		t.Errorf("the literal reference disappeared: %v", byURL)
	}
}

// TestBasePathProbesLiteralReferenceBeforeJoined pins the two-phase order:
// the path as written is requested first, and only after every literal
// endpoint has been probed does the declared prefix get joined and requested.
func TestBasePathProbesLiteralReferenceBeforeJoined(t *testing.T) {
	getter := &stubGetter{responses: map[string]collect.Response{
		"/": {URL: "http://app.test/", StatusCode: 200,
			Header: http.Header{"Content-Type": []string{"text/html"}},
			Body:   []byte(`<script src="/app.js"></script>`)},
		"/app.js": {URL: "http://app.test/app.js", StatusCode: 200,
			Header: http.Header{"Content-Type": []string{"application/javascript"}},
			Body: []byte(`
const api = axios.create({ baseURL: "/api" });
fetch("/users");
`)},
		"/users": {URL: "http://app.test/users", StatusCode: 404,
			Header: http.Header{"Content-Type": []string{"application/json"}},
			Body:   []byte(`{"error":"not found"}`)},
		"/api/users": {URL: "http://app.test/api/users", StatusCode: 200,
			Header: http.Header{"Content-Type": []string{"application/json"}},
			Body:   []byte(`{"ok":true}`)},
	}}
	config := model.DefaultConfig()
	config.Mode = model.ModeDirect
	config.Output.Directory = t.TempDir()
	config.Output.JSON = false
	config.Output.HTML = false
	runner, _ := newStubPipeline(t, config, getter)

	if _, _, err := runner.RunDetailed(context.Background(),
		model.Target{URL: "http://app.test/"}, http.Header{}, nil, nil, nil); err != nil {
		t.Fatal(err)
	}

	getter.mu.Lock()
	defer getter.mu.Unlock()
	literal, joined := -1, -1
	for index, path := range getter.requests {
		switch path {
		case "/users":
			if literal < 0 {
				literal = index
			}
		case "/api/users":
			if joined < 0 {
				joined = index
			}
		}
	}
	if literal < 0 || joined < 0 {
		t.Fatalf("expected both probes, got %v", getter.requests)
	}
	if literal > joined {
		t.Fatalf("prefixed path probed before literal: %v", getter.requests)
	}
}

// TestBasePathSkipsRootedAndNonCallReferences guards the heuristic: a
// reference already written under a declared prefix is not prefixed twice,
// and a path assignment (a router path, config value) is not treated as an
// interface that the base path applies to.
func TestBasePathSkipsRootedAndNonCallReferences(t *testing.T) {
	getter := &stubGetter{responses: map[string]collect.Response{
		"/": {URL: "http://app.test/", StatusCode: 200,
			Header: http.Header{"Content-Type": []string{"text/html"}},
			Body:   []byte(`<script src="/app.js"></script>`)},
		"/app.js": {URL: "http://app.test/app.js", StatusCode: 200,
			Header: http.Header{"Content-Type": []string{"application/javascript"}},
			Body: []byte(`
const api = axios.create({ baseURL: "/api" });
fetch("/api/users");
const route = { path: "/dashboard" };
`)},
		"/api/users": {URL: "http://app.test/api/users", StatusCode: 200,
			Header: http.Header{"Content-Type": []string{"application/json"}},
			Body:   []byte(`{"ok":true}`)},
		"/dashboard": {URL: "http://app.test/dashboard", StatusCode: 200,
			Header: http.Header{"Content-Type": []string{"text/html"}},
			Body:   []byte(`<html></html>`)},
	}}
	config := model.DefaultConfig()
	config.Mode = model.ModeDirect
	config.Output.Directory = t.TempDir()
	config.Output.JSON = false
	config.Output.HTML = false
	runner, _ := newStubPipeline(t, config, getter)

	if _, _, err := runner.RunDetailed(context.Background(),
		model.Target{URL: "http://app.test/"}, http.Header{}, nil, nil, nil); err != nil {
		t.Fatal(err)
	}

	getter.mu.Lock()
	defer getter.mu.Unlock()
	for _, unwanted := range []string{"/api/api/users", "/api/dashboard"} {
		for _, path := range getter.requests {
			if path == unwanted {
				t.Fatalf("unexpected joined probe %s: %v", unwanted, getter.requests)
			}
		}
	}
	var literal, route bool
	for _, path := range getter.requests {
		switch path {
		case "/api/users":
			literal = true
		case "/dashboard":
			route = true
		}
	}
	if !literal || !route {
		t.Fatalf("literal probes missing: %v", getter.requests)
	}
}

// TestAutoBasePathJoiningIsOrderIndependent covers the automatic prefix
// discovery across files: the prefix is declared in a script that is only
// discovered by the script using it, so the reference is recorded before any
// prefix is known. The final join pass must still try it, and it must not
// duplicate the probe when the pass runs again.
func TestAutoBasePathJoiningIsOrderIndependent(t *testing.T) {
	getter := &stubGetter{responses: map[string]collect.Response{
		"/": {URL: "http://app.test/", StatusCode: 200,
			Header: http.Header{"Content-Type": []string{"text/html"}},
			Body:   []byte(`<script src="/app.js"></script>`)},
		"/app.js": {URL: "http://app.test/app.js", StatusCode: 200,
			Header: http.Header{"Content-Type": []string{"application/javascript"}},
			Body:   []byte(`import("/config.js");fetch("/users")`)},
		"/config.js": {URL: "http://app.test/config.js", StatusCode: 200,
			Header: http.Header{"Content-Type": []string{"application/javascript"}},
			Body:   []byte(`axios.create({baseURL:"/api"})`)},
		"/api/users": {URL: "http://app.test/api/users", StatusCode: 200,
			Header: http.Header{"Content-Type": []string{"application/json"}},
			Body:   []byte(`{"ok":true}`)},
	}}
	config := model.DefaultConfig()
	config.Mode = model.ModeDirect
	config.Output.Directory = t.TempDir()
	config.Output.JSON = false
	config.Output.HTML = false
	runner, _ := newStubPipeline(t, config, getter)

	result, _, err := runner.RunDetailed(context.Background(),
		model.Target{URL: "http://app.test/"}, http.Header{}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	var joined int
	byURL := map[string]model.Endpoint{}
	for _, endpoint := range result.Endpoints {
		byURL[endpoint.URL] = endpoint
		if endpoint.URL == "http://app.test/api/users" {
			joined++
		}
	}
	endpoint, ok := byURL["http://app.test/api/users"]
	if !ok {
		t.Fatalf("the declared prefix was not tried: %v", byURL)
	}
	if endpoint.Source != "prefix" || endpoint.StatusCode != 200 {
		t.Fatalf("prefix endpoint = %#v", endpoint)
	}
	if joined != 1 {
		t.Fatalf("prefix endpoint recorded %d times", joined)
	}
	if _, ok := byURL["http://app.test/users"]; !ok {
		t.Fatalf("the literal reference disappeared: %v", byURL)
	}
	getter.mu.Lock()
	defer getter.mu.Unlock()
	probes := 0
	for _, path := range getter.requests {
		if path == "/api/users" {
			probes++
		}
	}
	if probes != 1 {
		t.Fatalf("/api/users probed %d times: %v", probes, getter.requests)
	}
}
