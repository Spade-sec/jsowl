package jsowl

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/youmulijiang/jsowl/internal/model"
)

func inlineSourceMap(t *testing.T, mapBody string) string {
	t.Helper()
	return "//# sourceMappingURL=data:application/json;base64," +
		base64.StdEncoding.EncodeToString([]byte(mapBody))
}

func writeLocalSourceMap(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestAnalyzeLocationRecoversInlineSourceMap(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "app.js")
	mapBody := `{"version":3,"sources":["src/secret.js"],` +
		`"sourcesContent":["fetch(\"/from-inline\");"]}`
	writeLocalScript(t, file, "fetch(\"/bundle\");\n"+inlineSourceMap(t, mapBody))

	config := DefaultConfig()
	config.Output.Directory = t.TempDir()
	result, err := AnalyzeLocation(context.Background(), config, file)
	if err != nil {
		t.Fatal(err)
	}
	mapped := findLocalEndpoint(result, "/from-inline")
	if mapped == nil {
		t.Fatalf("recovered endpoint missing: %#v (issues %#v)", result.Endpoints, result.Issues)
	}
	if !strings.Contains(mapped.SourceURL, "secret.js") {
		t.Fatalf("recovered source = %q", mapped.SourceURL)
	}
	if findLocalEndpoint(result, "/bundle") == nil {
		t.Fatal("bundle endpoint was lost")
	}
}

func TestAnalyzeLocationRecoversLocalSourceMapFile(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "app.js")
	writeLocalScript(t, file, `fetch("/bundle");`+"\n//# sourceMappingURL=app.js.map")
	writeLocalSourceMap(t, filepath.Join(root, "app.js.map"),
		`{"version":3,"sources":["../src/secret.js"],`+
			`"sourcesContent":["fetch(\"/from-map\");"]}`)

	config := DefaultConfig()
	config.Output.Directory = t.TempDir()
	result, err := AnalyzeLocation(context.Background(), config, file)
	if err != nil {
		t.Fatal(err)
	}
	if findLocalEndpoint(result, "/from-map") == nil {
		t.Fatalf("map source endpoint missing: %#v", result.Endpoints)
	}
	if len(result.Resources) != 1 ||
		result.Resources[0].Type != model.ResourceTypeScript {
		t.Fatalf("resources = %#v", result.Resources)
	}
}

func TestAnalyzeLocationSkipsSourceMapWhenDisabledOrBlacklisted(t *testing.T) {
	for _, testCase := range []struct {
		name      string
		configure func(*Config)
	}{
		{"disabled", func(config *Config) { config.Scope.ProbeSourceMaps = false }},
		{"blacklisted", func(config *Config) {
			config.Scope.SourceMapBlacklist = []string{"app.js.map"}
		}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			root := t.TempDir()
			file := filepath.Join(root, "app.js")
			writeLocalScript(t, file,
				`fetch("/bundle"); `+"\n//# sourceMappingURL=app.js.map")
			writeLocalSourceMap(t, filepath.Join(root, "app.js.map"),
				`{"version":3,"sources":["s.js"],`+
					`"sourcesContent":["fetch(\"/from-map\");"]}`)
			config := DefaultConfig()
			config.Output.Directory = t.TempDir()
			testCase.configure(&config)
			result, err := AnalyzeLocation(context.Background(), config, file)
			if err != nil {
				t.Fatal(err)
			}
			if findLocalEndpoint(result, "/from-map") != nil {
				t.Fatalf("map was analyzed: %#v", result.Endpoints)
			}
			if findLocalEndpoint(result, "/bundle") == nil {
				t.Fatal("bundle endpoint was lost")
			}
		})
	}
}

func TestAnalyzeLocationSourceMapDiagnosticsDoNotStopAnalysis(t *testing.T) {
	cases := []struct {
		name      string
		reference string
		mapBody   string
		writeMap  bool
		wantCode  string
	}{
		{"missing", "missing.js.map", "", false, "sourcemap_read_failed"},
		{"corrupt", "bad.js.map", "{not json", true, "sourcemap_parse_failed"},
		{"no-sources-content", "empty.js.map",
			`{"version":3,"sources":["a.js"]}`, true, "sourcemap_sources_missing"},
		{"remote", "//maps.example.invalid/app.map", "", false,
			"sourcemap_remote_skipped"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			root := t.TempDir()
			file := filepath.Join(root, "app.js")
			writeLocalScript(t, file, `fetch("/bundle");`+"\n//# sourceMappingURL="+
				testCase.reference)
			if testCase.writeMap {
				writeLocalSourceMap(t, filepath.Join(root, testCase.reference),
					testCase.mapBody)
			}
			config := DefaultConfig()
			config.Output.Directory = t.TempDir()
			result, err := AnalyzeLocation(context.Background(), config, file)
			if err != nil {
				t.Fatal(err)
			}
			if findLocalEndpoint(result, "/bundle") == nil {
				t.Fatalf("analysis stopped after map problem: %#v", result.Issues)
			}
			if !hasIssueCode(result, testCase.wantCode) {
				t.Fatalf("issues = %#v, want %s", result.Issues, testCase.wantCode)
			}
		})
	}
}

func TestAnalyzeLocationSourceMapReferenceIsAnalyzedOnce(t *testing.T) {
	root := t.TempDir()
	mapBody := `{"version":3,"sources":["shared.js"],` +
		`"sourcesContent":["fetch(\"/shared\");"]}`
	for _, name := range []string{"a.js", "b.js"} {
		writeLocalScript(t, filepath.Join(root, name),
			`fetch("/bundle");`+"\n//# sourceMappingURL=shared.js.map")
	}
	writeLocalSourceMap(t, filepath.Join(root, "shared.js.map"), mapBody)

	config := DefaultConfig()
	config.Output.Directory = t.TempDir()
	result, err := AnalyzeLocation(context.Background(), config, root)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, endpoint := range result.Endpoints {
		if endpoint.Raw == "/shared" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("recovered endpoint count = %d, endpoints = %#v", count, result.Endpoints)
	}
}

func TestAnalyzeLocationTreatsVirtualSourceNamesAsText(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "app.js")
	writeLocalScript(t, file, `fetch("/bundle");`+"\n//# sourceMappingURL=app.js.map")
	writeLocalSourceMap(t, filepath.Join(root, "app.js.map"),
		`{"version":3,"sources":["webpack:///./src/virtual.js"],`+
			`"sourcesContent":["fetch(\"/from-webpack\");"]}`)

	config := DefaultConfig()
	config.Output.Directory = t.TempDir()
	result, err := AnalyzeLocation(context.Background(), config, file)
	if err != nil {
		t.Fatal(err)
	}
	if findLocalEndpoint(result, "/from-webpack") == nil {
		t.Fatalf("virtual source was not analyzed: %#v", result.Endpoints)
	}
	for _, issue := range result.Issues {
		if issue.Code == "sourcemap_read_failed" {
			t.Fatalf("virtual source was treated as a disk path: %#v", issue)
		}
	}
}

func TestAnalyzeLocationExplicitMapIsNotJavaScript(t *testing.T) {
	root := t.TempDir()
	mapPath := filepath.Join(root, "app.js.map")
	writeLocalSourceMap(t, mapPath,
		`{"version":3,"sources":["src/app.js"],`+
			`"sourcesContent":["fetch(\"/from-explicit-map\");"]}`)

	config := DefaultConfig()
	config.Output.Directory = t.TempDir()
	result, err := AnalyzeLocation(context.Background(), config, mapPath)
	if err != nil {
		t.Fatal(err)
	}
	if findLocalEndpoint(result, "/from-explicit-map") == nil {
		t.Fatalf("explicit map was not parsed: %#v", result.Endpoints)
	}
	if len(result.Resources) != 1 ||
		result.Resources[0].Type != model.ResourceTypeSourceMap {
		t.Fatalf("resources = %#v", result.Resources)
	}
}

func TestAnalyzeLocationRecoveredSourceAPIsUseProbeFlow(t *testing.T) {
	recorder := &localRequestRecorder{}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		recorder.add(request)
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	root := t.TempDir()
	file := filepath.Join(root, "app.js")
	sourceContent := `axios.post("/mapped", {username:"u", password:"p"});
const token = "SECRET_ABC123";`
	mapBody := `{"version":3,"sources":["src/secret.js"],"sourcesContent":[` +
		fmt.Sprintf("%q", sourceContent) + `]}`
	writeLocalScript(t, file, "//# sourceMappingURL=app.js.map")
	writeLocalSourceMap(t, filepath.Join(root, "app.js.map"), mapBody)

	config := DefaultConfig()
	config.Output.Directory = t.TempDir()
	config.Rules.Custom = []model.Rule{{
		ID: "test.secret", Name: "测试密钥",
		Category: model.RuleCategorySensitive, Severity: model.SeverityHigh,
		Pattern: `SECRET_[A-Z0-9]+`, Enabled: true,
	}}
	result, err := AnalyzeLocationWithBase(
		context.Background(), config, file, server.URL+"/api",
	)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := findEndpointByURL(result, server.URL+"/api/mapped")
	if endpoint == nil {
		t.Fatalf("recovered API missing: %#v", result.Endpoints)
	}
	if !endpoint.Authorized || endpoint.StatusCode != http.StatusOK {
		t.Fatalf("recovered API did not use the probe flow: %#v", endpoint)
	}
	if !containsString(endpoint.BodyParams, "username") ||
		!containsString(endpoint.BodyParams, "password") {
		t.Fatalf("body params = %#v", endpoint.BodyParams)
	}
	foundSecret := false
	for _, finding := range result.Findings {
		if finding.Value == "SECRET_ABC123" &&
			finding.Category == model.RuleCategorySensitive {
			foundSecret = true
		}
	}
	if !foundSecret {
		t.Fatalf("recovered sensitive finding missing: %#v", result.Findings)
	}
	paths, _ := recorder.snapshot()
	// The endpoint is a POST + JSON call site: the regular GET probe runs
	// first, then the empty-JSON POST probe.
	methodCounts := map[string]int{}
	for _, method := range recorder.methodsSnapshot() {
		methodCounts[method]++
	}
	if len(paths) != 2 || paths[0] != "/api/mapped" || paths[1] != "/api/mapped" ||
		methodCounts[http.MethodGet] != 1 || methodCounts[http.MethodPost] != 1 {
		t.Fatalf("requested paths = %v methods = %v", paths, methodCounts)
	}
}
