package jsowl

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/youmulijiang/jsowl/internal/model"
)

func writeLocalScript(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func findLocalEndpoint(result *Result, raw string) *Endpoint {
	for index := range result.Endpoints {
		if result.Endpoints[index].Raw == raw {
			return &result.Endpoints[index]
		}
	}
	return nil
}

func TestAnalyzeLocationFileExtractsEndpointsAndSensitiveRules(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "app.js")
	writeLocalScript(t, file, `
const api = axios.create({ baseURL: "/api" });
fetch("/users");
const route = { path: "/dashboard" };
const token = "SECRET_ABC123";
`)
	config := DefaultConfig()
	config.Output.Directory = t.TempDir()
	config.Rules.Custom = []model.Rule{{
		ID: "test.secret", Name: "测试密钥",
		Category: model.RuleCategorySensitive, Severity: model.SeverityHigh,
		Pattern: `SECRET_[A-Z0-9]+`, Enabled: true,
	}}

	result, err := AnalyzeLocation(context.Background(), config, file)
	if err != nil {
		t.Fatal(err)
	}
	if result.Mode != ModeLocal {
		t.Fatalf("mode = %q", result.Mode)
	}
	if result.ReportDirectory == "" ||
		filepath.Dir(result.ReportDirectory) != filepath.Clean(config.Output.Directory) {
		t.Fatalf("report directory = %q", result.ReportDirectory)
	}
	if len(result.Resources) != 1 ||
		!strings.HasPrefix(result.Resources[0].URL, "file://") {
		t.Fatalf("resources = %#v", result.Resources)
	}
	literal := findLocalEndpoint(result, "/users")
	if literal == nil {
		t.Fatalf("literal endpoint missing: %#v", result.Endpoints)
	}
	if literal.Source == "prefix" || literal.Authorized {
		t.Fatalf("literal endpoint = %#v", literal)
	}
	if literal.Template == nil {
		t.Fatal("request template was not built")
	}
	joined := findLocalEndpoint(result, "/api/users")
	if joined == nil || joined.Source != "prefix" {
		t.Fatalf("prefix endpoint missing: %#v", result.Endpoints)
	}
	if findLocalEndpoint(result, "/dashboard") == nil {
		t.Fatalf("path reference missing: %#v", result.Endpoints)
	}
	for _, endpoint := range result.Endpoints {
		if endpoint.Authorized {
			t.Fatalf("relative endpoint %q without a host was marked authorized", endpoint.Raw)
		}
	}
	found := false
	for _, finding := range result.Findings {
		if finding.Value == "SECRET_ABC123" &&
			finding.Category == model.RuleCategorySensitive {
			found = true
		}
	}
	if !found {
		t.Fatalf("sensitive finding missing: %#v", result.Findings)
	}
	if result.FinishedAt.IsZero() {
		t.Fatal("finished time was not set")
	}
}

func TestAnalyzeLocationDirectoryWalksJavaScriptFiles(t *testing.T) {
	root := t.TempDir()
	writeLocalScript(t, filepath.Join(root, "a.js"), `fetch("/a");`)
	writeLocalScript(t, filepath.Join(root, "nested", "b.ts"), `axios.get("/b");`)
	writeLocalScript(t, filepath.Join(root, "nested", "c.jsx"), `fetch("/c");`)
	writeLocalScript(t, filepath.Join(root, "notes.txt"), `fetch("/ignored");`)

	config := DefaultConfig()
	config.Output.Directory = t.TempDir()
	result, err := AnalyzeLocation(context.Background(), config, root)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Resources) != 3 {
		t.Fatalf("resources = %d, want 3", len(result.Resources))
	}
	for _, raw := range []string{"/a", "/b", "/c"} {
		if findLocalEndpoint(result, raw) == nil {
			t.Errorf("endpoint %q missing: %#v", raw, result.Endpoints)
		}
	}
	if findLocalEndpoint(result, "/ignored") != nil {
		t.Fatal("non-JavaScript file was analyzed")
	}
}

func TestAnalyzeLocationRejectsEmptyDirectory(t *testing.T) {
	root := t.TempDir()
	writeLocalScript(t, filepath.Join(root, "notes.txt"), "not javascript")
	config := DefaultConfig()
	config.Output.Directory = t.TempDir()
	if _, err := AnalyzeLocation(context.Background(), config, root); err == nil {
		t.Fatal("expected an error for a directory without JavaScript")
	}
}

func TestAnalyzeLocationReportsWriteForLocalMode(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "app.js")
	writeLocalScript(t, file, `
const api = axios.create({ baseURL: "/api" });
fetch("/users").then((response) => response.json());
`)
	config := DefaultConfig()
	config.Output.Directory = t.TempDir()
	result, err := AnalyzeLocation(context.Background(), config, file)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteJSONReport(
		filepath.Join(result.ReportDirectory, "report.json"), result,
	); err != nil {
		t.Fatal(err)
	}
	if err := WriteHTMLReport(
		filepath.Join(result.ReportDirectory, "report.html"), result,
	); err != nil {
		t.Fatal(err)
	}
	if err := WriteTextReports(result.ReportDirectory, result); err != nil {
		t.Fatal(err)
	}
	if err := WriteSplitReports(result.ReportDirectory, result); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"report.json", "report.html", "api绝对路径.txt", "api相对路径.txt",
		"敏感信息.txt", "路由.txt", "API报告.html", "资源报告.html",
	} {
		if _, err := os.Stat(filepath.Join(result.ReportDirectory, name)); err != nil {
			t.Errorf("%s was not written: %v", name, err)
		}
	}
}
