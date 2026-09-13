package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/youmulijiang/jsowl/internal/model"
)

func TestWriteJSONRoundTripsResult(t *testing.T) {
	result := sampleResult()
	path := filepath.Join(t.TempDir(), "nested", "report.json")
	if err := WriteJSON(path, result); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var decoded model.Result
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Target != result.Target ||
		decoded.Findings[0].Value != result.Findings[0].Value {
		t.Fatalf("decoded result = %#v", decoded)
	}
	result.Target = "https://updated.example.test"
	if err := WriteJSON(path, result); err != nil {
		t.Fatalf("overwrite JSON report: %v", err)
	}
	data, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Target != result.Target {
		t.Fatalf("overwritten target = %q", decoded.Target)
	}
}

func TestWriteHTMLContainsSecurityDataAndEscapesTargetContent(t *testing.T) {
	result := sampleResult()
	result.Target = `https://example.test/?q=<script>alert(1)</script>`
	path := filepath.Join(t.TempDir(), "report.html")
	if err := WriteHTML(path, result); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	html := string(data)
	for _, want := range []string{
		"敏感数据，请妥善保管",
		"super-secret-token",
		"https://example.test/api/users",
		"&lt;script&gt;alert(1)&lt;/script&gt;",
		"target: \"https://example.test/?q=\\u003cscript\\u003ealert(1)\\u003c/script\\u003e\"",
		"ContextLine",
		"match_start",
		"tree-panel",
		"findings-body",
		"pagination",
		"503",
		"chrome missing",
		"id=\"category\"",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("HTML report does not contain %q", want)
		}
	}
	if strings.Contains(html, "<script>alert(1)</script>") {
		t.Fatal("target-controlled HTML was not escaped")
	}
	if strings.Contains(html, `{"entire":"response body"}`) {
		t.Fatal("HTML report unexpectedly contains a stored response body")
	}
}

func sampleResult() *model.Result {
	return &model.Result{
		Target:    "https://example.test",
		Mode:      model.ModeAuto,
		UserAgent: "JsOwl-Test",
		BrowserStatus: model.BrowserStatus{
			Attempted: true, Degraded: true, Reason: "chrome missing",
		},
		Resources: []model.Resource{{
			URL: "https://example.test/app.js", Type: model.ResourceTypeScript,
			StatusCode: 200, ContentType: "application/javascript", Size: 100,
		}},
		Endpoints: []model.Endpoint{{
			Raw: "/api/users", URL: "https://example.test/api/users",
			SourceURL: "https://example.test/app.js", Authorized: true,
			StatusCode: 503,
		}},
		Findings: []model.Finding{{
			RuleID: "secret.credential", RuleName: "Credential",
			Category: model.RuleCategorySensitive, Severity: model.SeverityHigh,
			Value: "super-secret-token", SourceURL: "https://example.test/app.js",
			Line: 4, Column: 15,
			ContextLines: []model.ContextLine{
				{LineNumber: 1, Content: "const ready = true", MatchStart: -1, MatchEnd: -1},
				{LineNumber: 2, Content: "// credentials", MatchStart: -1, MatchEnd: -1},
				{LineNumber: 3, Content: "function boot() {", MatchStart: -1, MatchEnd: -1},
				{LineNumber: 4, Content: "const token = super-secret-token", MatchStart: 14, MatchEnd: 32},
				{LineNumber: 5, Content: "}", MatchStart: -1, MatchEnd: -1},
				{LineNumber: 6, Content: "boot()", MatchStart: -1, MatchEnd: -1},
				{LineNumber: 7, Content: "// end", MatchStart: -1, MatchEnd: -1},
			},
		}},
		Issues: []model.Issue{{
			Code: "fixture", Stage: "test",
			Message: "fixture issue",
		}},
		Statistics: model.Statistics{
			Resources: 1, Scripts: 1, Endpoints: 1, Findings: 1,
		},
	}
}

func TestWriteTextReportsWritesAPIPathsParametersAndSensitive(t *testing.T) {
	result := sampleResult()
	result.Endpoints = append(result.Endpoints, model.Endpoint{
		Raw: "/api/users", URL: "https://example.test/api/users?id=42&tab=profile",
		SourceURL: "https://example.test/app.js", Authorized: true, StatusCode: 200,
	})
	directory := t.TempDir()
	if err := WriteTextReports(directory, result); err != nil {
		t.Fatal(err)
	}

	apiData, err := os.ReadFile(filepath.Join(directory, "api路径.txt"))
	if err != nil {
		t.Fatal(err)
	}
	api := string(apiData)
	if !strings.Contains(api, "https://example.test/api/users\n") ||
		!strings.Contains(api, "https://example.test/api/users?id=42&tab=profile\n") {
		t.Fatalf("api report missing endpoints: %q", api)
	}

	paramData, err := os.ReadFile(filepath.Join(directory, "参数.txt"))
	if err != nil {
		t.Fatal(err)
	}
	params := string(paramData)
	for _, want := range []string{"id=42", "tab=profile"} {
		if !strings.Contains(params, want) {
			t.Fatalf("parameter report missing %q: %q", want, params)
		}
	}

	sensitiveData, err := os.ReadFile(filepath.Join(directory, "敏感信息.txt"))
	if err != nil {
		t.Fatal(err)
	}
	sensitive := string(sensitiveData)
	for _, want := range []string{"[high]", "Credential", "super-secret-token", "app.js:4:15"} {
		if !strings.Contains(sensitive, want) {
			t.Fatalf("sensitive report missing %q: %q", want, sensitive)
		}
	}
}

func TestWriteTextReportsHandlesEmptyResult(t *testing.T) {
	result := &model.Result{Target: "https://empty.test"}
	directory := t.TempDir()
	if err := WriteTextReports(directory, result); err != nil {
		t.Fatal(err)
	}
	sensitive, err := os.ReadFile(filepath.Join(directory, "敏感信息.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(sensitive), "（未发现敏感信息）") {
		t.Fatalf("empty sensitive report = %q", sensitive)
	}
	params, err := os.ReadFile(filepath.Join(directory, "参数.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(params), "（未发现参数）") {
		t.Fatalf("empty parameter report = %q", params)
	}
}

func TestWriteSplitReportsGeneratesTopicPages(t *testing.T) {
	result := sampleResult()
	result.Endpoints = append(result.Endpoints, model.Endpoint{
		Raw: "/api/users?id=1", URL: "https://example.test/api/users?id=1",
		SourceURL: "https://example.test/app.js", Authorized: true,
		Method: "POST", Evidence: model.EvidenceRuntime,
	})
	directory := t.TempDir()
	if err := WriteSplitReports(directory, result); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"报告导航.html", "API报告.html", "敏感信息报告.html", "参数报告.html", "资源报告.html",
	} {
		data, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if !strings.Contains(string(data), "https://example.test") {
			t.Fatalf("%s missing target", name)
		}
	}
	api, _ := os.ReadFile(filepath.Join(directory, "API报告.html"))
	for _, want := range []string{"POST", "runtime", "https://example.test/api/users?id=1"} {
		if !strings.Contains(string(api), want) {
			t.Fatalf("API report missing %q", want)
		}
	}
	nav, _ := os.ReadFile(filepath.Join(directory, "报告导航.html"))
	for _, want := range []string{
		"report.html", "API 端点报告", "敏感信息报告", "请求参数报告",
		"资源报告", "API 路径", "请求参数", "敏感信息",
	} {
		if !strings.Contains(string(nav), want) {
			t.Fatalf("navigation missing %q", want)
		}
	}
}
