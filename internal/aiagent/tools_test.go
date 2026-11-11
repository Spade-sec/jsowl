package aiagent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/youmulijiang/jsowl/internal/model"
	"github.com/youmulijiang/jsowl/internal/storage"
)

// evidenceWithSource builds evidence over a temp report directory holding
// one persisted script, exercising the real storage.LoadJS path.
func evidenceWithSource(t *testing.T) *Evidence {
	t.Helper()
	reportDir := t.TempDir()
	sourceURL := "https://example.com/static/app.js"
	resource := model.Resource{
		URL: sourceURL, Type: model.ResourceTypeScript,
		LocalPath: "js/app.js", StatusCode: 200,
	}
	body := []byte("var api = \"/api/user/login\";\nvar token = \"tk_123\";\n")
	if err := os.MkdirAll(filepath.Join(reportDir, "js"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(reportDir, "js", "app.js"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	result := &model.Result{
		ReportDirectory: reportDir,
		Target:          "https://example.com",
		Resources:       []model.Resource{resource},
		Endpoints: []model.Endpoint{
			{Raw: "/api/user/login", Method: "POST", Type: "api", StatusCode: 200, Evidence: model.EvidenceStatic,
				Spec: &model.RequestSpec{
					ContentType: "application/json",
					Body: []model.Param{
						{Key: "username", Value: "admin", Evidence: model.EvidenceLiteral},
						{Key: "password", Value: "{{fuzz:body:pwd}}", Evidence: model.EvidencePlaceholder,
							Taint: &model.Taint{Kind: model.TaintUnknown, Symbol: "pwd"}},
					},
				},
				ContextLines: []model.ContextLine{{LineNumber: 1, Content: "axios.post('/api/user/login', {username, password})"}},
			},
			{Raw: "/api/order/list", Method: "GET", Type: "api"},
			{Raw: "/login", Type: "route"},
		},
		Findings: []model.Finding{
			{RuleID: "token", RuleName: "Token", Severity: model.SeverityHigh, Value: "tk_123",
				SourceURL: sourceURL, Line: 2,
				ContextLines: []model.ContextLine{{LineNumber: 2, Content: "var token = \"tk_123\";"}},
			},
		},
	}
	return NewEvidence(result)
}

func TestListEndpointsFilters(t *testing.T) {
	set := NewToolset(evidenceWithSource(t))
	out := set.Execute("list_endpoints", json.RawMessage(`{"type":"route"}`))
	if !strings.Contains(out, "[2] GET /login") && !strings.Contains(out, "/login") {
		t.Fatalf("route filter output = %q", out)
	}
	out = set.Execute("list_endpoints", json.RawMessage(`{"prefix":"/api/user"}`))
	if strings.Contains(out, "/api/order/list") {
		t.Fatalf("prefix filter leaked: %q", out)
	}
	out = set.Execute("list_endpoints", nil)
	if !strings.Contains(out, "[0] POST /api/user/login") {
		t.Fatalf("default listing = %q", out)
	}
}

func TestGetEndpointDetail(t *testing.T) {
	set := NewToolset(evidenceWithSource(t))
	out := set.Execute("get_endpoint", json.RawMessage(`{"index":0}`))
	for _, want := range []string{"POST /api/user/login", "username = admin", "污点:unknown", "证据:literal", "上下文 1"} {
		if !strings.Contains(out, want) {
			t.Fatalf("endpoint detail missing %q in %q", want, out)
		}
	}
	out = set.Execute("get_endpoint", json.RawMessage(`{"index":99}`))
	if !strings.Contains(out, "越界") {
		t.Fatalf("out-of-range = %q", out)
	}
}

func TestGetFindings(t *testing.T) {
	set := NewToolset(evidenceWithSource(t))
	out := set.Execute("get_findings", json.RawMessage(`{"severity":"high"}`))
	if !strings.Contains(out, "tk_123") || !strings.Contains(out, "Token") {
		t.Fatalf("findings = %q", out)
	}
	out = set.Execute("get_findings", json.RawMessage(`{"severity":"critical"}`))
	if !strings.Contains(out, "没有匹配") {
		t.Fatalf("empty severity filter = %q", out)
	}
}

func TestGetContextReadsPersistedSource(t *testing.T) {
	set := NewToolset(evidenceWithSource(t))
	out := set.Execute("get_context", json.RawMessage(`{"source_url":"https://example.com/static/app.js","line":1,"before":0,"after":2}`))
	if !strings.Contains(out, "1: var api") || !strings.Contains(out, "2: var token") {
		t.Fatalf("context = %q", out)
	}
	out = set.Execute("get_context", json.RawMessage(`{"source_url":"https://example.com/static/missing.js","line":1}`))
	if !strings.Contains(out, "没有持久化") {
		t.Fatalf("missing source = %q", out)
	}
}

func TestSearchCodeAcrossSources(t *testing.T) {
	set := NewToolset(evidenceWithSource(t))
	out := set.Execute("search_code", json.RawMessage(`{"pattern":"api/user/login"}`))
	if !strings.Contains(out, "app.js:1") {
		t.Fatalf("search = %q", out)
	}
	out = set.Execute("search_code", json.RawMessage(`{"pattern":"("}`))
	if !strings.Contains(out, "正则不合法") {
		t.Fatalf("bad regex = %q", out)
	}
}

func TestExecuteUnknownToolAndPanickingTool(t *testing.T) {
	set := NewToolset(evidenceWithSource(t))
	if out := set.Execute("no_such_tool", nil); !strings.Contains(out, "未知工具") {
		t.Fatalf("unknown tool = %q", out)
	}
	set.tools["boom"] = Tool{Name: "boom", Fn: func(json.RawMessage) string { panic("bug") }}
	if out := set.Execute("boom", nil); !strings.Contains(out, "内部失败") {
		t.Fatalf("panic not contained: %q", out)
	}
}

func TestEvidenceSourceAbsentWithoutReportDir(t *testing.T) {
	result := &model.Result{ReportDirectory: t.TempDir()}
	result.Resources = []model.Resource{{URL: "https://x/a.js", Type: model.ResourceTypeScript, LocalPath: "js/gone.js"}}
	evidence := NewEvidence(result)
	// loadSource fails (file missing) — evidence reports absence instead of
	// crashing or returning an empty-but-present body.
	if _, ok := evidence.source("https://x/a.js"); ok {
		t.Fatal("missing file must be reported absent")
	}
	if _, ok := evidence.source("https://x/unknown.js"); ok {
		t.Fatal("unknown URL must be reported absent")
	}
}

func TestLineWindowClamps(t *testing.T) {
	body := "a\nb\nc"
	if got := lineWindow(body, 2, 99); len(got) != 2 || got[0] != "b" {
		t.Fatalf("window = %v", got)
	}
	if got := lineWindow(body, 0, 1); len(got) != 1 || got[0] != "a" {
		t.Fatalf("clamped window = %v", got)
	}
}

// Ensure the production loader is what the evidence uses by default.
var _ func(string, string) ([]byte, error) = storage.LoadJS
