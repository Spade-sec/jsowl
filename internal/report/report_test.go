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
		"完整敏感信息",
		"super-secret-token",
		"https://example.test/api/users",
		"503",
		"chrome missing",
		"&lt;script&gt;alert(1)&lt;/script&gt;",
		`id="category"`,
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
			Line: 1, Column: 2,
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
