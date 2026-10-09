package jsowl

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/youmulijiang/jsowl/internal/pipeline"
)

// TestEndToEndParameterScenarios scans a fixture page whose script exercises
// every extraction scenario from the capability matrix and verifies the
// parameter inventory and the HTML scenario badges come out the other end.
func TestEndToEndParameterScenarios(t *testing.T) {
	script := `
const user = { userId: 123 };
const {id, name} = user;
const {profile: {email}} = data;
function getUser(userId, token) { return null; }
const apiKey = "xxx";
const app = { config: { timeout: 5000 } };
axios.post("/api/login", { username: "test" });
fetch("/api/items?page=1&size=10");
`
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "text/html")
		_, _ = writer.Write([]byte(
			`<html><head><script src="/app.js"></script></head><body></body></html>`))
	})
	mux.HandleFunc("/app.js", func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/javascript")
		_, _ = writer.Write([]byte(script))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	config := DefaultConfig()
	config.Mode = ModeDirect
	config.Limits.MaxResources = 5
	config.Output.Directory = t.TempDir()
	config.Output.HTML = true
	scanner, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	result, err := scanner.Scan(context.Background(), Target{URL: server.URL})
	if err != nil {
		t.Fatal(err)
	}

	type scenarioHit struct {
		name, scenario string
	}
	want := []scenarioHit{
		{"userId", ParamScenarioObjectProperty},
		{"id", ParamScenarioDestructuring},
		{"email", ParamScenarioNestedDestructurin},
		{"token", ParamScenarioFunctionParam},
		{"apiKey", ParamScenarioVariable},
		{"username", ParamScenarioAPIRequest},
		{"page", ParamScenarioURLQuery},
		{"timeout", ParamScenarioConfigObject},
		{"userId", ParamScenarioRouteParam}, // route placeholder below
	}
	// The route scenario comes from a framework route; inject one the way a
	// static route extraction would.
	result.Endpoints = append(result.Endpoints, Endpoint{
		URL: result.Target + "/#/user/:userId/profile",
		SourceURL: scriptURL(server.URL), Type: "route",
		Evidence: EvidenceStatic, Source: "ast",
	})
	pipeline.Finalize(result)

	seen := func(name, scenario string) bool {
		for _, hit := range result.Params {
			if hit.Name == name && hit.Scenario == scenario {
				return true
			}
		}
		return false
	}
	for _, w := range want[:8] {
		if !seen(w.name, w.scenario) {
			t.Fatalf("scenario %s/%s missing from %+v", w.name, w.scenario, result.Params)
		}
	}
	if !seen("userId", ParamScenarioRouteParam) {
		t.Fatalf("route_param userId missing from %+v", result.Params)
	}

	// Reports carry the scenario badges.
	if err := WriteSplitReports(config.Output.Directory, result); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(config.Output.Directory, "参数报告.html"))
	if err != nil {
		t.Fatal(err)
	}
	html := string(data)
	for _, want := range []string{"对象属性", "解构赋值", "嵌套解构", "函数参数", "变量赋值", "配置对象"} {
		if !strings.Contains(html, want) {
			t.Fatalf("parameter report missing badge %q", want)
		}
	}
}

func scriptURL(serverURL string) string {
	return serverURL + "/app.js"
}
