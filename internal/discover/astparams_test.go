package discover

import (
	"net/url"
	"testing"

	"github.com/youmulijiang/jsowl/internal/model"
)

func paramHits(t *testing.T, code string) []model.ParamHit {
	t.Helper()
	source, err := url.Parse("https://example.test/app.js")
	if err != nil {
		t.Fatal(err)
	}
	return ParamsFromAST(source, []byte(code))
}

func findHits(hits []model.ParamHit, name, scenario string) *model.ParamHit {
	for i := range hits {
		if hits[i].Name == name && hits[i].Scenario == scenario {
			return &hits[i]
		}
	}
	return nil
}

// TestParamsFromASTScenarios covers the extraction scenarios from the
// capability matrix: object properties, destructuring, nested destructuring,
// function parameters, literal variables and config objects.
func TestParamsFromASTScenarios(t *testing.T) {
	hits := paramHits(t, `
		const user = { userId: 123 };
		const {id, name} = user;
		const {profile: {email}} = data;
		function getUser(userId, token) { return null; }
		const apiKey = "xxx";
		const app = { config: { timeout: 5000 } };
		const {page = 1} = query;
		send({ config: { retries: 3 } });
	`)

	// 对象属性: const user = { userId: 123 }
	hit := findHits(hits, "userId", model.ParamScenarioObjectProperty)
	if hit == nil {
		t.Fatalf("object property userId missing from %+v", hits)
	}
	if hit.Value != "123" || hit.Evidence != model.EvidenceLiteral {
		t.Fatalf("userId hit = %+v", hit)
	}
	if hit.Line == 0 || hit.SourceURL != "https://example.test/app.js" {
		t.Fatalf("userId hit location = %+v", hit)
	}
	if len(hit.ContextLines) == 0 {
		t.Fatal("userId hit carries no context lines")
	}

	// 解构赋值: const {id, name} = user
	for _, name := range []string{"id", "name"} {
		if findHits(hits, name, model.ParamScenarioDestructuring) == nil {
			t.Fatalf("destructuring %s missing from %+v", name, hits)
		}
	}

	// 嵌套解构: const {profile: {email}} = data → profile, email
	for _, name := range []string{"profile", "email"} {
		if findHits(hits, name, model.ParamScenarioNestedDestructurin) == nil {
			t.Fatalf("nested destructuring %s missing from %+v", name, hits)
		}
	}

	// 函数参数: function getUser(userId, token)
	for _, name := range []string{"userId", "token"} {
		if findHits(hits, name, model.ParamScenarioFunctionParam) == nil {
			t.Fatalf("function param %s missing from %+v", name, hits)
		}
	}

	// 变量赋值: const apiKey = "xxx"
	hit = findHits(hits, "apiKey", model.ParamScenarioVariable)
	if hit == nil {
		t.Fatalf("variable apiKey missing from %+v", hits)
	}
	if hit.Value != "xxx" {
		t.Fatalf("apiKey value = %q", hit.Value)
	}

	// 配置对象: config: { timeout: 5000 }
	hit = findHits(hits, "timeout", model.ParamScenarioConfigObject)
	if hit == nil {
		t.Fatalf("config timeout missing from %+v", hits)
	}
	if hit.Value != "5000" {
		t.Fatalf("timeout value = %q", hit.Value)
	}

	// 配置对象(内联对象参数): send({ config: { retries: 3 } })
	if findHits(hits, "retries", model.ParamScenarioConfigObject) == nil {
		t.Fatalf("inline config retries missing from %+v", hits)
	}

	// 解构默认值: const {page = 1} = query
	hit = findHits(hits, "page", model.ParamScenarioDestructuring)
	if hit == nil || hit.Value != "1" {
		t.Fatalf("destructuring default page = %+v", hit)
	}
}

func TestParamsFromASTFiltersNoise(t *testing.T) {
	hits := paramHits(t, `
		const t = { a: 1, b2: 2 };
		function x(page) { return page; }
		const anon = (userId) => userId;
		const config = { new: 1, prototype: 2, retry: 3 };
		const named = function(token) { return token; };
	`)

	// Single-letter names are minifier artifacts.
	if findHits(hits, "a", model.ParamScenarioObjectProperty) != nil ||
		findHits(hits, "page", model.ParamScenarioFunctionParam) != nil {
		t.Fatalf("single-letter names leaked: %+v", hits)
	}
	// A single-letter variable cannot gate its object either.
	if findHits(hits, "b2", model.ParamScenarioObjectProperty) == nil {
		t.Fatalf("b2 should still be recorded via the object walk: %+v", hits)
	}
	// Reserved words never become parameters (here: top-level keys).
	if findHits(hits, "new", model.ParamScenarioObjectProperty) != nil ||
		findHits(hits, "prototype", model.ParamScenarioObjectProperty) != nil {
		t.Fatalf("reserved words leaked: %+v", hits)
	}
	if findHits(hits, "retry", model.ParamScenarioObjectProperty) == nil {
		t.Fatalf("top-level retry missing: %+v", hits)
	}
	// Arrow functions bound to a named variable contribute their signature.
	if findHits(hits, "userId", model.ParamScenarioFunctionParam) == nil {
		t.Fatalf("arrow param userId missing: %+v", hits)
	}
	if findHits(hits, "token", model.ParamScenarioFunctionParam) == nil {
		t.Fatalf("named function expression param token missing: %+v", hits)
	}
}

func TestParamsFromASTDeduplicatesPerLine(t *testing.T) {
	hits := paramHits(t, `
		const user = { userId: 123 };
		const other = { userId: 5 };
	`)
	count := 0
	for _, hit := range hits {
		if hit.Name == "userId" && hit.Scenario == model.ParamScenarioObjectProperty {
			count++
		}
	}
	if count != 2 {
		t.Fatalf("distinct lines should each produce one hit, got %d in %+v", count, hits)
	}
}
