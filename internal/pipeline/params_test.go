package pipeline

import (
	"testing"

	"github.com/youmulijiang/jsowl/internal/model"
)

// TestDeriveParamHitsScenarios checks the endpoint-side scenarios: API request
// bodies, URL query strings, URL path segments, and framework route
// placeholders.
func TestDeriveParamHitsScenarios(t *testing.T) {
	result := &model.Result{
		Endpoints: []model.Endpoint{
			{
				URL:       "https://api.example.test/users/list?page=1&size=10",
				SourceURL: "https://example.test/app.js",
				Type:      "api", Evidence: model.EvidenceStatic,
				Spec: &model.RequestSpec{
					Body: []model.Param{{Key: "name", Value: "test", Evidence: model.EvidenceLiteral}},
				},
			},
			{
				URL:       "https://example.test/#/user/:userId/profile",
				SourceURL: "https://example.test/router.js",
				Type:      "route",
			},
		},
		Resources: []model.Resource{
			{URL: "https://cdn.example.test/app.js?ver=123"},
		},
	}
	hits := deriveParamHits(result)
	find := func(name, scenario string) *model.ParamHit {
		for i := range hits {
			if hits[i].Name == name && hits[i].Scenario == scenario {
				return &hits[i]
			}
		}
		return nil
	}

	// API请求: body 参数
	if hit := find("name", model.ParamScenarioAPIRequest); hit == nil {
		t.Fatalf("api_request name missing from %+v", hits)
	}
	// URL参数: 端点与资源的查询串
	if hit := find("page", model.ParamScenarioURLQuery); hit == nil {
		t.Fatalf("url_query page missing from %+v", hits)
	}
	if hit := find("ver", model.ParamScenarioURLQuery); hit == nil {
		t.Fatalf("url_query ver missing from %+v", hits)
	}
	// 路径段: /users/list 的字面段,资源 URL 的文件名不算
	if hit := find("users", model.ParamScenarioURLPath); hit == nil {
		t.Fatalf("url_path users missing from %+v", hits)
	}
	if hit := find("list", model.ParamScenarioURLPath); hit == nil {
		t.Fatalf("url_path list missing from %+v", hits)
	}
	if hit := find("app.js", model.ParamScenarioURLPath); hit != nil {
		t.Fatalf("resource file names must not become url_path hits: %+v", hits)
	}
	// 路径段: 哈希路由的字面段;占位符 :userId 只归 route_param
	for _, segment := range []string{"user", "profile"} {
		if hit := find(segment, model.ParamScenarioURLPath); hit == nil {
			t.Fatalf("url_path %s missing from %+v", segment, hits)
		}
	}
	if hit := find(":userId", model.ParamScenarioURLPath); hit != nil {
		t.Fatalf("route placeholders must not become url_path hits: %+v", hits)
	}
	// 路由参数: /user/:userId/profile
	if hit := find("userId", model.ParamScenarioRouteParam); hit == nil {
		t.Fatalf("route_param userId missing from %+v", hits)
	}
}

func TestRouteParamNames(t *testing.T) {
	cases := map[string][]string{
		"/user/:userId/profile":         {"userId"},
		"/user/{userId}/posts/{postId}": {"userId", "postId"},
		"/#/user/:userId/profile":       {"userId"},
		"https://host:8080/static":      {},
		"/plain/path":                   {},
	}
	for raw, want := range cases {
		got := routeParamNames(raw)
		if len(got) != len(want) {
			t.Fatalf("routeParamNames(%q) = %v, want %v", raw, got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("routeParamNames(%q) = %v, want %v", raw, got, want)
			}
		}
	}
}

// TestURLPathSegments covers the literal path-segment extraction: plain and
// hash-routed paths yield segments, placeholders and file-like segments stay
// out, and repeats dedupe in URL order.
func TestURLPathSegments(t *testing.T) {
	cases := map[string][]string{
		"https://api.example.test/api/ra":      {"api", "ra"}, // 用户示例: /api/ra → api, ra
		"/api/ra":                              {"api", "ra"},
		"https://host/static/js/app.js":        {"static", "js"}, // 文件名不算参数
		"https://host/#/user/list":             {"user", "list"},
		"https://host/#!/user/list":            {"user", "list"},
		"https://host/#/user/list?tab=1":       {"user", "list"},
		"https://host/user/:userId/profile":    {"user", "profile"},
		"https://host/user/{userId}/profile":   {"user", "profile"},
		"https://host/order/12345":             {"order", "12345"}, // 数字段是可 fuzz 的路径位
		"https://host/a/b/a":                   {"a", "b"},         // 去重,保持顺序
		"https://host/?page=1":                 {},
		"https://host":                         {},
		"https://host/static/config.json":      {"static"},
		"https://host/api/v%202/name%20x":      {"api", "v 2", "name x"}, // 已解码
		"https://host/api/export.csv?format=1": {"api"},                  // 文件名不算,查询串不是路径段
		"https://host/api/ra/":                 {"api", "ra"},            // 尾斜杠不产生空段
	}
	for raw, want := range cases {
		got := model.URLPathSegments(raw)
		if len(got) != len(want) {
			t.Fatalf("URLPathSegments(%q) = %v, want %v", raw, got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("URLPathSegments(%q) = %v, want %v", raw, got, want)
			}
		}
	}
}

// TestMergeParamHitsIdempotent ensures repeated finalization never
// duplicates derived hits.
func TestMergeParamHitsIdempotent(t *testing.T) {
	result := &model.Result{
		Endpoints: []model.Endpoint{
			{URL: "https://example.test/api?page=1", Type: "api"},
		},
	}
	Finalize(result)
	count := len(result.Params)
	if count == 0 {
		t.Fatal("finalize produced no params")
	}
	Finalize(result)
	if len(result.Params) != count {
		t.Fatalf("finalize duplicated params: %d -> %d", count, len(result.Params))
	}
}
