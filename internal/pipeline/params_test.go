package pipeline

import (
	"testing"

	"github.com/youmulijiang/jsowl/internal/model"
)

// TestDeriveParamHitsScenarios checks the endpoint-side scenarios: API request
// bodies, URL query strings, and framework route placeholders.
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
