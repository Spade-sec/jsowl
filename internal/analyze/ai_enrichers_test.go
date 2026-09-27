package analyze

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/youmulijiang/jsowl/internal/aiclient"
	"github.com/youmulijiang/jsowl/internal/model"
)

// mockAI spins a chat-completions server replying with a fixed body and
// counts requests.
func mockAI(t *testing.T, reply string, calls *atomic.Int32) *aiclient.Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Write([]byte(`{"choices":[{"message":{"content":` + strconv_quote(reply) + `}}]}`))
	}))
	t.Cleanup(server.Close)
	return aiclient.New(server.URL, "k", "m", "")
}

func strconv_quote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func TestAITemplateEnricherRefinesPlaceholders(t *testing.T) {
	var calls atomic.Int32
	client := mockAI(t, `[{"index":0,"completeness":"missing-fields","assessment":"登录缺验证码字段","suggested_params":["captcha","uuid"]}]`, &calls)
	templateAI, _, _ := NewAIThird(client, 5)

	templates := []*model.RequestTemplate{
		{Method: "POST", URL: "/ydzf/applet/login", Body: "loginName={{fuzz:loginName}}&password={{fuzz:password}}"},
	}
	endpoints := []*model.Endpoint{
		{Raw: "/ydzf/applet/login", Method: "POST", Type: "api",
			Spec: &model.RequestSpec{ContentType: "application/x-www-form-urlencoded",
				Body: []model.Param{{Key: "loginName", Value: "{t.loginName}", Evidence: model.EvidencePlaceholder}}}},
	}
	refined := templateAI.Enrich(templates, endpoints)
	if refined[0].AI == nil {
		t.Fatal("AI review missing")
	}
	if refined[0].AI.Completeness != "missing-fields" {
		t.Fatalf("completeness = %q", refined[0].AI.Completeness)
	}
	if len(refined[0].AI.SuggestedParams) != 2 {
		t.Fatalf("suggested params = %+v", refined[0].AI.SuggestedParams)
	}
	// Advisory contract: body text untouched.
	if refined[0].Body != templates[0].Body {
		t.Fatal("AI must not rewrite the body")
	}
}

func TestAITaintEnricherValidatesUpstream(t *testing.T) {
	var calls atomic.Int32
	client := mockAI(t, `[{"index":0,"kind":"upstream","upstream":"/drug/list","field":"rows"}]`, &calls)
	_, taintAI, _ := NewAIThird(client, 5)

	result := &model.Result{Endpoints: []model.Endpoint{
		{Raw: "/drug/list", Type: "api"},
		{Raw: "/drug/submit", Type: "api", Spec: &model.RequestSpec{
			Body: []model.Param{{Key: "", Value: "{t}", Evidence: model.EvidencePlaceholder,
				Taint: &model.Taint{Kind: model.TaintUnknown, Symbol: "t"}}}},
		}},
	}
	refined := taintAI.EnrichTaint(result)
	ta := refined.Endpoints[1].Spec.Body[0].Taint
	if ta.Kind != model.TaintUpstream || ta.Upstream != "/drug/list" || ta.UpstreamField != "rows" {
		t.Fatalf("refined taint = %+v", ta)
	}
}

func TestAITaintEnricherRejectsHallucinatedUpstream(t *testing.T) {
	var calls atomic.Int32
	// AI claims an upstream the scan never discovered → must stay unknown.
	client := mockAI(t, `[{"index":0,"kind":"upstream","upstream":"/admin/secret","field":"x"}]`, &calls)
	_, taintAI, _ := NewAIThird(client, 5)

	result := &model.Result{Endpoints: []model.Endpoint{
		{Raw: "/drug/submit", Type: "api", Spec: &model.RequestSpec{
			Body: []model.Param{{Key: "", Value: "{t}", Evidence: model.EvidencePlaceholder,
				Taint: &model.Taint{Kind: model.TaintUnknown, Symbol: "t"}}}},
		}},
	}
	refined := taintAI.EnrichTaint(result)
	ta := refined.Endpoints[0].Spec.Body[0].Taint
	if ta.Kind != model.TaintUnknown {
		t.Fatalf("hallucinated upstream must stay unknown, got %+v", ta)
	}
}

func TestAIFindingEnricherRates(t *testing.T) {
	var calls atomic.Int32
	client := mockAI(t, `[{"index":0,"rating":"high","reason":"真实阿里云 AK 格式","suggestion":"尝试 OSS 接口"}]`, &calls)
	_, _, findingAI := NewAIThird(client, 5)

	result := &model.Result{Findings: []model.Finding{{
		RuleName: "Aliyun AK", Category: model.RuleCategorySensitive,
		Severity: "high", Value: "LTAI5tABCDEFG123",
	}}}
	refined := findingAI.EnrichFindings(result)
	ai := refined.Findings[0].AI
	if ai == nil || ai.Rating != "high" || ai.Suggestion == "" {
		t.Fatalf("finding AI = %+v", ai)
	}
}

func TestAIBudgetCap(t *testing.T) {
	var calls atomic.Int32
	client := mockAI(t, `[{"index":0,"completeness":"complete","assessment":"ok"}]`, &calls)
	templateAI, _, _ := NewAIThird(client, 2) // cap 2 requests

	endpoints := make([]*model.Endpoint, 0, 30)
	templates := make([]*model.RequestTemplate, 0, 30)
	for i := 0; i < 30; i++ {
		templates = append(templates, &model.RequestTemplate{Method: "GET", URL: "/x"})
		endpoints = append(endpoints, &model.Endpoint{Raw: "/x", Type: "api"})
	}
	templateAI.Enrich(templates, endpoints)
	if got := calls.Load(); got != 2 {
		t.Fatalf("budget cap: requests = %d, want 2", got)
	}
}

func TestAIEnricherGracefulOnGarbage(t *testing.T) {
	var calls atomic.Int32
	client := mockAI(t, `抱歉，我无法输出 JSON。`, &calls)
	templateAI, taintAI, findingAI := NewAIThird(client, 5)

	templates := []*model.RequestTemplate{{Method: "GET", URL: "/x"}}
	endpoints := []*model.Endpoint{{Raw: "/x", Type: "api"}}
	refined := templateAI.Enrich(templates, endpoints)
	if refined[0].AI != nil {
		t.Fatal("garbage reply must not produce a review")
	}
	result := &model.Result{Endpoints: []model.Endpoint{{Raw: "/x", Type: "api",
		Spec: &model.RequestSpec{Body: []model.Param{{Key: "", Value: "{t}",
			Evidence: model.EvidencePlaceholder, Taint: &model.Taint{Kind: model.TaintUnknown}}}}}},
		Findings: []model.Finding{{RuleName: "r", Category: model.RuleCategorySensitive, Value: "v"}},
	}
	if got := taintAI.EnrichTaint(result); got == nil {
		t.Fatal("garbage taint reply must degrade to original result")
	}
	if got := findingAI.EnrichFindings(result); got == nil {
		t.Fatal("garbage finding reply must degrade to original result")
	}
	if result.Findings[0].AI != nil {
		t.Fatal("garbage reply must not attach an assessment")
	}
	if !strings.Contains(result.Findings[0].Value, "v") {
		t.Fatal("finding value must be untouched")
	}
}
