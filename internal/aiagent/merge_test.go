package aiagent

import (
	"testing"

	"github.com/youmulijiang/jsowl/internal/model"
)

func sampleResult() *model.Result {
	return &model.Result{
		Target: "https://example.com",
		Endpoints: []model.Endpoint{
			{
				Raw: "/api/user/login", Method: "POST", Type: "api",
				Spec: &model.RequestSpec{
					ContentType: "application/json",
					Body: []model.Param{
						{Key: "username", Value: "admin", Evidence: model.EvidenceLiteral},
						{Key: "password", Value: "{{fuzz:body:pwd}}", Evidence: model.EvidencePlaceholder,
							Taint: &model.Taint{Kind: model.TaintUnknown, Symbol: "pwd"}},
						{Key: "captcha", Value: "1234", Evidence: model.EvidenceLiteral},
					},
				},
			},
			{Raw: "/api/admin/user", Method: "GET", Type: "api"},
		},
		Findings: []model.Finding{
			{RuleID: "aliyun-ak", RuleName: "Aliyun AK", Severity: model.SeverityHigh,
				Value: "LTAI5tExample", Category: model.RuleCategorySensitive},
			{RuleID: "phone", RuleName: "手机号", Severity: model.SeverityLow,
				Value: "13800000000", Category: model.RuleCategorySensitive},
			{RuleID: "phone", RuleName: "手机号", Severity: model.SeverityLow,
				Value: "13900000000", Category: model.RuleCategorySensitive},
		},
	}
}

func TestApplyReviewAndFuzzPlans(t *testing.T) {
	result := sampleResult()
	final := &FinalReport{
		Reviews: []TemplateReview{{
			Endpoint:        "/api/user/login",
			Completeness:    "missing-fields",
			Assessment:      "登录缺少验证码校验字段",
			SuggestedParams: []string{"uuid", " "},
			FuzzPlans: []model.FuzzPlan{
				{Field: "password", Strategy: "boundary", Values: []string{"a"}},
				{Field: " ", Strategy: "enum"}, // blank field dropped
			},
		}},
	}
	stats := Apply(result, final)
	if stats.Reviews != 1 || stats.Status != StatusOK {
		t.Fatalf("stats = %+v", stats)
	}
	review := result.Endpoints[0].Template.AI
	if review == nil || review.Completeness != "missing-fields" {
		t.Fatalf("review = %+v", review)
	}
	if len(review.SuggestedParams) != 1 || review.SuggestedParams[0] != "uuid" {
		t.Fatalf("suggested params = %v", review.SuggestedParams)
	}
	if len(review.FuzzPlans) != 1 || review.FuzzPlans[0].Field != "password" {
		t.Fatalf("fuzz plans = %+v", review.FuzzPlans)
	}
	// Advisory contract: recovered literal values untouched.
	if result.Endpoints[0].Spec.Body[0].Value != "admin" {
		t.Fatalf("literal value rewritten: %q", result.Endpoints[0].Spec.Body[0].Value)
	}
}

func TestApplyTaintOnlyUpgradesUnknown(t *testing.T) {
	result := sampleResult()
	final := &FinalReport{
		Taints: []TaintFix{{
			Endpoint: "/api/user/login", Param: "password",
			Kind: model.TaintUpstream, Upstream: "/api/admin/user", Field: "uuid",
		}},
	}
	stats := Apply(result, final)
	if stats.Taints != 1 {
		t.Fatalf("stats = %+v", stats)
	}
	taint := result.Endpoints[0].Spec.Body[1].Taint
	if taint.Kind != model.TaintUpstream || taint.Upstream != "/api/admin/user" || taint.UpstreamField != "uuid" {
		t.Fatalf("taint = %+v", taint)
	}
	// Symbol survives the refinement.
	if taint.Symbol != "pwd" {
		t.Fatalf("symbol lost: %q", taint.Symbol)
	}
}

func TestApplyTaintRejectsHallucinatedUpstream(t *testing.T) {
	result := sampleResult()
	final := &FinalReport{
		Taints: []TaintFix{{
			Endpoint: "/api/user/login", Param: "password",
			Kind: model.TaintUpstream, Upstream: "/api/nonexistent",
		}},
	}
	if stats := Apply(result, final); stats.Taints != 0 {
		t.Fatalf("hallucinated upstream merged: %+v", stats)
	}
	if result.Endpoints[0].Spec.Body[1].Taint.Kind != model.TaintUnknown {
		t.Fatalf("unknown verdict overwritten")
	}
}

func TestApplyTaintSegmentBoundary(t *testing.T) {
	// A param only exists on the endpoint that owns it: "/admin/user"
	// resolves to /api/admin/user, which has no spec, so nothing merges.
	result := sampleResult()
	final := &FinalReport{
		Taints: []TaintFix{{Endpoint: "/admin/user", Param: "password",
			Kind: model.TaintStorage}},
	}
	if stats := Apply(result, final); stats.Taints != 0 {
		t.Fatalf("param lives on another endpoint: %+v", stats)
	}
	// But the boundary suffix does resolve the owner endpoint, and its
	// unknown placeholder is refined.
	final.Taints[0].Endpoint = "/user/login"
	if stats := Apply(result, final); stats.Taints != 1 {
		t.Fatalf("boundary suffix rejected: %+v", stats)
	}
}

func TestApplyRatingsWhitelistAndIdentity(t *testing.T) {
	result := sampleResult()
	// Findings 1 and 2 share the rule id "phone", so a rule-id-only
	// fallback for that id is ambiguous and must match nothing.
	final := &FinalReport{
		Ratings: []FindingRating{
			{RuleID: "aliyun-ak", Value: "LTAI5tExample", Rating: "high", Reason: "真实 AK", Suggestion: "试 OSS"},
			{RuleID: "phone", Value: "13800000000", Rating: "medium"},          // exact pair wins despite ambiguous id
			{RuleID: "phone", Value: "wrong-value", Rating: "invalid"},        // ambiguous rule — dropped
			{RuleID: "aliyun-ak", Value: "LTAI5tExample", Rating: "critical"}, // off-vocabulary — dropped
		},
	}
	stats := Apply(result, final)
	if stats.Ratings != 2 {
		t.Fatalf("stats = %+v", stats)
	}
	if result.Findings[0].AI == nil || result.Findings[0].AI.Rating != "high" {
		t.Fatalf("first rating = %+v", result.Findings[0].AI)
	}
	if result.Findings[1].AI == nil || result.Findings[1].AI.Rating != "medium" {
		t.Fatalf("exact-pair rating = %+v", result.Findings[1].AI)
	}
	if result.Findings[2].AI != nil {
		t.Fatalf("unrelated finding rated: %+v", result.Findings[2].AI)
	}
}

func TestApplySummaryPrioritiesValidated(t *testing.T) {
	result := sampleResult()
	final := &FinalReport{
		Summary: SummaryOut{
			Overview: "存在可登录后台的管理端接口。",
			Priorities: []PriorityOut{
				{Target: "/api/user/login", Tests: []string{"空验证码登录"}},
				{Target: "/api/does-not-exist", Kind: "endpoint"}, // dropped
				{Target: "LTAI5tExample", Kind: "finding"},
			},
			Notes: []string{"所有接口都走 /api 前缀", " "},
		},
	}
	Apply(result, final)
	if result.AI == nil || result.AI.Overview == "" {
		t.Fatalf("summary = %+v", result.AI)
	}
	if len(result.AI.Priorities) != 2 {
		t.Fatalf("priorities = %+v", result.AI.Priorities)
	}
	if result.AI.Priorities[0].Kind != "endpoint" || result.AI.Priorities[1].Kind != "finding" {
		t.Fatalf("kinds not resolved: %+v", result.AI.Priorities)
	}
	if len(result.AI.Notes) != 1 {
		t.Fatalf("notes = %v", result.AI.Notes)
	}
	if result.AI.Stats == nil || result.AI.Stats.Status != StatusOK {
		t.Fatalf("stats = %+v", result.AI.Stats)
	}
}

func TestApplyDropsUnknownEndpoints(t *testing.T) {
	result := sampleResult()
	final := &FinalReport{
		Reviews: []TemplateReview{
			{Endpoint: "/api/invented", Completeness: "complete", Assessment: "幻觉接口"},
			{Endpoint: "", Completeness: "complete", Assessment: "空引用"},
		},
	}
	if stats := Apply(result, final); stats.Reviews != 0 {
		t.Fatalf("hallucinated endpoint merged: %+v", stats)
	}
	if result.Endpoints[0].Template != nil {
		t.Fatalf("template should not have been built for a dropped review")
	}
}
