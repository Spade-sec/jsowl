package report

import (
	"strings"
	"testing"

	"github.com/youmulijiang/jsowl/internal/model"
)

func TestAIAnalysisRendered(t *testing.T) {
	// API 详情：AI 分析区块
	tpl := &model.RequestTemplate{
		Method: "POST", URL: "/ydzf/applet/login",
		AI: &model.AIReview{
			Completeness:    "missing-fields",
			Assessment:      "登录缺少验证码字段，建议补充",
			SuggestedParams: []string{"captcha", "uuid"},
			FuzzPlans: []model.FuzzPlan{
				{Field: "captcha", Strategy: "boundary", Values: []string{"", "000000"}, Note: "验证码可能未校验"},
			},
		},
	}
	detail := renderAPIDetail(model.Endpoint{Raw: "/applet/login", Type: "api", Template: tpl})
	for _, want := range []string{"AI 分析", "missing-fields", "登录缺少验证码字段", "captcha, uuid", "sev ai", "fuzz 计划", "boundary", "验证码可能未校验"} {
		if !strings.Contains(detail, want) {
			t.Fatalf("AI block missing %q", want)
		}
	}

	// 敏感信息表：AI 评估列
	result := model.Result{Findings: []model.Finding{{
		RuleName: "Aliyun AK", Category: model.RuleCategorySensitive, Severity: "high",
		Value: "LTAI5tX", SourceURL: "http://x/app.js", Line: 3,
		AI: &model.AIAssessment{Rating: "high", Reason: "真实 AK 格式", Suggestion: "试 OSS"},
	}}}
	_, body, err := renderSensitiveReport(&result)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"AI 评估", "sev high", "真实 AK 格式", "试 OSS"} {
		if !strings.Contains(body, want) {
			t.Fatalf("sensitive report missing %q", want)
		}
	}
	// 无 AI 时不渲染区块
	plain := renderAPIDetail(model.Endpoint{Raw: "/x", Type: "api",
		Template: &model.RequestTemplate{Method: "GET", URL: "/x"}})
	if strings.Contains(plain, "AI 分析") {
		t.Fatal("no AI review must not render the block")
	}
}

func TestAIPageRendersSummaryAndVerdicts(t *testing.T) {
	result := &model.Result{
		Endpoints: []model.Endpoint{{
			Raw: "/api/login", Method: "POST", Type: "api",
			Template: &model.RequestTemplate{
				Method: "POST", URL: "/api/login",
				AI: &model.AIReview{
					Completeness:    "missing-fields",
					Assessment:      "登录缺少验证码字段",
					SuggestedParams: []string{"captcha"},
					FuzzPlans: []model.FuzzPlan{
						{Field: "captcha", Strategy: "boundary", Values: []string{"", "000000"}, Note: "验证码可能未校验"},
					},
				},
			},
		}},
		Findings: []model.Finding{{
			RuleName: "Aliyun AK", Category: model.RuleCategorySensitive, Severity: "high",
			Value: "LTAI5tX",
			AI:    &model.AIAssessment{Rating: "high", Reason: "真实 AK", Suggestion: "试 OSS"},
		}},
		AI: &model.AISummary{
			Overview: "存在未校验验证码的登录接口。",
			Priorities: []model.AIPriority{
				{Target: "/api/login", Kind: "endpoint", Reason: "可登录后台", Tests: []string{"空验证码登录"}},
			},
			Notes: []string{"全部接口走 /api 前缀"},
			Stats: &model.AIAgentStats{Status: "ok", Steps: 3, Requests: 4, Reviews: 1, Ratings: 1},
		},
	}
	count, body, err := renderAIReport(result)
	if err != nil {
		t.Fatal(err)
	}
	if count != 3 { // priorities(1) + reviews(1) + ratings(1)
		t.Fatalf("count = %d", count)
	}
	for _, want := range []string{
		"完成", "3 轮 / 4 次", "总评", "存在未校验验证码的登录接口",
		"优先测试队列", "/api/login", "endpoint", "空验证码登录",
		"接口请求包复核", "missing-fields", "登录缺少验证码字段",
		"fuzz 计划", "boundary", "验证码可能未校验",
		"敏感发现评级", "真实 AK", "试 OSS",
		"横切观察", "全部接口走 /api 前缀",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("AI page missing %q", want)
		}
	}
}

func TestAIPagePartialStatusAndEmptyState(t *testing.T) {
	count, body, err := renderAIReport(&model.Result{AI: &model.AISummary{
		Stats: &model.AIAgentStats{Status: "partial", Steps: 2, Requests: 2, Reason: "预算耗尽"},
	}})
	if err != nil || count != 0 {
		t.Fatalf("count/err = %d, %v", count, err)
	}
	for _, want := range []string{"部分完成", "预算耗尽", "2 轮 / 2 次"} {
		if !strings.Contains(body, want) {
			t.Fatalf("partial page missing %q", want)
		}
	}

	emptyCount, emptyBody, err := renderAIReport(&model.Result{})
	if err != nil || emptyCount != 0 {
		t.Fatalf("empty page = %d, %v", emptyCount, err)
	}
	if !strings.Contains(emptyBody, "没有 AI 分析内容") {
		t.Fatalf("empty state = %q", emptyBody)
	}
}
