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
		},
	}
	detail := renderAPIDetail(model.Endpoint{Raw: "/applet/login", Type: "api", Template: tpl})
	for _, want := range []string{"AI 分析", "missing-fields", "登录缺少验证码字段", "captcha, uuid", "sev ai"} {
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
