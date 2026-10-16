package report

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/youmulijiang/jsowl/internal/discover"
	"github.com/youmulijiang/jsowl/internal/extract"
	"github.com/youmulijiang/jsowl/internal/model"
)

// sampleReportEnv gates local sample-report generation: the generator writes
// into the repository, so it only runs when explicitly asked for.
const sampleReportEnv = "JSOWL_SAMPLE_REPORT"

// richSampleResult is the fixture used for local browser verification: every
// severity level, several hosts, duplicated findings, an unresolved relative
// path, a method-less endpoint, long URLs and values, route probes, request
// specs, reconstructed packets with an AI review, and diagnostics.
func richSampleResult() *model.Result {
	started := time.Date(2026, 5, 4, 9, 12, 0, 0, time.Local)
	longURL := "https://shop.example.com/api/v2/catalog/search?q=keyword&page=1&size=50&sort=price_asc" +
		"&filter[category]=electronics&filter[brand]=acme&filter[stock]=in_stock&currency=CNY&locale=zh-CN"
	longJWT := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
		"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpzT3dsIFNhbXBsZSIsImFkbWluIjp0cnVlLCJpYXQiOjE3MTAwMDAwMDB9." +
		"3bT1kQwErTyUiOpAsDfGhJkLzXcVbNmQwErTyUiOpAs"

	return &model.Result{
		Target:     "https://shop.example.com/app",
		Mode:       model.ModeAuto,
		UserAgent:  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) JsOwl/1.0",
		StartedAt:  started,
		FinishedAt: started.Add(3*time.Minute + 24*time.Second),
		BrowserStatus: model.BrowserStatus{
			Attempted: true, Used: true,
		},
		Technologies: []string{"Vue", "axios", "webpack"},
		Resources: []model.Resource{
			{URL: "https://shop.example.com/app", Type: model.ResourceTypeDocument, StatusCode: 200, Size: 2048, Depth: 0},
			{URL: "https://shop.example.com/static/js/app.8f2c1a.js", Type: model.ResourceTypeScript, StatusCode: 200, Size: 486_233, LocalPath: "js/app.8f2c1a.js", Depth: 1},
			{URL: "https://shop.example.com/static/js/chunk-vendors.4d91bb.js", Type: model.ResourceTypeScript, StatusCode: 200, Size: 912_004, LocalPath: "js/chunk-vendors.4d91bb.js", Depth: 1},
			{URL: "https://shop.example.com/static/js/chunks/users.71ab20.js", Type: model.ResourceTypeChunk, StatusCode: 200, Size: 61_442, LocalPath: "js/chunks/users.71ab20.js", Depth: 2},
			{URL: "https://shop.example.com/static/js/chunks/orders.9c03ef.js", Type: model.ResourceTypeChunk, StatusCode: 200, Size: 78_120, LocalPath: "js/chunks/orders.9c03ef.js", Depth: 2},
			{URL: "https://shop.example.com/static/js/app.8f2c1a.js.map", Type: model.ResourceTypeSourceMap, StatusCode: 200, Size: 1_204_882, LocalPath: "js/app.8f2c1a.js.map", Depth: 1},
			{URL: "https://cdn.example.com/assets/logo.svg", Type: model.ResourceTypeAsset, StatusCode: 200, Size: 3_120, Depth: 1},
			{URL: "https://cdn.example.com/assets/theme.css", Type: model.ResourceTypeAsset, StatusCode: 404, Size: 512, Depth: 1},
			{URL: "https://api.partner.example.net/sdk/partner-sdk.min.js", Type: model.ResourceTypeExternal, StatusCode: 200, Size: 240_998, Depth: 1},
			// No status code recorded: must render as 无响应, never as 200.
			{URL: "https://shop.example.com/static/js/legacy.js", Type: model.ResourceTypeScript, Depth: 1},
		},
		Endpoints: []model.Endpoint{
			// An IP literal and a reserved-suffix host, so the sample shows the
			// non-domain outcomes next to the real domains.
			{
				Raw: "/metrics", URL: "http://10.20.30.40:8080/metrics",
				SourceURL:  "https://shop.example.com/static/js/app.8f2c1a.js",
				Authorized: true, Method: "GET", Type: "api", Source: "regex",
				Evidence: model.EvidenceStatic, StatusCode: 200,
			},
			{
				Raw: "/healthz", URL: "https://lab.internal.test/healthz",
				SourceURL:  "https://shop.example.com/static/js/app.8f2c1a.js",
				Authorized: true, Method: "GET", Type: "api", Source: "ast",
				Evidence: model.EvidenceFullURL, StatusCode: 200,
			},
			{
				Raw: "/api/v2/users", URL: "https://shop.example.com/api/v2/users",
				SourceURL:  "https://shop.example.com/static/js/chunks/users.71ab20.js",
				Authorized: true, Method: "GET", Type: "api", Source: "ast",
				Evidence: model.EvidenceFullURL, StatusCode: 200, Line: 42, Column: 18,
				BodyParams: []string{"userId", "withProfile"},
				Spec: &model.RequestSpec{
					BaseURL: "https://shop.example.com", BaseURLKind: model.EvidenceLiteral,
					ContentType: "application/json", ContentTypeEvidence: model.EvidenceInferred,
					Query: []model.Param{
						{Key: "userId", Value: "1", Evidence: model.EvidenceLiteral},
						{Key: "withProfile", Value: "true", Evidence: model.EvidenceLiteral},
						{Key: "token", Value: "{token}", Evidence: model.EvidencePlaceholder,
							Taint: &model.Taint{Kind: model.TaintStorage, Symbol: "localStorage.token"}},
					},
				},
				ContextLines: []model.ContextLine{
					{LineNumber: 41, Content: "async function fetchUser(userId) {", MatchStart: -1, MatchEnd: -1},
					{LineNumber: 42, Content: `  return axios.get("/api/v2/users", { params: { userId } })`, MatchStart: 14, MatchEnd: 34},
					{LineNumber: 43, Content: "}", MatchStart: -1, MatchEnd: -1},
				},
			},
			{
				Raw: "/api/v2/login", URL: "https://shop.example.com/api/v2/login",
				SourceURL:  "https://shop.example.com/static/js/app.8f2c1a.js",
				Authorized: true, Method: "POST", Type: "api", Source: "ast",
				Evidence: model.EvidenceFullURL, StatusCode: 200, Line: 118, Column: 3,
				BodyParams: []string{"username", "password", "captcha"},
				Spec: &model.RequestSpec{
					ContentType: "application/json", ContentTypeEvidence: model.EvidenceInferred,
					Body: []model.Param{
						{Key: "username", Value: "{username}", Evidence: model.EvidencePlaceholder},
						{Key: "password", Value: "{password}", Evidence: model.EvidencePlaceholder},
						{Key: "captcha", Value: "1234", Evidence: model.EvidenceLiteral},
					},
				},
				Template: &model.RequestTemplate{
					Method: "POST", URL: "https://shop.example.com/api/v2/login",
					Headers: []model.HeaderTpl{
						{Key: "Content-Type", Value: "application/json", Evidence: model.EvidenceInferred},
						{Key: "Authorization", Value: "Bearer {{fuzz:token}}", Evidence: model.EvidencePlaceholder},
					},
					Body:  `{"username": "{{fuzz:username}}", "password": "{{fuzz:password}}", "captcha": "1234"}`,
					Notes: []string{"源码中密码字段在发送前可能先做了前端摘要，直接替换明文可能无法登录。"},
					AI: &model.AIReview{
						Completeness:    "missing-fields",
						Assessment:      "登录参数基本完整，但缺少验证码的校验前置参数（uuid）。",
						SuggestedParams: []string{"uuid", "deviceId"},
					},
				},
			},
			{
				Raw: "/api/v2/orders", URL: "https://shop.example.com/api/v2/orders",
				SourceURL:  "https://shop.example.com/static/js/chunks/orders.9c03ef.js",
				Authorized: true, Method: "DELETE", Type: "api", Source: "ast",
				Evidence: model.EvidenceStatic, StatusCode: 403, Line: 27, Column: 5,
				BodyParams: []string{"orderId"},
			},
			{
				Raw: "/api/v2/orders/status", URL: "https://shop.example.com/api/v2/orders/status",
				SourceURL:  "https://shop.example.com/static/js/chunks/orders.9c03ef.js",
				Authorized: true, Method: "PATCH", Type: "api", Source: "regex",
				Evidence: model.EvidenceStatic, StatusCode: 200, Line: 51, Column: 9,
				BodyParams:     []string{"orderId", "status"},
				ResponseParams: []string{"updatedAt", "operator"},
			},
			{
				Raw: "/api/v2/profile", URL: "https://shop.example.com/api/v2/profile",
				SourceURL:  "https://shop.example.com/static/js/chunks/users.71ab20.js",
				Authorized: true, Method: "PUT", Type: "api", Source: "ast",
				Evidence: model.EvidenceFullURL, StatusCode: 200, Line: 63, Column: 4,
				BodyParams: []string{"nickname", "avatar"},
			},
			// No method recovered: must be shown as 未知, never defaulted to GET.
			{
				Raw: "/api/v2/banners", URL: "https://shop.example.com/api/v2/banners",
				SourceURL:  "https://shop.example.com/static/js/app.8f2c1a.js",
				Authorized: true, Type: "api", Source: "regex", Evidence: model.EvidenceStatic,
			},
			// Runtime observation carries the strongest evidence rank.
			{
				Raw: longURL, URL: longURL,
				SourceURL:  "https://shop.example.com/static/js/chunks/orders.9c03ef.js",
				Authorized: true, Method: "GET", Type: "api", Source: "cdp",
				Evidence: model.EvidenceRuntime, StatusCode: 200,
				BodyParams: []string{"q", "page", "size", "sort", "currency", "locale"},
			},
			// Relative reference with no host: must be grouped on its own.
			{
				Raw: "v1/session/heartbeat", URL: "v1/session/heartbeat",
				SourceURL:  "https://shop.example.com/static/js/app.8f2c1a.js",
				Authorized: false, Type: "api", Source: "regex", Evidence: model.EvidenceStatic,
			},
			// A second host, recovered from a third-party bundle.
			{
				Raw: "https://api.partner.example.net/v3/track", URL: "https://api.partner.example.net/v3/track",
				SourceURL:  "https://api.partner.example.net/sdk/partner-sdk.min.js",
				Authorized: false, Method: "POST", Type: "api", Source: "ast",
				Evidence: model.EvidenceFullURL, StatusCode: 200, Vendor: true,
				BodyParams: []string{"event", "uid", "ts"},
			},
			{Raw: "/#/dashboard", URL: "https://shop.example.com/#/dashboard", SourceURL: "https://shop.example.com/static/js/app.8f2c1a.js", Type: "route", Source: "ast", Evidence: model.EvidenceStatic, Probe: "static"},
			{Raw: "/#/orders/:orderId", URL: "https://shop.example.com/#/orders/:orderId", SourceURL: "https://shop.example.com/static/js/chunks/orders.9c03ef.js", Type: "route", Source: "ast", Evidence: model.EvidenceStatic, Probe: "static"},
			{Raw: "/admin/console", URL: "https://shop.example.com/admin/console", SourceURL: "https://shop.example.com/static/js/app.8f2c1a.js", Type: "route", Source: "cdp-runtime", Evidence: model.EvidenceRuntime, Probe: "server"},
			{Raw: "/#/reports/export", URL: "https://shop.example.com/#/reports/export", SourceURL: "https://shop.example.com/static/js/app.8f2c1a.js", Type: "route", Source: "ast", Evidence: model.EvidenceStatic, Probe: "error"},
		},
		Findings: []model.Finding{
			{
				RuleID: "hae.密钥凭证.阿里云 Access Key", RuleName: "阿里云 Access Key",
				Category: model.RuleCategorySensitive, Severity: model.SeverityCritical,
				Value: "LTAI5tXk9QwErTyUiOpAsDf", SourceURL: "https://shop.example.com/static/js/app.8f2c1a.js",
				Line: 26, Column: 24,
				ContextLines: []model.ContextLine{
					{LineNumber: 25, Content: "const ossConfig = {", MatchStart: -1, MatchEnd: -1},
					{LineNumber: 26, Content: `  accessKeyId: "LTAI5tXk9QwErTyUiOpAsDf",`, MatchStart: 15, MatchEnd: 39},
					{LineNumber: 27, Content: `  accessKeySecret: "9f8e7d6c5b4a3210",`, MatchStart: 19, MatchEnd: 35},
				},
				AI: &model.AIAssessment{
					Rating: "high", Reason: "值符合阿里云 AccessKeyId 的固定前缀与长度特征。",
					Suggestion: "在授权范围内尝试只读列举 OSS 桶，确认权限范围后立即上报。",
				},
			},
			{
				// Same rule, same value, different file: one aggregated finding,
				// two evidence locations.
				RuleID: "hae.密钥凭证.阿里云 Access Key", RuleName: "阿里云 Access Key",
				Category: model.RuleCategorySensitive, Severity: model.SeverityCritical,
				Value: "LTAI5tXk9QwErTyUiOpAsDf", SourceURL: "https://shop.example.com/static/js/chunks/users.71ab20.js",
				Line: 8, Column: 31,
			},
			{
				RuleID: "hae.密钥凭证.PEM 私钥内容", RuleName: "PEM 私钥内容",
				Category: model.RuleCategorySensitive, Severity: model.SeverityCritical,
				Value: "-----BEGIN RSA PRIVATE KEY-----", SourceURL: "https://shop.example.com/static/js/app.8f2c1a.js",
				Line: 402, Column: 6, Vendor: true,
				AI: &model.AIAssessment{Rating: "medium", Reason: "疑似测试用密钥前缀，需人工确认是否可用。"},
			},
			{
				RuleID: "hae.PII.身份证号", RuleName: "身份证号",
				Category: model.RuleCategorySensitive, Severity: model.SeverityHigh,
				Value: "110105199003074219", SourceURL: "https://shop.example.com/static/js/chunks/users.71ab20.js",
				Line: 77, Column: 40,
			},
			{
				RuleID: "hae.网络信息.URL内嵌账密", RuleName: "URL内嵌账密",
				Category: model.RuleCategorySensitive, Severity: model.SeverityHigh,
				Value:     "mongodb://svc:Passw0rd%21@10.20.30.40:27017/orders",
				SourceURL: "https://shop.example.com/static/js/app.8f2c1a.js", Line: 512, Column: 12,
			},
			{
				// Long matched value: the list truncates it, the detail panel and
				// CSV export keep it whole.
				RuleID: "hae.密钥凭证.JWT token", RuleName: "JWT token",
				Category: model.RuleCategorySensitive, Severity: model.SeverityHigh,
				Value: longJWT, SourceURL: "https://shop.example.com/static/js/app.8f2c1a.js",
				Line: 233, Column: 17,
				AI: &model.AIAssessment{Rating: "medium", Reason: "结构完整，但可能是公开的示例 token。", Suggestion: "解码 payload 确认是否含高权限声明。"},
			},
			{
				RuleID: "hae.指纹暴露.Druid控制台", RuleName: "Druid控制台",
				Category: model.RuleCategorySensitive, Severity: model.SeverityMedium,
				Value: "/druid/index.html", SourceURL: "https://shop.example.com/static/js/app.8f2c1a.js",
				Line: 611, Column: 22,
			},
			{
				RuleID: "hae.PII.邮箱地址", RuleName: "邮箱地址",
				Category: model.RuleCategorySensitive, Severity: model.SeverityMedium,
				Value: "ops-team@example.com", SourceURL: "https://shop.example.com/static/js/chunks/users.71ab20.js",
				Line: 33, Column: 15,
			},
			{
				RuleID: "hae.PII.邮箱地址", RuleName: "邮箱地址",
				Category: model.RuleCategorySensitive, Severity: model.SeverityMedium,
				Value: "security@example.com", SourceURL: "https://shop.example.com/static/js/app.8f2c1a.js",
				Line: 88, Column: 9, Vendor: true,
			},
			{
				RuleID: "hae.网络信息.内网IP", RuleName: "内网IP",
				Category: model.RuleCategorySensitive, Severity: model.SeverityLow,
				Value: "10.20.30.40", SourceURL: "https://shop.example.com/static/js/app.8f2c1a.js",
				Line: 512, Column: 8,
			},
			{
				RuleID: "hae.指纹暴露.Vite开发模式残留", RuleName: "Vite开发模式残留",
				Category: model.RuleCategorySensitive, Severity: model.SeverityLow,
				Value: "__vite__injectQuery", SourceURL: "https://shop.example.com/static/js/app.8f2c1a.js",
				Line: 741, Column: 2,
			},
			{
				RuleID: "hae.URL.完整 HTTP URL", RuleName: "完整 HTTP URL",
				Category: model.RuleCategoryURL, Severity: model.SeverityInfo,
				Value: longURL, SourceURL: "https://shop.example.com/static/js/chunks/orders.9c03ef.js",
				Line: 19, Column: 24,
			},
			{
				RuleID: "hae.URL.XMLHttpRequest URL", RuleName: "XMLHttpRequest URL",
				Category: model.RuleCategoryURL, Severity: model.SeverityInfo,
				Value: "/api/v2/banners", SourceURL: "https://shop.example.com/static/js/app.8f2c1a.js",
				Line: 305, Column: 30,
			},
		},
		Params: []model.ParamHit{
			{Name: "userId", Scenario: model.ParamScenarioObjectProperty, Value: "1", Evidence: model.EvidenceLiteral, SourceURL: "https://shop.example.com/static/js/chunks/users.71ab20.js", Line: 14, Column: 11},
			{Name: "orderId", Scenario: model.ParamScenarioFunctionParam, SourceURL: "https://shop.example.com/static/js/chunks/orders.9c03ef.js", Line: 27, Column: 24},
			{Name: "nickname", Scenario: model.ParamScenarioDestructuring, SourceURL: "https://shop.example.com/static/js/chunks/users.71ab20.js", Line: 61, Column: 9},
			{Name: "apiKey", Scenario: model.ParamScenarioVariable, Value: "xxx", SourceURL: "https://shop.example.com/static/js/app.8f2c1a.js", Line: 96, Column: 3},
			{Name: "page", Scenario: model.ParamScenarioURLQuery, SourceURL: "https://shop.example.com/api/v2/catalog/search", Line: 0},
		},
		Issues: []model.Issue{
			{Code: "resource_get_failed", Stage: "collect", URL: "https://cdn.example.com/assets/logo.svg", Message: "connection reset by peer", Retryable: true},
			{Code: "body_truncated", Stage: "collect", URL: "https://api.partner.example.net/sdk/partner-sdk.min.js", Message: "body exceeds limits.max_body_size (262144 bytes)"},
			{Code: "js_analysis_failed", Stage: "analyze", URL: "https://shop.example.com/static/js/app.8f2c1a.js.map", Message: "source map JSON is truncated"},
			{Code: "js_not_saved", Stage: "storage", URL: "https://shop.example.com/static/js/app.8f2c1a.js.map", Message: "output.download_js is false"},
			{Code: "js_save_failed", Stage: "storage", URL: "https://cdn.example.com/assets/theme.css", Message: "open ...: access is denied", Retryable: true},
		},
		// Content-discovered hosts, produced by the real extractor so the sample
		// shows what a scan would show.
		Hosts: sampleContentHosts(),
	}
}

// sampleContentHosts runs the real host extraction over a representative
// bundle. The sample report's "content discovered" column therefore comes from
// the same code path a scan uses, not from hand-written fixtures.
func sampleContentHosts() []model.HostAsset {
	source, err := url.Parse("https://shop.example.com/static/js/app.8f2c1a.js")
	if err != nil {
		return nil
	}
	script := `
// allowed origins: https://allow.example.com, https://cdn.partner.example.net
const apiBase = "https://api.example.com/v2";
const socket = "wss://socket.example.net/live";
const parts = "https://" + "concat." + "example.org/v1";
const cache = "redis://cache.internal.test:6379/0";
const legacy = "http://10.20.30.41:8080/admin";
const single = { host: "gateway" };
const site = "https://shop.example.com/app";
const dynamic = ` + "`" + `https://${apiBase}/v2/users` + "`" + `;
fetch(apiBase + "/orders");
`
	analysis := discover.AnalyzeJS(source, []byte(script))
	aggregator := extract.NewAggregator(
		extract.NewExtractor(model.HostsConfig{}), model.HostOriginContent,
	)
	for _, candidate := range analysis.Hosts {
		aggregator.Add(candidate)
	}
	return aggregator.Assets()
}

func TestRichSampleCoversEveryReportDimension(t *testing.T) {
	result := richSampleResult()
	summary := buildSummary(result, result.FinishedAt)

	for _, severity := range reportSeverities {
		found := false
		for _, row := range summary.SeverityMetrics {
			if row.Severity == severity && row.Groups > 0 && row.Hits > 0 {
				found = true
			}
		}
		if !found {
			t.Errorf("sample is missing severity level %q", severity)
		}
	}
	if len(summary.Domains) < 3 {
		t.Fatalf("sample should span several hosts, got %#v", summary.Domains)
	}
	var unresolved bool
	for _, domain := range summary.Domains {
		if domain.Host == unresolvedHost {
			unresolved = true
		}
	}
	if !unresolved {
		t.Fatal("sample must include a relative reference to exercise the unresolved-host bucket")
	}
	methods := map[string]int{}
	for _, bucket := range summary.Methods {
		methods[bucket.Key] = bucket.Count
	}
	if methods[unresolvedMethod] == 0 {
		t.Fatal("sample must include an endpoint without a method")
	}
	if methods["GET"] == 0 || methods["POST"] == 0 || methods["DELETE"] == 0 {
		t.Fatalf("sample must span several verbs, got %#v", methods)
	}

	// Duplicated findings collapse into one aggregated finding that keeps both
	// evidence locations.
	var ak *findingGroup
	for index := range summary.Groups {
		if summary.Groups[index].Value == "LTAI5tXk9QwErTyUiOpAsDf" {
			ak = &summary.Groups[index]
		}
	}
	if ak == nil {
		t.Fatal("duplicated sample finding missing")
	}
	if ak.Hits != 2 || len(ak.Sources) != 2 {
		t.Fatalf("duplicated finding must aggregate to 2 hits with 2 sources: %#v", ak)
	}
	if ak.AICount != 1 || ak.AI == nil {
		t.Fatal("the AI assessment on one of the duplicate hits must survive")
	}

	// A long value is summarized for the list but kept whole on the group.
	var jw *findingGroup
	for index := range summary.Groups {
		if summary.Groups[index].RuleID == "hae.密钥凭证.JWT token" {
			jw = &summary.Groups[index]
		}
	}
	if jw == nil {
		t.Fatal("long-value sample finding missing")
	}
	if jw.Value == jw.Summary || len(jw.Summary) >= len(jw.Value) {
		t.Fatal("the list summary must be a shortened form of a long value")
	}
	if !strings.Contains(jw.Value, ".") || len(jw.Value) < 150 {
		t.Fatalf("sample JWT is not long enough to exercise truncation: %d bytes", len(jw.Value))
	}
}

func TestRichSampleRendersEverythingTheWorkbenchNeeds(t *testing.T) {
	result := richSampleResult()
	directory := t.TempDir()
	if err := WriteHTML(filepath.Join(directory, "report.html"), result); err != nil {
		t.Fatal(err)
	}
	if err := WriteSplitReports(directory, result); err != nil {
		t.Fatal(err)
	}
	if err := WriteTextReports(directory, result); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(directory, "report.html"))
	if err != nil {
		t.Fatal(err)
	}
	page := string(data)
	for _, want := range []string{
		// Full evidence, not a truncated form, ships in the page.
		"LTAI5tXk9QwErTyUiOpAsDf",
		"9f8e7d6c5b4a3210",        // context line of the AK finding
		"shop.example.com",        // host bucket
		"api.partner.example.net", // second host
		"v1/session/heartbeat",    // unresolved relative path
		"（未解析主机）",                 // its bucket label
		"未探测",                     // route probe fallback
		"服务端真实页面",                 // probe outcome label
		"missing-fields",          // AI review of a packet
		"uuid",                    // AI-suggested parameter
		"catalog/search",          // long URL
		"无响应",                     // resource without a status code
		"body_truncated",          // diagnostic code
		"待人工验证",                   // confirmation status
	} {
		if !strings.Contains(page, want) {
			t.Errorf("sample report missing %q", want)
		}
	}
}

// TestGenerateSampleReport writes browsable sample reports for local
// inspection. They are written into the repository, so the test only runs
// when asked:
//
//	JSOWL_SAMPLE_REPORT=1 go test ./internal/report -run TestGenerateSampleReport -v
//
// Three sets are produced: a rich report (every severity, several hosts,
// duplicated findings, long values, diagnostics), an empty report (the
// zero-data rendering path) and a large report (pagination and the capped
// print scope).
func TestGenerateSampleReport(t *testing.T) {
	if os.Getenv(sampleReportEnv) == "" {
		t.Skipf("set %s=1 to write the sample reports", sampleReportEnv)
	}
	root := repositoryRoot(t)
	samples := []struct {
		name   string
		result *model.Result
	}{
		{"sample-report", richSampleResult()},
		{"empty-report", &model.Result{Target: "https://empty.example.com", Mode: model.ModeDirect, UserAgent: "JsOwl-Test"}},
		{"large-report", largeSampleResult()},
	}
	for _, sample := range samples {
		directory := filepath.Join(root, "jsowl-report", sample.name)
		if err := os.MkdirAll(directory, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := WriteJSON(filepath.Join(directory, "report.json"), sample.result); err != nil {
			t.Fatal(err)
		}
		if err := WriteTextReports(directory, sample.result); err != nil {
			t.Fatal(err)
		}
		if err := WriteSplitReports(directory, sample.result); err != nil {
			t.Fatal(err)
		}
		if err := WriteHTML(filepath.Join(directory, "report.html"), sample.result); err != nil {
			t.Fatal(err)
		}
		t.Logf("%s written to %s", sample.name, directory)
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate the repository root")
	}
	return filepath.Dir(filepath.Dir(filepath.Dir(file)))
}

// largeSampleResult stresses pagination and the capped print scope: hundreds
// of distinct aggregated findings plus a large endpoint list.
func largeSampleResult() *model.Result {
	result := &model.Result{
		Target:     "https://large.example.com/app",
		Mode:       model.ModeAuto,
		UserAgent:  "JsOwl-Test",
		StartedAt:  time.Date(2026, 5, 4, 11, 0, 0, 0, time.Local),
		FinishedAt: time.Date(2026, 5, 4, 11, 6, 30, 0, time.Local),
	}
	rules := []struct {
		id, name, severity string
	}{
		{"hae.密钥凭证.通用敏感 Key-Value", "通用敏感 Key-Value", "critical"},
		{"hae.密钥凭证.云账号配置值", "云账号配置值", "high"},
		{"hae.PII.邮箱地址", "邮箱地址", "medium"},
		{"hae.网络信息.内网IP", "内网IP", "low"},
		{"hae.URL.完整 HTTP URL", "完整 HTTP URL", "info"},
	}
	for index := 0; index < 320; index++ {
		rule := rules[index%len(rules)]
		file := fmt.Sprintf("https://large.example.com/static/js/module-%02d.js", index%12)
		if index%5 == 0 {
			file = fmt.Sprintf("https://cdn.large.example.net/vendor-%02d.js", index%4)
		}
		// Every hit carries a distinct value, so each one is its own
		// aggregated finding and the print-scope cap becomes reachable.
		value := fmt.Sprintf("discovered-value-%03d", index)
		result.Findings = append(result.Findings, model.Finding{
			RuleID: rule.id, RuleName: rule.name,
			Category: model.RuleCategorySensitive, Severity: model.Severity(rule.severity),
			Value: value, SourceURL: file, Line: 10 + index, Column: 3 + index%20,
			ContextLines: []model.ContextLine{
				{LineNumber: 10 + index, Content: `  const config = { key: "` + value + `" };`, MatchStart: 22, MatchEnd: 22 + len(value)},
			},
		})
	}
	for index := 0; index < 140; index++ {
		result.Endpoints = append(result.Endpoints, model.Endpoint{
			Raw:        fmt.Sprintf("/api/v1/resource-%02d", index%20),
			URL:        fmt.Sprintf("https://large.example.com/api/v1/resource-%02d?page=%d", index%20, index%10),
			SourceURL:  "https://large.example.com/static/js/module-a.js",
			Authorized: true,
			Method:     []string{"GET", "POST", "PUT", "DELETE", "PATCH"}[index%5],
			Type:       "api", Source: "ast", Evidence: model.EvidenceFullURL, StatusCode: 200,
			BodyParams: []string{"id", "page"},
		})
	}
	result.Resources = append(result.Resources, model.Resource{
		URL:  "https://large.example.com/static/js/module-a.js",
		Type: model.ResourceTypeScript, StatusCode: 200, Size: 1024, LocalPath: "js/module-a.js",
	})
	result.Issues = append(result.Issues, model.Issue{
		Code: "body_truncated", Stage: "collect", URL: "https://large.example.com/static/js/module-b.js",
		Message: "body exceeds limits.max_body_size",
	})
	return result
}
