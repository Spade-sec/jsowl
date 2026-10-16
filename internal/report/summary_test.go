package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/youmulijiang/jsowl/internal/model"
)

func fixedClock() time.Time {
	return time.Date(2026, 5, 4, 10, 30, 0, 0, time.UTC)
}

// sampleAggregateResult exercises every aggregate dimension at once: repeated
// hits, several severities, several hosts, an unresolved relative path, a
// method-less endpoint, AI output and diagnostics.
func sampleAggregateResult() *model.Result {
	return &model.Result{
		Target:     "https://shop.example.com/app?from=scan",
		Mode:       model.ModeAuto,
		UserAgent:  "JsOwl-Test",
		StartedAt:  fixedClock().Add(-90 * time.Second),
		FinishedAt: fixedClock(),
		BrowserStatus: model.BrowserStatus{
			Attempted: true, Used: true,
		},
		Resources: []model.Resource{
			{URL: "https://shop.example.com/app.js", Type: model.ResourceTypeScript, StatusCode: 200, Size: 120, LocalPath: "js/app.js"},
			{URL: "https://shop.example.com/chunks/users.js", Type: model.ResourceTypeChunk, StatusCode: 200, Size: 80, LocalPath: "js/chunks/users.js"},
			{URL: "https://cdn.partner.net/vendor.js", Type: model.ResourceTypeExternal, StatusCode: 404},
		},
		Endpoints: []model.Endpoint{
			{Raw: "/api/users", URL: "https://shop.example.com/api/users", SourceURL: "https://shop.example.com/app.js", Authorized: true, Method: "GET", Type: "api", StatusCode: 200},
			{Raw: "/api/users", URL: "https://shop.example.com/api/users?id=1", SourceURL: "https://shop.example.com/app.js", Authorized: true, Method: "POST", Type: "api", StatusCode: 200, BodyParams: []string{"id"}},
			{Raw: "/api/orders", URL: "https://shop.example.com/api/orders", SourceURL: "https://shop.example.com/app.js", Authorized: true, Method: "DELETE", Type: "api", StatusCode: 403},
			{Raw: "v1/report", URL: "v1/report?page=2", SourceURL: "https://shop.example.com/app.js", Authorized: false, Type: "api"},
			{Raw: "https://api.partner.net/v2/orders", URL: "https://api.partner.net/v2/orders", SourceURL: "https://cdn.partner.net/vendor.js", Authorized: false, Method: "GET", Evidence: model.EvidenceFullURL, Type: "api", StatusCode: 200},
			{Raw: "/admin", URL: "https://shop.example.com/admin", SourceURL: "https://shop.example.com/app.js", Type: "route", Source: "cdp-runtime", Evidence: model.EvidenceRuntime, Probe: "server"},
			{Raw: "/user/:userId", URL: "https://shop.example.com/user/:userId", SourceURL: "https://shop.example.com/app.js", Type: "route", Source: "ast"},
		},
		Findings: []model.Finding{
			{
				RuleID: "hae.密钥凭证.阿里云 Access Key", RuleName: "阿里云 Access Key",
				Category: model.RuleCategorySensitive, Severity: model.SeverityCritical,
				Value: "LTAI5tSecretValue", SourceURL: "https://shop.example.com/app.js",
				Line: 12, Column: 18,
				ContextLines: []model.ContextLine{
					{LineNumber: 12, Content: `const ak = "LTAI5tSecretValue"`, MatchStart: 11, MatchEnd: 30},
				},
				AI: &model.AIAssessment{Rating: "high", Reason: "符合阿里云 AK 格式", Suggestion: "试 OSS 列举"},
			},
			{
				// Same rule, same value, different location: one aggregated
				// finding with two sources and two hits.
				RuleID: "hae.密钥凭证.阿里云 Access Key", RuleName: "阿里云 Access Key",
				Category: model.RuleCategorySensitive, Severity: model.SeverityCritical,
				Value: "LTAI5tSecretValue", SourceURL: "https://shop.example.com/chunks/users.js",
				Line: 3, Column: 4,
			},
			{
				// Same rule, different value: must stay a separate finding.
				RuleID: "hae.密钥凭证.阿里云 Access Key", RuleName: "阿里云 Access Key",
				Category: model.RuleCategorySensitive, Severity: model.SeverityCritical,
				Value: "LTAI5tOtherValue", SourceURL: "https://shop.example.com/app.js",
				Line: 90, Column: 2,
			},
			{
				// Same rule and value as the first, lower severity: must not merge.
				RuleID: "hae.密钥凭证.阿里云 Access Key", RuleName: "阿里云 Access Key",
				Category: model.RuleCategorySensitive, Severity: model.SeverityMedium,
				Value: "LTAI5tSecretValue", SourceURL: "https://shop.example.com/app.js",
				Line: 140, Column: 7,
			},
			{
				RuleID: "hae.PII.邮箱地址", RuleName: "邮箱地址",
				Category: model.RuleCategorySensitive, Severity: model.SeverityMedium,
				Value: "ops@example.com", SourceURL: "https://cdn.partner.net/vendor.js",
				Line: 51, Column: 9, Vendor: true,
			},
			{
				RuleID: "hae.网络信息.内网IP", RuleName: "内网IP",
				Category: model.RuleCategorySensitive, Severity: model.SeverityLow,
				Value: "10.0.0.12", SourceURL: "https://shop.example.com/app.js",
				Line: 20, Column: 3,
			},
			{
				RuleID: "hae.URL.完整 HTTP URL", RuleName: "完整 HTTP URL",
				Category: model.RuleCategoryURL, Severity: model.SeverityInfo,
				Value: "https://shop.example.com/api/users?id=1", SourceURL: "https://shop.example.com/app.js",
				Line: 60, Column: 11,
			},
		},
		Params: []model.ParamHit{
			{Name: "userId", Scenario: model.ParamScenarioFunctionParam, SourceURL: "https://shop.example.com/app.js", Line: 30},
			{Name: "id", Scenario: model.ParamScenarioAPIRequest, SourceURL: "https://shop.example.com/app.js", Line: 12},
		},
		Issues: []model.Issue{
			{Code: "resource_get_failed", Stage: "collect", URL: "https://cdn.partner.net/vendor.js", Message: "timeout", Retryable: true},
			{Code: "js_analysis_failed", Stage: "analyze", URL: "https://shop.example.com/app.js", Message: "parse error"},
		},
	}
}

func TestAggregateFindingsUnitsAndKeys(t *testing.T) {
	summary := buildSummary(sampleAggregateResult(), fixedClock())

	if len(summary.Groups) != 6 {
		t.Fatalf("expected 6 aggregated findings, got %d", len(summary.Groups))
	}
	if summary.GroupHits != 7 {
		t.Fatalf("expected 7 raw hits, got %d", summary.GroupHits)
	}

	first := summary.Groups[0]
	if first.Severity != string(model.SeverityCritical) {
		t.Fatalf("aggregation must order by severity first, got %q", first.Severity)
	}
	if first.Hits != 2 {
		// The identical critical hits merge; the same value at medium severity
		// must not, so the critical group carries exactly two hits.
		t.Fatalf("critical group hits = %d, want 2 (the medium hit must not merge)", first.Hits)
	}
	if len(first.Sources) != first.Hits {
		t.Fatalf("every raw hit must keep its own source entry: %d sources for %d hits", len(first.Sources), first.Hits)
	}
	if first.ID != "G001" {
		t.Fatalf("first group id = %q", first.ID)
	}
	if first.AI == nil || first.AICount != 1 {
		t.Fatalf("AI assessment must survive aggregation: %#v", first.AI)
	}
	if first.Confirmation != "待人工验证" {
		t.Fatalf("confirmation must stay 待人工验证, got %q", first.Confirmation)
	}
	if first.Verify == "" {
		t.Fatal("every aggregated finding needs a manual verification hint")
	}

	// Distinct values, severities and rules never merge.
	seen := map[string]int{}
	for _, group := range summary.Groups {
		key := group.RuleID + "|" + group.Severity + "|" + group.Value
		seen[key]++
	}
	if seen["hae.密钥凭证.阿里云 Access Key|critical|LTAI5tSecretValue"] != 1 {
		t.Fatal("same rule+severity+value must be a single aggregated finding")
	}
	if seen["hae.密钥凭证.阿里云 Access Key|medium|LTAI5tSecretValue"] != 1 {
		t.Fatal("a different severity must not merge into the same finding")
	}
	if seen["hae.密钥凭证.阿里云 Access Key|critical|LTAI5tOtherValue"] != 1 {
		t.Fatal("a different value must not merge into the same finding")
	}

	// IDs are a stable function of the result: rebuilding yields the same ids.
	again := buildSummary(sampleAggregateResult(), fixedClock().Add(time.Hour))
	for index, group := range again.Groups {
		if group.ID != summary.Groups[index].ID {
			t.Fatalf("group ids are not stable: %q vs %q", group.ID, summary.Groups[index].ID)
		}
	}
}

func TestSummarySeverityMetricsDistinguishUnits(t *testing.T) {
	summary := buildSummary(sampleAggregateResult(), fixedClock())
	byKey := map[string]severityMetric{}
	for _, row := range summary.SeverityMetrics {
		byKey[row.Severity] = row
	}
	if byKey["critical"].Groups != 2 || byKey["critical"].Hits != 3 {
		t.Fatalf("critical row = %#v, want 2 groups / 3 hits", byKey["critical"])
	}
	if byKey["medium"].Groups != 2 || byKey["medium"].Hits != 2 {
		t.Fatalf("medium row = %#v", byKey["medium"])
	}
	if byKey["info"].Groups != 1 || byKey["info"].Hits != 1 {
		t.Fatalf("info row = %#v", byKey["info"])
	}
	if summary.FindingTotal.Value != 6 || summary.FindingTotal.Sub != 7 {
		t.Fatalf("finding total = %#v, want 6 aggregated / 7 raw", summary.FindingTotal)
	}
	if summary.Key == nil {
		t.Fatal("key findings must be a slice, never nil, so the page can render an empty state")
	}
}

func TestSummaryDomainAndMethodBuckets(t *testing.T) {
	summary := buildSummary(sampleAggregateResult(), fixedClock())

	var found bool
	for _, metric := range summary.AttackMetrics {
		if metric.Key != "domains" {
			continue
		}
		found = true
		// shop.example.com, api.partner.net, cdn.partner.net: the union of
		// hosts seen on endpoints, resources and finding sources. The
		// unresolved relative path is not a domain and is not counted.
		if metric.Value != 3 {
			t.Fatalf("domain metric = %d, want 3 (unresolved host excluded)", metric.Value)
		}
		if metric.Value < 0 || metric.Sub > metric.Value {
			t.Fatalf("endpoint-host subset cannot exceed the total host count: %#v", metric)
		}
	}
	if !found {
		t.Fatal("domain metric missing")
	}

	var unresolved *domainBucket
	for index := range summary.Domains {
		if summary.Domains[index].Host == unresolvedHost {
			unresolved = &summary.Domains[index]
		}
	}
	if unresolved == nil {
		t.Fatal("the relative endpoint must land in the unresolved-host bucket")
	}
	if unresolved.Endpoints != 1 {
		t.Fatalf("unresolved bucket endpoints = %d, want 1", unresolved.Endpoints)
	}
	// The bucket counts endpoint records, exactly like the endpoint list the
	// chart drills into, so the chart and the filtered table always agree.
	for _, domain := range summary.Domains {
		if domain.Host == "shop.example.com" && domain.Endpoints != 3 {
			t.Fatalf("shop.example.com endpoints = %d, want 3", domain.Endpoints)
		}
	}

	methods := map[string]int{}
	for _, bucket := range summary.Methods {
		methods[bucket.Key] = bucket.Count
	}
	if methods[unresolvedMethod] != 1 {
		t.Fatalf("method-less endpoint must be counted as 未知, got %#v", methods)
	}
	if _, assumed := methods["GET"]; !assumed {
		t.Fatal("GET must only appear for endpoints that actually declared it")
	}
	if methods["GET"] != 2 {
		t.Fatalf("GET count = %d, want 2 (declared methods only)", methods["GET"])
	}
}

func TestSummaryHandlesEmptyAndMissingFields(t *testing.T) {
	summary := buildSummary(&model.Result{Target: "https://empty.test"}, fixedClock())
	if summary.Groups == nil || len(summary.Groups) != 0 {
		t.Fatalf("empty result must produce an empty (non-nil) group list: %#v", summary.Groups)
	}
	if summary.Key == nil {
		t.Fatal("empty result must still carry an empty key list")
	}
	if summary.HasScanTime {
		t.Fatal("a result without timestamps must not claim scan times")
	}
	if summary.StartedAt != "" || summary.FinishedAt != "" || summary.Duration != "" {
		t.Fatalf("no timestamp may be invented: %#v", summary)
	}
	if summary.GeneratedAt == "" {
		t.Fatal("report generation time must be present and labelled as such")
	}
	for _, row := range summary.SeverityMetrics {
		if row.Groups != 0 || row.Hits != 0 {
			t.Fatalf("empty result severity row = %#v", row)
		}
	}
	if summary.Resources.Notes == nil {
		t.Fatal("resource notes must be present so the page can explain the counting rule")
	}

	// Missing fields inside a record must not panic and must be labelled.
	sparse := buildSummary(&model.Result{
		Target:    "https://sparse.test",
		Findings:  []model.Finding{{RuleID: "team.custom.rule", Value: "abc"}},
		Endpoints: []model.Endpoint{{Raw: "/x"}},
	}, fixedClock())
	if len(sparse.Groups) != 1 {
		t.Fatalf("sparse finding dropped: %#v", sparse.Groups)
	}
	if sparse.Groups[0].SeverityLabel != "未知" {
		t.Fatalf("unknown severity must be labelled 未知, got %q", sparse.Groups[0].SeverityLabel)
	}
	if sparse.Groups[0].Verify == "" {
		t.Fatal("a custom rule still needs a verification hint")
	}
	if sparse.Groups[0].CategoryLabel != "未分类" {
		t.Fatalf("empty category label = %q", sparse.Groups[0].CategoryLabel)
	}
}

func TestSummaryUnknownSeverityGetsItsOwnRow(t *testing.T) {
	summary := buildSummary(&model.Result{
		Target: "https://x.test",
		Findings: []model.Finding{{
			RuleID: "team.custom.rule", RuleName: "custom", Severity: "urgent", Value: "v",
		}},
	}, fixedClock())
	var unknown *severityMetric
	for index := range summary.SeverityMetrics {
		if summary.SeverityMetrics[index].Severity == "unknown" {
			unknown = &summary.SeverityMetrics[index]
		}
	}
	if unknown == nil || unknown.Groups != 1 || unknown.Hits != 1 {
		t.Fatalf("unrecognized severity must be reported on its own row: %#v", summary.SeverityMetrics)
	}
	// It must sort last, never above a known level.
	if last := summary.SeverityMetrics[len(summary.SeverityMetrics)-1]; last.Severity != "unknown" {
		t.Fatalf("unknown severity must sort after info, got %q", last.Severity)
	}
}

func TestSummaryResourceAndIssueBucketsAreProvable(t *testing.T) {
	summary := buildSummary(sampleAggregateResult(), fixedClock())
	if summary.Resources.Total != 3 || summary.Resources.Saved != 2 {
		t.Fatalf("resource summary = %#v", summary.Resources)
	}
	status := map[string]int{}
	for _, bucket := range summary.Resources.Status {
		status[bucket.Key] = bucket.Count
	}
	if status["200"] != 2 || status["404"] != 1 {
		t.Fatalf("status buckets = %#v", status)
	}
	notes := strings.Join(summary.Resources.Notes, " ")
	if !strings.Contains(notes, "解析成功率") {
		t.Fatal("the report must state why no parse-success rate is computed")
	}
	codes := map[string]string{}
	for _, bucket := range summary.Issues.Codes {
		codes[bucket.Key] = bucket.Label
	}
	if codes["resource_get_failed"] != "资源获取失败" {
		t.Fatalf("issue code labels = %#v", codes)
	}
	if summary.Issues.Total != 2 || summary.Issues.Retryable != 1 {
		t.Fatalf("issue summary = %#v", summary.Issues)
	}
}

func TestSummaryParameterNamesMatchTextReport(t *testing.T) {
	result := sampleAggregateResult()
	summary := buildSummary(result, fixedClock())

	directory := t.TempDir()
	if err := WriteTextReports(directory, result); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(directory, "参数.txt"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Fields(strings.TrimSpace(string(data)))
	if len(lines) != len(summary.Params) {
		t.Fatalf("参数.txt has %d names, summary has %d", len(lines), len(summary.Params))
	}
	for index, name := range lines {
		if summary.Params[index] != name {
			t.Fatalf("参数.txt and the summary disagree at %d: %q vs %q", index, name, summary.Params[index])
		}
	}
}

func TestWriteHTMLDashboardEmbedsSummaryAndPrintView(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.html")
	result := sampleAggregateResult()
	if err := writeHTMLReport(path, result, fixedClock()); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	page := string(data)
	for _, want := range []string{
		// Dashboard surfaces
		"id=\"attack-metrics\"", "id=\"security-metrics\"", "id=\"severity-chart\"",
		"id=\"type-chart\"", "id=\"domain-chart\"", "id=\"method-chart\"", "id=\"key-findings\"",
		// Workbench
		"id=\"findings-body\"", "id=\"findings-table\"", "id=\"findings-pagination\"",
		"id=\"category\"", "id=\"findings-export\"", "id=\"endpoints-export\"",
		// Tree panel and attachments
		"id=\"tree-panel\"", "API报告.html", "敏感信息报告.html", "url.txt",
		// Print view
		"id=\"print-doc\"", "id=\"print-button\"", "id=\"print-scope\"",
		// Aggregated data actually shipped
		"\"attackMetrics\"", "\"severityMetrics\"", "G001", "待人工验证", "阿里云 Access Key",
		// Counting rules are stated on the page
		"聚合发现", "原始命中", "唯一端点",
		// Automation boundary statement
		"未给出 CVSS 评分", "不代替人工测试", "本报告不构成完整的渗透测试结论",
		// Script modules
		"function bindReportSort(", "JsOwlCharts", "JsOwlCSV",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("report missing %q", want)
		}
	}
	if strings.Contains(page, "{{") {
		t.Error("template placeholders left unrendered")
	}
}

func TestWriteHTMLKeepsScanControlledTextInert(t *testing.T) {
	payload := `</script><script>alert(1)</script>`
	result := &model.Result{
		Target: "https://evil.test/" + payload,
		Findings: []model.Finding{{
			RuleID: "hae.PII.邮箱地址", RuleName: "邮箱地址" + payload,
			Category: model.RuleCategorySensitive, Severity: model.SeverityHigh,
			Value:     "value" + payload,
			SourceURL: "javascript:alert(1)",
			Line:      1, Column: 1,
			AI: &model.AIAssessment{Rating: "high", Reason: "reason" + payload, Suggestion: "s" + payload},
		}},
		Endpoints: []model.Endpoint{{
			Raw: "/x", URL: "javascript:alert(2)", SourceURL: payload,
		}},
	}
	path := filepath.Join(t.TempDir(), "report.html")
	if err := writeHTMLReport(path, result, fixedClock()); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	page := string(data)
	if strings.Contains(page, "<script>alert(1)</script>") || strings.Contains(page, "<script>alert(2)</script>") {
		t.Fatal("scan-controlled text broke out of its context")
	}
	if !strings.Contains(page, `\u003c/script\u003e`) {
		t.Fatal("the embedded JSON must escape </script> as \\u003c/script\\u003e")
	}
	// The page must not link javascript: URLs directly: links are built in
	// JS through safeHref, and the raw value stays escaped text or JSON.
	if strings.Contains(page, `href="javascript:`) {
		t.Fatal("a javascript: URL was rendered as a link")
	}
	if !strings.Contains(page, "function safeHref(") {
		t.Fatal("the report must ship the URL scheme guard")
	}
}

func TestSummaryJSONRoundTripsThroughThePage(t *testing.T) {
	// The page receives the summary as JSON; the shape must stay decodable so
	// a future reader (or a test harness) can rely on it.
	raw, err := json.Marshal(buildSummary(sampleAggregateResult(), fixedClock()))
	if err != nil {
		t.Fatal(err)
	}
	var decoded reportSummary
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Groups) != 6 || decoded.FindingTotal.Value != 6 {
		t.Fatalf("decoded summary = %#v", decoded)
	}
}

func TestSummaryKeepsRawValueSoExportGuardsStayInTheExport(t *testing.T) {
	// The spreadsheet formula guard belongs to the CSV export path only. The
	// embedded report data must keep the exact matched value, otherwise the
	// report itself would be silently altered.
	const formula = `=cmd|'/c calc'!A0`
	result := &model.Result{
		Target: "https://x.test",
		Findings: []model.Finding{{
			RuleID: "hae.URL.完整 HTTP URL", RuleName: "完整 HTTP URL",
			Category: model.RuleCategoryURL, Severity: model.SeverityInfo, Value: formula,
		}},
	}
	summary := buildSummary(result, fixedClock())
	if summary.Groups[0].Value != formula {
		t.Fatalf("summary value was altered: %q", summary.Groups[0].Value)
	}

	path := filepath.Join(t.TempDir(), "report.html")
	if err := writeHTMLReport(path, result, fixedClock()); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	page := string(data)
	if !strings.Contains(page, formula) {
		t.Fatal("the report must carry the unmodified matched value")
	}
	if strings.Contains(page, `"'=cmd`) {
		t.Fatal("the CSV formula guard leaked into the report data")
	}
}
