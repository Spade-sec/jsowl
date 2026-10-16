package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/youmulijiang/jsowl/internal/model"
)

func TestWriteJSONRoundTripsResult(t *testing.T) {
	result := sampleResult()
	path := filepath.Join(t.TempDir(), "nested", "report.json")
	if err := WriteJSON(path, result); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var decoded model.Result
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Target != result.Target ||
		decoded.Findings[0].Value != result.Findings[0].Value {
		t.Fatalf("decoded result = %#v", decoded)
	}
	result.Target = "https://updated.example.test"
	if err := WriteJSON(path, result); err != nil {
		t.Fatalf("overwrite JSON report: %v", err)
	}
	data, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Target != result.Target {
		t.Fatalf("overwritten target = %q", decoded.Target)
	}
}

func TestWriteHTMLContainsSecurityDataAndEscapesTargetContent(t *testing.T) {
	result := sampleResult()
	result.Target = `https://example.test/?q=<script>alert(1)</script>`
	path := filepath.Join(t.TempDir(), "report.html")
	if err := WriteHTML(path, result); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	html := string(data)
	for _, want := range []string{
		"敏感数据，请妥善保管",
		"super-secret-token",
		"https://example.test/api/users",
		"&lt;script&gt;alert(1)&lt;/script&gt;",
		"target: \"https://example.test/?q=\\u003cscript\\u003ealert(1)\\u003c/script\\u003e\"",
		"ContextLine",
		"match_start",
		"tree-panel",
		"findings-body",
		"pagination",
		"503",
		"chrome missing",
		"id=\"category\"",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("HTML report does not contain %q", want)
		}
	}
	if strings.Contains(html, "<script>alert(1)</script>") {
		t.Fatal("target-controlled HTML was not escaped")
	}
	if strings.Contains(html, `{"entire":"response body"}`) {
		t.Fatal("HTML report unexpectedly contains a stored response body")
	}
}

func sampleResult() *model.Result {
	return &model.Result{
		Target:    "https://example.test",
		Mode:      model.ModeAuto,
		UserAgent: "JsOwl-Test",
		BrowserStatus: model.BrowserStatus{
			Attempted: true, Degraded: true, Reason: "chrome missing",
		},
		Resources: []model.Resource{{
			URL: "https://example.test/app.js", Type: model.ResourceTypeScript,
			StatusCode: 200, ContentType: "application/javascript", Size: 100,
		}},
		Endpoints: []model.Endpoint{{
			Raw: "/api/users", URL: "https://example.test/api/users",
			SourceURL: "https://example.test/app.js", Authorized: true,
			StatusCode: 503,
		}},
		Findings: []model.Finding{{
			RuleID: "secret.credential", RuleName: "Credential",
			Category: model.RuleCategorySensitive, Severity: model.SeverityHigh,
			Value: "super-secret-token", SourceURL: "https://example.test/app.js",
			Line: 4, Column: 15,
			ContextLines: []model.ContextLine{
				{LineNumber: 1, Content: "const ready = true", MatchStart: -1, MatchEnd: -1},
				{LineNumber: 2, Content: "// credentials", MatchStart: -1, MatchEnd: -1},
				{LineNumber: 3, Content: "function boot() {", MatchStart: -1, MatchEnd: -1},
				{LineNumber: 4, Content: "const token = super-secret-token", MatchStart: 14, MatchEnd: 32},
				{LineNumber: 5, Content: "}", MatchStart: -1, MatchEnd: -1},
				{LineNumber: 6, Content: "boot()", MatchStart: -1, MatchEnd: -1},
				{LineNumber: 7, Content: "// end", MatchStart: -1, MatchEnd: -1},
			},
		}},
		Issues: []model.Issue{{
			Code: "fixture", Stage: "test",
			Message: "fixture issue",
		}},
		Statistics: model.Statistics{
			Resources: 1, Scripts: 1, Endpoints: 1, Findings: 1,
		},
	}
}

func TestWriteTextReportsWritesAPIPathsParametersAndSensitive(t *testing.T) {
	result := sampleResult()
	result.Endpoints = append(result.Endpoints, model.Endpoint{
		Raw: "/api/users", URL: "https://example.test/api/users?id=42&tab=profile",
		SourceURL: "https://example.test/app.js", Authorized: true, StatusCode: 200,
	})
	result.Endpoints = append(result.Endpoints, model.Endpoint{
		Raw: "./v2/orders?expand=1", URL: "https://example.test/v2/orders?expand=1",
		SourceURL: "https://example.test/app.js", Authorized: true, StatusCode: 200,
	})
	result.Endpoints = append(result.Endpoints, model.Endpoint{
		Raw: "https://api.partner.test/v2/orders", URL: "https://api.partner.test/v2/orders",
		SourceURL: "https://example.test/app.js", Authorized: false,
		Method: "GET", Evidence: model.EvidenceFullURL,
	})
	directory := t.TempDir()
	if err := WriteTextReports(directory, result); err != nil {
		t.Fatal(err)
	}

	absoluteData, err := os.ReadFile(filepath.Join(directory, "api绝对路径.txt"))
	if err != nil {
		t.Fatal(err)
	}
	absolute := string(absoluteData)
	// The absolute list mirrors the API report: the reference exactly as
	// written in the source, not the folded resolved URL.
	if !strings.Contains(absolute, "/api/users\n") {
		t.Fatalf("absolute api report missing /api/users: %q", absolute)
	}
	if strings.Contains(absolute, "?id=42") {
		t.Fatalf("absolute api report must use the source reference: %q", absolute)
	}
	if strings.Contains(absolute, "https://example.test/api/users") {
		t.Fatalf("absolute api report must not contain folded full URLs: %q", absolute)
	}
	if strings.Contains(absolute, "https://api.partner.test") {
		t.Fatalf("absolute api report must exclude full URLs: %q", absolute)
	}

	urlData, err := os.ReadFile(filepath.Join(directory, "url.txt"))
	if err != nil {
		t.Fatal(err)
	}
	urlList := string(urlData)
	if !strings.Contains(urlList, "https://api.partner.test/v2/orders\n") {
		t.Fatalf("url.txt missing full URL: %q", urlList)
	}

	relativeData, err := os.ReadFile(filepath.Join(directory, "api相对路径.txt"))
	if err != nil {
		t.Fatal(err)
	}
	relative := string(relativeData)
	if !strings.Contains(relative, "./v2/orders?expand=1\n") {
		t.Fatalf("relative api report missing endpoint: %q", relative)
	}

	paramData, err := os.ReadFile(filepath.Join(directory, "参数.txt"))
	if err != nil {
		t.Fatal(err)
	}
	params := string(paramData)
	for _, want := range []string{"id\n", "tab\n", "expand\n"} {
		if !strings.Contains(params, want) {
			t.Fatalf("parameter report missing %q: %q", want, params)
		}
	}
	for _, unwanted := range []string{"id=42", "\t", "http"} {
		if strings.Contains(params, unwanted) {
			t.Fatalf("parameter report must be bare names, found %q: %q", unwanted, params)
		}
	}

	sensitiveData, err := os.ReadFile(filepath.Join(directory, "敏感信息.txt"))
	if err != nil {
		t.Fatal(err)
	}
	sensitive := string(sensitiveData)
	for _, want := range []string{"[high]", "Credential", "super-secret-token", "app.js:4:15"} {
		if !strings.Contains(sensitive, want) {
			t.Fatalf("sensitive report missing %q: %q", want, sensitive)
		}
	}
}

func TestWriteTextReportsHandlesEmptyResult(t *testing.T) {
	result := &model.Result{Target: "https://empty.test"}
	directory := t.TempDir()
	if err := WriteTextReports(directory, result); err != nil {
		t.Fatal(err)
	}
	sensitive, err := os.ReadFile(filepath.Join(directory, "敏感信息.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(sensitive), "（未发现敏感信息）") {
		t.Fatalf("empty sensitive report = %q", sensitive)
	}
	params, err := os.ReadFile(filepath.Join(directory, "参数.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if len(params) != 0 {
		t.Fatalf("empty parameter report should be empty, got %q", params)
	}
}

func TestWriteSplitReportsGeneratesTopicPages(t *testing.T) {
	result := sampleResult()
	result.Endpoints = append(result.Endpoints, model.Endpoint{
		Raw: "/api/users?id=1", URL: "https://example.test/api/users?id=1",
		SourceURL: "https://example.test/app.js", Authorized: true,
		Method: "POST", Evidence: model.EvidenceRuntime,
	})
	directory := t.TempDir()
	if err := WriteSplitReports(directory, result); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"API报告.html", "敏感信息报告.html", "参数报告.html", "资源报告.html", "URL报告.html",
	} {
		data, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if !strings.Contains(string(data), "https://example.test") {
			t.Fatalf("%s missing target", name)
		}
	}
	if _, err := os.Stat(filepath.Join(directory, "报告导航.html")); !os.IsNotExist(err) {
		t.Fatalf("报告导航.html should no longer be written: %v", err)
	}
	result.Endpoints = append(result.Endpoints, model.Endpoint{
		Raw: "/search", URL: "https://example.test/search?q=hello",
		SourceURL: "https://example.test/app.js", Authorized: true,
	})
	result.Endpoints = append(result.Endpoints, model.Endpoint{
		Raw: "https://api.partner.test/v2/orders", URL: "https://api.partner.test/v2/orders",
		SourceURL: "https://example.test/app.js", Authorized: false,
		Method: "GET", Evidence: model.EvidenceFullURL,
	})
	result.Endpoints = append(result.Endpoints, model.Endpoint{
		Raw: "/admin", URL: "https://example.test/admin",
		SourceURL: "https://example.test/app.js", Authorized: false,
		Type: "route", Source: "cdp-runtime", Evidence: model.EvidenceRuntime,
		Probe: "server",
	})
	result.Findings[0].SourceURL = "https://example.test/app.js"
	for index := range result.Endpoints {
		if result.Endpoints[index].Raw == "/api/users?id=1" {
			result.Endpoints[index].Line = 42
			result.Endpoints[index].Column = 9
			result.Endpoints[index].ContextLines = []model.ContextLine{
				{LineNumber: 41, Content: "const api = client;", MatchStart: -1, MatchEnd: -1},
				{LineNumber: 42, Content: "client.post(\"/api/users\", body)", MatchStart: 0, MatchEnd: 31},
			}
		}
	}
	if err := WriteSplitReports(directory, result); err != nil {
		t.Fatal(err)
	}
	if err := WriteTextReports(directory, result); err != nil {
		t.Fatal(err)
	}
	api, _ := os.ReadFile(filepath.Join(directory, "API报告.html"))
	for _, want := range []string{
		"POST", "runtime", "/api/users?id=1", // raw path kept, not folded
		"绝对路径", "相对路径", // grouped by path kind
		"复制", "data-copy=\"/api/users?id=1\"", // one-click copy
		"app.js:42:9", "上下文", "client.post(", "const api = client;",
		// Coordinates are authoritative now: the whole matched region is
		// wrapped, quotes included.
		`<mark>client.post(&quot;/api/users&quot;, body)</mark>`, // match region highlighted
	} {
		if !strings.Contains(string(api), want) {
			t.Fatalf("API report missing %q", want)
		}
	}
	// Full URLs moved out of the API report into the URL report.
	for _, unwanted := range []string{
		`https://example.test/api/users?id=1`,
		`data-copy="https://api.partner.test/v2/orders"`,
	} {
		if strings.Contains(string(api), unwanted) {
			t.Fatalf("API report should not contain %q", unwanted)
		}
	}
	urlReport, err := os.ReadFile(filepath.Join(directory, "URL报告.html"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"https://api.partner.test/v2/orders", "data-page-size"} {
		if !strings.Contains(string(urlReport), want) {
			t.Fatalf("URL report missing %q", want)
		}
	}
	routes, err := os.ReadFile(filepath.Join(directory, "路由报告.html"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"https://example.test/admin", "CDP 运行时", "服务端真实页面", "路由路径",
	} {
		if !strings.Contains(string(routes), want) {
			t.Fatalf("route report missing %q", want)
		}
	}
	routeTxt, err := os.ReadFile(filepath.Join(directory, "路由.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(routeTxt), "https://example.test/admin	[server]") {
		t.Fatalf("route txt = %q", routeTxt)
	}
	params, _ := os.ReadFile(filepath.Join(directory, "参数报告.html"))
	for _, want := range []string{
		"提取方式", "域名", "次数", "host-filter", "data-hosts", "ast", "regex",
	} {
		if !strings.Contains(string(params), want) {
			t.Fatalf("parameter report missing %q", want)
		}
	}
	// Merged navigation: every split page links back to report.html and to
	// its siblings; no standalone navigation page exists.
	for _, name := range []string{"API报告.html", "路由报告.html"} {
		page, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"report.html", "API 端点报告", "敏感信息报告"} {
			if !strings.Contains(string(page), want) {
				t.Fatalf("%s nav missing %q", name, want)
			}
		}
	}
	if err := WriteHTML(filepath.Join(directory, "report.html"), result); err != nil {
		t.Fatal(err)
	}
	main, err := os.ReadFile(filepath.Join(directory, "report.html"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"API报告.html", "URL报告.html", "敏感信息报告.html", "参数报告.html",
		"路由报告.html", "资源报告.html", "url.txt", "api绝对路径.txt",
	} {
		if !strings.Contains(string(main), want) {
			t.Fatalf("main report nav missing %q", want)
		}
	}
}

func TestAPIReportDetailPanel(t *testing.T) {
	result := sampleResult()
	result.Endpoints = append(result.Endpoints, model.Endpoint{
		Raw: "/api/login", URL: "https://example.test/api/login",
		SourceURL: "https://example.test/app.js", Method: "POST",
		Line: 88, Column: 3,
		ContextLines: []model.ContextLine{
			{LineNumber: 88, Content: `axios.post("/api/login", {user: "admin"})`, MatchStart: 0, MatchEnd: 12},
		},
		Spec: &model.RequestSpec{
			BaseURL:             "https://api.example.test",
			BaseURLKind:         model.EvidenceLiteral,
			ContentType:         "application/json",
			ContentTypeEvidence: model.EvidenceInferred,
			Query: []model.Param{
				{Key: "page", Value: "1", Evidence: model.EvidenceLiteral},
				{Key: "kw", Value: "{kw}", Evidence: model.EvidencePlaceholder},
			},
			Body: []model.Param{
				{Key: "user", Value: "admin", Evidence: model.EvidenceLiteral},
			},
		},
	})
	// A bare endpoint without spec or context renders no detail panel.
	result.Endpoints = append(result.Endpoints, model.Endpoint{
		Raw: "/bare", URL: "https://example.test/bare", Type: "api",
	})
	directory := t.TempDir()
	if err := WriteSplitReports(directory, result); err != nil {
		t.Fatal(err)
	}
	api, err := os.ReadFile(filepath.Join(directory, "API报告.html"))
	if err != nil {
		t.Fatal(err)
	}
	page := string(api)
	for _, want := range []string{
		`class="api-row"`, // row is the toggle now
		"RequestSpec",     // spec section in the panel
		"BaseURL",         // base URL surfaced
		"字面量",             // literal evidence label
		"动态占位",            // placeholder evidence label
		"推断",              // inferred evidence label
		"来源定位",            // source location section
		"app.js:88:3",     // exact JS position
		"匹配上下文",           // context section inside the panel
		"数字",              // query value typed as number
		"字符串",             // body value typed as string
	} {
		if !strings.Contains(page, want) {
			t.Fatalf("API report detail panel missing %q", want)
		}
	}
	if strings.Contains(page, `ctx-toggle`) {
		t.Fatalf("context toggle button should be removed")
	}
	if strings.Contains(strings.SplitN(page, `/bare`, 2)[1], `class="api-row"`) &&
		!strings.Contains(strings.SplitN(page, `/api/login`, 2)[1], `class="api-row"`) {
		// /bare has no detail: it must not be clickable. The login row must be.
		t.Fatalf("row toggle classes wrong")
	}
}

func TestHighlightFragmentsHighlightsEveryOccurrence(t *testing.T) {
	content := `{"path":"/ContentManagement","component":"Layout","redirect":"/ContentManagement/ReleaseManagement"}`
	got, markedAny := highlightFragments(content, []string{"/ContentManagement"})
	if !markedAny {
		t.Fatal("expected the fragment to be marked")
	}
	marked := strings.Count(got, "<mark>")
	if marked != 2 {
		t.Fatalf("expected 2 marks for repeated fragment, got %d: %s", marked, got)
	}
	// The longer fragment must not leave a nested or partial mark behind.
	got, _ = highlightFragments(content, []string{"/ContentManagement", "ReleaseManagement"})
	if strings.Count(got, "<mark>") != 3 {
		t.Fatalf("expected 3 marks with overlapping fragments, got: %s", got)
	}
	if strings.Contains(got, "mark><mark") || strings.Contains(got, "</mark></mark>") {
		t.Fatalf("marks must never nest: %s", got)
	}
}

// TestParameterReportMarksScenarios checks the parameter report renders the
// extraction-scenario badges for code-shape hits and keeps URL-derived rows.
func TestParameterReportMarksScenarios(t *testing.T) {
	result := sampleResult()
	result.Params = []model.ParamHit{
		{
			Name: "userId", Scenario: model.ParamScenarioObjectProperty,
			Value: "123", Evidence: model.EvidenceLiteral,
			SourceURL: "https://example.test/app.js", Line: 7, Column: 15,
			ContextLines: []model.ContextLine{
				{LineNumber: 7, Content: "const user = { userId: 123 };", MatchStart: 13, MatchEnd: 19},
			},
		},
		{
			Name: "apiKey", Scenario: model.ParamScenarioVariable,
			Value: "xxx", SourceURL: "https://example.test/app.js", Line: 9,
		},
	}
	result.Endpoints = append(result.Endpoints, model.Endpoint{
		Raw: "/search", URL: "https://example.test/search?q=hello",
		SourceURL: "https://example.test/app.js", Authorized: true,
	})
	directory := t.TempDir()
	if err := WriteSplitReports(directory, result); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(directory, "参数报告.html"))
	if err != nil {
		t.Fatal(err)
	}
	html := string(data)
	for _, want := range []string{
		"userId", "apiKey", "q",
		"对象属性", "变量赋值", "URL参数",
		"app.js",
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("parameter report missing %q", want)
		}
	}
	if strings.Contains(html, "app.js:") {
		t.Fatalf("来源 column should link the JS file without a line suffix")
	}
	// The plain-text list carries code-shape names too.
	if err := WriteTextReports(directory, result); err != nil {
		t.Fatal(err)
	}
	text, err := os.ReadFile(filepath.Join(directory, "参数.txt"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"userId", "apiKey", "q"} {
		if !strings.Contains(string(text), want) {
			t.Fatalf("参数.txt missing %q", want)
		}
	}
}

// TestParameterReportFillsCodeShapeColumns guards the fix for code-shape-only
// rows, whose 次数 / 域名 / 提取方式 cells used to render empty because the
// inventory pass never fed them through the aggregator.
func TestParameterReportFillsCodeShapeColumns(t *testing.T) {
	result := sampleResult()
	result.Params = []model.ParamHit{
		{
			Name: "userId", Scenario: model.ParamScenarioObjectProperty,
			SourceURL: "https://app.example.test/static/app.js", Line: 12,
		},
		// Same file, another line: must not add a second 来源 link.
		{
			Name: "userId", Scenario: model.ParamScenarioFunctionParam,
			SourceURL: "https://app.example.test/static/app.js", Line: 40,
		},
		// A different file is a distinct source and is listed too.
		{
			Name: "userId", Scenario: model.ParamScenarioDestructuring,
			SourceURL: "https://cdn.example.test/vendor.js", Line: 5,
		},
	}
	directory := t.TempDir()
	if err := WriteSplitReports(directory, result); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(directory, "参数报告.html"))
	if err != nil {
		t.Fatal(err)
	}
	html := string(data)

	// The code-shape hit now contributes its host and extractor, so the row is
	// no longer blank in those columns. 来源 holds the plain JS link, no line.
	for _, want := range []string{"app.example.test", "ast", "app.example.test/static/app.js"} {
		if !strings.Contains(html, want) {
			t.Fatalf("parameter report missing %q for code-shape row", want)
		}
	}
	if strings.Contains(html, "app.example.test/static/app.js:12") {
		t.Fatalf("来源 column should not carry the line number")
	}
	// One link per distinct file: the same file wired twice stays a single
	// link, while a second file is listed as its own source.
	if got := strings.Count(html, `<code>https://app.example.test/static/app.js</code>`); got != 1 {
		t.Fatalf("same-file sources not deduplicated: %d links", got)
	}
	if !strings.Contains(html, `<code>https://cdn.example.test/vendor.js</code>`) {
		t.Fatalf("second JS file missing from 来源 column")
	}
	// The header carries exactly the six kept columns, including the split-out
	// 来源 column.
	header := `<th style="width:160px">参数名</th><th style="width:200px">场景</th><th style="width:60px">次数</th><th style="width:200px">域名</th><th style="width:110px">提取方式</th><th>来源</th>`
	if !strings.Contains(html, header) {
		t.Fatalf("parameter report header changed unexpectedly")
	}
	// The JS location moved out of the name cell into the 来源 column.
	if !strings.Contains(html, `<td><code>userId</code></td>`) {
		t.Fatalf("param name cell should hold the bare name, no JS location")
	}
	if strings.Contains(html, `<code>userId</code><div`) {
		t.Fatalf("JS location still appended under the param name")
	}
	// The 示例值 and 首次出现 columns were removed.
	for _, unwanted := range []string{"示例值", "首次出现"} {
		if strings.Contains(html, unwanted) {
			t.Fatalf("parameter report still contains removed column %q", unwanted)
		}
	}
}
