package report

import (
	"fmt"
	"html/template"
	"net/url"
	"path/filepath"
	"sort"
	"strings"

	"github.com/youmulijiang/jsowl/internal/model"
)

// splitReports lists the topic-focused HTML reports generated next to the
// main interactive report. Server-rendered tables keep each file small and
// instantly openable, unlike the single all-in-one report.
type splitReport struct {
	file   string
	title  string
	render func(*model.Result) (int, string, error)
}

// WriteSplitReports writes the split HTML reports plus a navigation index
// into the target's report directory.
func WriteSplitReports(directory string, result *model.Result) error {
	reports := []splitReport{
		{"API报告.html", "API 端点报告", renderAPIReport},
		{"敏感信息报告.html", "敏感信息报告", renderSensitiveReport},
		{"参数报告.html", "请求参数报告", renderParameterReport},
		{"路由报告.html", "路由探测报告", renderRouteReport},
		{"资源报告.html", "资源报告", renderResourceReport},
	}
	links := []linkItem{
		{File: "report.html", Name: "主报告", Desc: "交互式总览"},
	}
	for _, report := range reports {
		count, body, err := report.render(result)
		if err != nil {
			return err
		}
		page, err := renderSplitPage(result, report.title, links, count, body)
		if err != nil {
			return err
		}
		if err := writeAtomic(filepath.Join(directory, report.file), []byte(page)); err != nil {
			return err
		}
		links = append(links, linkItem{File: report.file, Name: report.title})
	}
	links = append(links,
		linkItem{File: "api路径.txt", Name: "API 路径", Desc: "纯文本端点列表"},
		linkItem{File: "路由.txt", Name: "路由", Desc: "纯文本路由列表"},
		linkItem{File: "参数.txt", Name: "请求参数", Desc: "参数名=值 与来源"},
		linkItem{File: "敏感信息.txt", Name: "敏感信息", Desc: "纯文本命中列表"},
	)
	index, err := renderIndex(result, links)
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(directory, "报告导航.html"), []byte(index))
}

type linkItem struct {
	File string
	Name string
	Desc string
}

// Href keeps non-ASCII file names raw in href attributes; html/template
// would otherwise percent-encode them.
func (item linkItem) Href() template.URL { return template.URL(item.File) }

type splitPage struct {
	Title   string
	Target  string
	Links   []linkItem
	Current string
	Count   int
	Body    template.HTML
}

const splitBase = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Title}} · JsOwl</title>
<style>
:root{color-scheme:dark;--bg:#0b1020;--panel:#151c31;--line:#29334f;--text:#e8edf8;--muted:#9aa8c7;--accent:#79d7ff;--warn:#ffcb6b;--danger:#ff6b6b}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.6 system-ui,sans-serif}
header{padding:16px 24px;border-bottom:1px solid var(--line);display:flex;flex-wrap:wrap;gap:10px;align-items:baseline}
h1{margin:0;font-size:18px}
.target{color:var(--muted);font-size:13px;word-break:break-all}
nav{display:flex;flex-wrap:wrap;gap:8px;padding:12px 24px;border-bottom:1px solid var(--line);background:var(--panel)}
nav a{color:var(--muted);text-decoration:none;padding:4px 12px;border:1px solid var(--line);border-radius:8px;font-size:13px}
nav a:hover{color:var(--accent);border-color:var(--accent)}
nav a.active{color:var(--bg);background:var(--accent);border-color:var(--accent);font-weight:600}
main{padding:16px 24px}
.count{color:var(--muted);font-size:13px;margin:0 0 10px}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:12px;overflow:hidden}
th,td{padding:8px 12px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top;font-size:13px}
th{background:rgba(11,16,32,.7);color:var(--muted);font-size:12px;position:sticky;top:0}
tr:last-child td{border-bottom:none}
code{font-family:ui-monospace,Consolas,monospace;font-size:12px;background:var(--bg);padding:1px 6px;border-radius:4px;word-break:break-all}
.sev{display:inline-block;padding:1px 8px;border-radius:10px;font-size:11px;font-weight:600;text-transform:uppercase}
.sev.critical,.sev.high{background:rgba(255,107,107,.16);color:var(--danger)}
.sev.medium{background:rgba(255,203,107,.15);color:var(--warn)}
.sev.low{background:rgba(121,215,255,.15);color:var(--accent)}
.sev.info,.sev.static{background:rgba(158,168,199,.15);color:var(--muted)}
.sev.runtime{background:rgba(126,231,135,.16);color:#7ee787}
.sev.full-url{background:rgba(255,203,107,.15);color:var(--warn)}
.muted{color:var(--muted);font-size:12px}
.filterbar{display:flex;flex-wrap:wrap;gap:12px;align-items:center;margin-bottom:12px}
.filterbar label{display:flex;align-items:center;gap:6px;font-size:13px;color:var(--muted)}
.filterbar select,.filterbar input[type="search"]{background:var(--bg);color:var(--text);border:1px solid var(--line);border-radius:6px;padding:5px 10px;font-size:13px}
details.ctx{margin-top:6px}
details.ctx summary{cursor:pointer;color:var(--accent);font-size:12px;user-select:none}
details.ctx pre{margin:6px 0 0;padding:10px 12px;background:var(--bg);border:1px solid var(--line);border-radius:8px;font:12px/1.5 ui-monospace,Consolas,monospace;white-space:pre-wrap;word-break:break-all;max-height:320px;overflow:auto}
td{word-break:break-all}
footer{padding:12px 24px;color:var(--muted);font-size:12px;border-top:1px solid var(--line)}
</style>
</head>
<body>
<header><h1>{{.Title}}</h1><span class="target">{{.Target}}</span></header>
<nav>{{range .Links}}<a href="{{.Href}}" title="{{.Desc}}"{{if eq .Name $.Current}} class="active"{{end}}>{{.Name}}</a>{{end}}</nav>
<main>
<p class="count">共 {{.Count}} 条</p>
{{.Body}}
</main>
<footer>JsOwl 安全信息收集报告 · 敏感数据，请妥善保管</footer>
</body>
</html>
`

func renderSplitPage(result *model.Result, title string, links []linkItem, count int, tableHTML string) (string, error) {
	tmpl, err := template.New("split").Parse(splitBase)
	if err != nil {
		return "", err
	}
	var output strings.Builder
	err = tmpl.Execute(&output, splitPage{
		Title:   title,
		Target:  result.Target,
		Links:   links,
		Current: title,
		Count:   count,
		Body:    template.HTML(tableHTML),
	})
	return output.String(), err
}

func renderAPIReport(result *model.Result) (int, string, error) {
	endpoints := append([]model.Endpoint(nil), result.Endpoints...)
	sort.SliceStable(endpoints, func(i, j int) bool { return endpoints[i].URL < endpoints[j].URL })
	var b strings.Builder
	b.WriteString(`<table><thead><tr><th style="width:70px">方法</th><th style="width:90px">证据</th><th>URL</th><th>来源</th><th style="width:70px">授权</th><th style="width:70px">状态</th></tr></thead><tbody>`)
	for _, endpoint := range endpoints {
		method := endpoint.Method
		if method == "" {
			method = "—" // unknown: not recovered from AST or regex
		}
		source := endpoint.SourceURL
		if source == "" {
			source = result.Target
		}
		location := source
		if endpoint.Line > 0 {
			location = fmt.Sprintf("%s:%d:%d", source, endpoint.Line, endpoint.Column)
		}
		context := renderContextBlock(endpoint.ContextLines)
		bodyNote := ""
		if len(endpoint.BodyParams) > 0 {
			bodyNote = `<div class="muted">body: ` + htmlEscape(strings.Join(endpoint.BodyParams, ", ")) + `</div>`
		}
		rawNote := rawPathNote(endpoint)
		fmt.Fprintf(&b,
			"<tr><td><b>%s</b></td><td><span class=\"sev %s\">%s</span></td><td><code>%s</code>%s</td><td><code>%s</code>%s%s</td><td>%t</td><td>%d</td></tr>",
			htmlEscape(method), evidenceClass(endpoint.Evidence), htmlEscape(evidenceLabel(endpoint.Evidence)),
			htmlEscape(endpoint.URL), rawNote, htmlEscape(location), bodyNote, context, endpoint.Authorized, endpoint.StatusCode)
	}
	b.WriteString("</tbody></table>")
	return len(endpoints), b.String(), nil
}

// renderContextBlock formats endpoint context lines as an expandable pre
// block suitable for copying straight into an LLM prompt.
func renderContextBlock(lines []model.ContextLine) string {
	if len(lines) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(`<details class="ctx"><summary>上下文</summary><pre>`)
	for _, line := range lines {
		marker := " "
		if line.MatchStart >= 0 && line.MatchEnd > line.MatchStart {
			marker = ">"
		}
		fmt.Fprintf(&b, "%s %4d | %s\n", marker, line.LineNumber, htmlEscape(line.Content))
	}
	b.WriteString("</pre></details>")
	return b.String()
}

func renderSensitiveReport(result *model.Result) (int, string, error) {
	findings := make([]model.Finding, 0, len(result.Findings))
	for _, finding := range result.Findings {
		if finding.Category == model.RuleCategorySensitive {
			findings = append(findings, finding)
		}
	}
	var b strings.Builder
	b.WriteString(`<table><thead><tr><th style="width:90px">严重性</th><th style="width:200px">规则</th><th>完整值</th><th style="width:280px">来源</th></tr></thead><tbody>`)
	for _, finding := range findings {
		fmt.Fprintf(&b,
			"<tr><td><span class=\"sev %s\">%s</span></td><td>%s<div class=\"muted\">%s</div></td><td><code>%s</code></td><td><code>%s</code><div class=\"muted\">行 %d 列 %d</div></td></tr>",
			htmlEscape(string(finding.Severity)), htmlEscape(string(finding.Severity)),
			htmlEscape(finding.RuleName), htmlEscape(finding.RuleID),
			htmlEscape(finding.Value), htmlEscape(finding.SourceURL),
			finding.Line, finding.Column)
	}
	b.WriteString("</tbody></table>")
	return len(findings), b.String(), nil
}

type parameterRow struct {
	Name   string
	Value  string
	Source string
}

func collectParameterRows(result *model.Result) []parameterRow {
	type entry struct {
		value  string
		source string
	}
	params := map[string]entry{}
	collect := func(raw string) {
		parsed, err := url.Parse(raw)
		if err != nil {
			return
		}
		for key, values := range parsed.Query() {
			if _, exists := params[key]; exists {
				continue
			}
			value := ""
			if len(values) > 0 {
				value = values[0]
			}
			params[key] = entry{value: value, source: raw}
		}
	}
	for _, endpoint := range result.Endpoints {
		collect(endpoint.URL)
		for _, name := range endpoint.BodyParams {
			if _, exists := params[name]; !exists {
				params[name] = entry{value: "(body)", source: endpoint.URL}
			}
		}
	}
	for _, resource := range result.Resources {
		collect(resource.URL)
	}
	rows := make([]parameterRow, 0, len(params))
	for name, entry := range params {
		rows = append(rows, parameterRow{Name: name, Value: entry.value, Source: entry.source})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })
	return rows
}

// parameterStat aggregates one parameter name across every URL that
// carries it: which hosts, how often, and which extractor surfaced it.
type parameterStat struct {
	Name      string
	Count     int
	Hosts     []string
	Sources   []string
	Example   string
	FirstSeen string
	Body      bool
}

// collectParameterStats merges URL query parameters and AST body parameters
// into per-name statistics.
func collectParameterStats(result *model.Result) []parameterStat {
	type entry struct {
		count     int
		hosts     map[string]bool
		sources   map[string]bool
		example   string
		firstSeen string
		body      bool
	}
	stats := map[string]*entry{}
	add := func(name, value, sourceURL, extractor string, isBody bool) {
		stat, exists := stats[name]
		if !exists {
			stat = &entry{
				hosts: map[string]bool{}, sources: map[string]bool{},
				example: value, firstSeen: sourceURL,
			}
			stats[name] = stat
		}
		stat.count++
		if isBody {
			stat.body = true
		}
		if sourceURL != "" {
			if parsed, err := url.Parse(sourceURL); err == nil && parsed.Host != "" {
				stat.hosts[parsed.Host] = true
			}
		}
		if extractor != "" {
			stat.sources[extractor] = true
		}
	}
	endpointExtractor := func(endpoint model.Endpoint) string {
		if endpoint.Source != "" {
			return endpoint.Source
		}
		switch endpoint.Evidence {
		case model.EvidenceRuntime:
			return "cdp"
		case model.EvidenceFullURL:
			return "ast"
		default:
			return "regex"
		}
	}
	for _, endpoint := range result.Endpoints {
		extractor := endpointExtractor(endpoint)
		if parsed, err := url.Parse(endpoint.URL); err == nil {
			for key, values := range parsed.Query() {
				value := ""
				if len(values) > 0 {
					value = values[0]
				}
				add(key, value, endpoint.URL, extractor, false)
			}
		}
		for _, name := range endpoint.BodyParams {
			add(name, "(body)", endpoint.URL, extractor, true)
		}
	}
	for _, resource := range result.Resources {
		parsed, err := url.Parse(resource.URL)
		if err != nil {
			continue
		}
		for key, values := range parsed.Query() {
			value := ""
			if len(values) > 0 {
				value = values[0]
			}
			add(key, value, resource.URL, "url", false)
		}
	}

	names := make([]string, 0, len(stats))
	for name := range stats {
		names = append(names, name)
	}
	sort.Strings(names)
	rows := make([]parameterStat, 0, len(names))
	for _, name := range names {
		stat := stats[name]
		row := parameterStat{
			Name: name, Count: stat.count,
			Example: stat.example, FirstSeen: stat.firstSeen, Body: stat.body,
		}
		for host := range stat.hosts {
			row.Hosts = append(row.Hosts, host)
		}
		sort.Strings(row.Hosts)
		for source := range stat.sources {
			row.Sources = append(row.Sources, source)
		}
		sort.Strings(row.Sources)
		rows = append(rows, row)
	}
	return rows
}

func renderParameterReport(result *model.Result) (int, string, error) {
	rows := collectParameterStats(result)

	hosts := map[string]bool{}
	for _, row := range rows {
		for _, host := range row.Hosts {
			hosts[host] = true
		}
	}
	hostList := make([]string, 0, len(hosts))
	for host := range hosts {
		hostList = append(hostList, host)
	}
	sort.Strings(hostList)

	var b strings.Builder
	b.WriteString(`<div class="filterbar">
<label>域名 <select id="host-filter"><option value="">全部</option>`)
	for _, host := range hostList {
		b.WriteString(`<option value="` + htmlEscape(host) + `">` + htmlEscape(host) + `</option>`)
	}
	b.WriteString(`</select></label>
<label>搜索 <input type="search" id="param-search" placeholder="参数名或值..."></label>
<span class="muted" id="param-count"></span>
</div>
<table id="param-table"><thead><tr><th style="width:180px">参数名</th><th style="width:70px">次数</th><th style="width:220px">域名</th><th style="width:150px">提取方式</th><th style="width:240px">示例值</th><th>首次出现</th></tr></thead><tbody>`)
	for _, row := range rows {
		markers := ""
		if row.Body {
			markers = ` <span class="sev full-url">body</span>`
		}
		fmt.Fprintf(&b,
			"<tr data-hosts=%q><td><code>%s</code>%s</td><td>%d</td><td class=\"muted\">%s</td><td>%s</td><td><code>%s</code></td><td><code>%s</code></td></tr>",
			strings.Join(row.Hosts, " "), htmlEscape(row.Name), markers,
			row.Count, htmlEscape(strings.Join(row.Hosts, ", ")),
			htmlEscape(strings.Join(row.Sources, ", ")),
			htmlEscape(row.Example), htmlEscape(row.FirstSeen))
	}
	b.WriteString(`</tbody></table>
<script>
(function(){
  var rows = Array.prototype.slice.call(document.querySelectorAll('#param-table tbody tr'));
  var host = document.getElementById('host-filter');
  var search = document.getElementById('search-fallback') || null;
  var query = document.getElementById('param-search');
  var counter = document.getElementById('param-count');
  function apply(){
    var hostValue = host.value.toLowerCase();
    var text = query.value.toLowerCase();
    var visible = 0;
    rows.forEach(function(row){
      var ok = (!hostValue || (row.dataset.hosts || '').toLowerCase().indexOf(hostValue) !== -1) &&
               (!text || row.textContent.toLowerCase().indexOf(text) !== -1);
      row.style.display = ok ? '' : 'none';
      if (ok) visible++;
    });
    counter.textContent = '显示 ' + visible + ' / ' + rows.length + ' 个参数';
  }
  host.addEventListener('change', apply);
  var timer = null;
  query.addEventListener('input', function(){
    clearTimeout(timer);
    timer = setTimeout(apply, 150);
  });
  apply();
})();
</script>`)
	return len(rows), b.String(), nil
}

// renderRouteReport renders framework routes with source and probe outcome.
func renderRouteReport(result *model.Result) (int, string, error) {
	routes := make([]model.Endpoint, 0, len(result.Endpoints))
	for _, endpoint := range result.Endpoints {
		if endpoint.Type == "route" {
			routes = append(routes, endpoint)
		}
	}
	sort.SliceStable(routes, func(i, j int) bool { return routes[i].URL < routes[j].URL })
	var b strings.Builder
	b.WriteString(`<table><thead><tr><th>路由路径</th><th style="width:140px">提取方式</th><th style="width:90px">证据</th><th style="width:280px">来源</th><th style="width:110px">探测结果</th></tr></thead><tbody>`)
	for _, route := range routes {
		probe := route.Probe
		probeLabel, probeClass := "未探测", "info"
		switch probe {
		case "server":
			probeLabel, probeClass = "服务端真实页面", "runtime"
		case "static":
			probeLabel, probeClass = "纯前端路由", "info"
		case "error":
			probeLabel, probeClass = "探测失败", "medium"
		case "unknown":
			probeLabel, probeClass = "无基准", "info"
		}
		fmt.Fprintf(&b,
			"<tr><td><code>%s</code>%s</td><td>%s</td><td><span class=\"sev %s\">%s</span></td><td><code>%s</code></td><td><span class=\"sev %s\">%s</span></td></tr>",
			htmlEscape(route.URL), rawPathNote(route), htmlEscape(extractorLabel(route.Source)),
			evidenceClass(route.Evidence), htmlEscape(evidenceLabel(route.Evidence)),
			htmlEscape(route.SourceURL),
			probeClass, htmlEscape(probeLabel))
	}
	b.WriteString("</tbody></table>")
	return len(routes), b.String(), nil
}

// rawPathNote renders the pre-resolution path annotation.
func rawPathNote(endpoint model.Endpoint) string {
	if endpoint.Raw == "" || endpoint.Raw == endpoint.URL {
		return ""
	}
	kind := "绝对"
	if isRelativeRaw(endpoint.Raw) {
		kind = "相对"
	}
	return `<div class="muted">原始(` + kind + `): ` + htmlEscape(endpoint.Raw) + `</div>`
}

func extractorLabel(source string) string {
	switch source {
	case "cdp", "cdp-runtime":
		return "CDP 运行时"
	case "ast":
		return "AST"
	case "regex":
		return "正则"
	}
	if source == "" {
		return "—"
	}
	return source
}

func renderResourceReport(result *model.Result) (int, string, error) {
	resources := append([]model.Resource(nil), result.Resources...)
	sort.SliceStable(resources, func(i, j int) bool { return resources[i].URL < resources[j].URL })
	var b strings.Builder
	b.WriteString(`<table><thead><tr><th style="width:90px">类型</th><th>URL</th><th style="width:60px">状态</th><th style="width:90px">大小</th><th style="width:220px">本地路径</th></tr></thead><tbody>`)
	for _, resource := range resources {
		fmt.Fprintf(&b, "<tr><td>%s</td><td><code>%s</code></td><td>%d</td><td>%d</td><td><code>%s</code></td></tr>",
			htmlEscape(string(resource.Type)), htmlEscape(resource.URL),
			resource.StatusCode, resource.Size, htmlEscape(resource.LocalPath))
	}
	b.WriteString("</tbody></table>")
	return len(resources), b.String(), nil
}

func renderIndex(result *model.Result, links []linkItem) (string, error) {
	body := fmt.Sprintf(`<table><tbody>
<tr><td style="width:120px">资源</td><td>%d</td></tr>
<tr><td>端点</td><td>%d</td></tr>
<tr><td>发现</td><td>%d</td></tr>
</tbody></table>
<p class="count" style="margin-top:14px">从上方导航进入各分项报告；纯文本结果适合直接喂给其他工具。</p>`,
		len(result.Resources), len(result.Endpoints), len(result.Findings))
	return renderSplitPage(result, "报告导航", links,
		len(result.Resources)+len(result.Endpoints)+len(result.Findings), body)
}

func evidenceClass(evidence string) string {
	switch evidence {
	case model.EvidenceRuntime, model.EvidenceFullURL:
		return evidence
	default:
		return "static"
	}
}

func evidenceLabel(evidence string) string {
	if evidence == "" {
		return "static"
	}
	return evidence
}

// isRelativeRaw reports whether the pre-resolution endpoint reference was
// a relative path.
func isRelativeRaw(raw string) bool {
	parsed, err := url.Parse(raw)
	return err == nil && parsed.Scheme == "" && parsed.Host == ""
}

func htmlEscape(value string) string {
	// Pages served in legacy charsets (e.g. GBK) leak invalid UTF-8 bytes;
	// drop them so every generated report stays valid UTF-8.
	value = strings.ToValidUTF8(value, "�")
	return strings.NewReplacer(
		"&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;",
	).Replace(value)
}
