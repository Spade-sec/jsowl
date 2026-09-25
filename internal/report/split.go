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
		{"URL报告.html", "完整 URL 报告", renderURLReport},
		{"敏感信息报告.html", "敏感信息报告", renderSensitiveReport},
		{"参数报告.html", "请求参数报告", renderParameterReport},
		{"路由报告.html", "路由探测报告", renderRouteReport},
		{"资源报告.html", "资源报告", renderResourceReport},
	}
	// Build the full navigation first so every page shares the same nav bar.
	links := []linkItem{
		{File: "report.html", Name: "主报告", Desc: "交互式总览"},
	}
	for _, report := range reports {
		links = append(links, linkItem{File: report.file, Name: report.title})
	}
	links = append(links,
		linkItem{File: "api绝对路径.txt", Name: "API 绝对路径", Desc: "纯文本 /a/b/c 路径列表"},
		linkItem{File: "api相对路径.txt", Name: "API 相对路径", Desc: "纯文本 a/b/c 路径列表"},
		linkItem{File: "url.txt", Name: "完整 URL", Desc: "纯文本 http(s) URL 列表"},
		linkItem{File: "路由.txt", Name: "路由", Desc: "纯文本路由列表"},
		linkItem{File: "参数.txt", Name: "请求参数", Desc: "纯文本参数名列表"},
		linkItem{File: "敏感信息.txt", Name: "敏感信息", Desc: "纯文本命中列表"},
	)
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
	}
	// No separate navigation page: the main report.html links to every
	// split page and txt file (see splitLinks in assets/report.html), and
	// each split page links back through its own nav bar.
	return nil
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
:root{color-scheme:light;--bg:#f5f6f8;--panel:#ffffff;--line:#e4e7ec;--text:#1f2329;--muted:#8a919c;--accent:#2f6fed;--accent-soft:#eaf1fe;--warn:#b7791f;--danger:#d64545;--success:#2f9e6e}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.6 system-ui,-apple-system,"Segoe UI",sans-serif}
header{padding:16px 24px;border-bottom:1px solid var(--line);display:flex;flex-wrap:wrap;gap:10px;align-items:baseline;background:var(--panel)}
h1{margin:0;font-size:18px;font-weight:600}
.target{color:var(--muted);font-size:13px;word-break:break-all}
nav{display:flex;flex-wrap:wrap;gap:8px;padding:10px 24px;border-bottom:1px solid var(--line);background:var(--panel);position:sticky;top:0;z-index:10}
nav a{color:var(--muted);text-decoration:none;padding:4px 12px;border:1px solid var(--line);border-radius:999px;font-size:13px;background:var(--panel)}
nav a:hover{color:var(--accent);border-color:var(--accent)}
nav a.active{color:#fff;background:var(--accent);border-color:var(--accent);font-weight:600}
main{padding:16px 24px}
.count{color:var(--muted);font-size:13px;margin:0 0 10px}
table{width:100%;border-collapse:separate;border-spacing:0;background:var(--panel);border:1px solid var(--line);border-radius:12px;overflow:hidden}
th,td{padding:8px 12px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top;font-size:13px}
th{background:#fafbfc;color:var(--muted);font-size:12px;font-weight:500;position:sticky;top:0}
tr:last-child td{border-bottom:none}
tr:hover td{background:#f8f9fb}
code{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:12px;background:var(--bg);padding:1px 6px;border-radius:4px;word-break:break-all}
.sev{display:inline-block;padding:1px 8px;border-radius:999px;font-size:11px;font-weight:600;text-transform:uppercase;white-space:nowrap}
.sev.critical{background:#fdecec;color:var(--danger)}
.sev.high{background:#fdecec;color:var(--danger)}
.sev.medium{background:#fdf3e3;color:var(--warn)}
.sev.low{background:var(--accent-soft);color:var(--accent)}
.sev.info,.sev.static{background:#f0f1f3;color:var(--muted)}
.sev.runtime{background:#e6f6ef;color:var(--success)}
.sev.full-url{background:#fdf3e3;color:var(--warn)}
.sev.vendor{background:#f0f1f3;color:var(--muted);border:1px dashed var(--line)}
.muted{color:var(--muted);font-size:12px}
.section-title{margin:18px 0 10px;font-size:15px;color:var(--text);font-weight:600}
.copy-btn{background:var(--panel);border:1px solid var(--line);color:var(--muted);border-radius:6px;padding:1px 8px;font-size:11px;cursor:pointer;margin-left:8px;vertical-align:middle}
.copy-btn:hover{color:var(--accent);border-color:var(--accent)}
.filterbar{display:flex;flex-wrap:wrap;gap:12px;align-items:center;margin-bottom:12px}
.filterbar label{display:flex;align-items:center;gap:6px;font-size:13px;color:var(--muted)}
.filterbar select,.filterbar input[type="search"]{background:var(--panel);color:var(--text);border:1px solid var(--line);border-radius:8px;padding:5px 10px;font-size:13px}
details.ctx{margin-top:6px}
details.ctx summary{cursor:pointer;color:var(--accent);font-size:12px;user-select:none}
details.ctx pre{margin:6px 0 0;padding:10px 12px;background:var(--bg);border:1px solid var(--line);border-radius:8px;font:12px/1.5 ui-monospace,SFMono-Regular,Consolas,monospace;white-space:pre-wrap;word-break:break-all;max-height:320px;overflow:auto}
tr.ctx-row{display:none}
tr.ctx-row.open{display:table-row}
tr.ctx-row>td{padding:0 12px 12px;border-bottom:1px solid var(--line)}
.ctx-block pre.ctx-pre{margin:0;padding:10px 12px;background:var(--bg);border:1px solid var(--line);border-radius:8px;font:12px/1.5 ui-monospace,SFMono-Regular,Consolas,monospace;white-space:pre-wrap;word-break:break-all;max-height:320px;overflow:auto}
.ctx-pre mark{background:#fdeea8;color:#7a5d00;border-radius:3px;padding:0 2px}
.pager{display:flex;gap:8px;align-items:center;justify-content:center;padding:10px 0}
.pager button{background:var(--panel);border:1px solid var(--line);color:var(--text);padding:5px 12px;border-radius:8px;font-size:12px;cursor:pointer}
.pager button:disabled{opacity:.4;cursor:not-allowed}
.pager .page-info{font-size:12px;color:var(--muted);min-width:110px;text-align:center}
td{word-break:break-all}
footer{padding:12px 24px;color:var(--muted);font-size:12px;border-top:1px solid var(--line);background:var(--panel)}
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
<script>
(function(){
  // Table pagination: every table.paginated shows data-page-size rows per
  // page with a prev/next pager appended after it.
  document.querySelectorAll('table.paginated').forEach(function(table){
    var pageSize = parseInt(table.getAttribute('data-page-size') || '50', 10);
    var tbody = table.tBodies[0];
    if (!tbody) return;
    // Data rows only: full-width context rows ride along with their
    // endpoint row and must not consume page slots.
    var rows = Array.prototype.slice.call(tbody.rows).filter(function(row){
      return row.className.indexOf('ctx-row') === -1;
    });
    var totalPages = Math.max(1, Math.ceil(rows.length / pageSize));
    var page = 1;
    var pager = document.createElement('div');
    pager.className = 'pager';
    table.parentNode.insertBefore(pager, table.nextSibling);
    function apply(){
      var first = (page - 1) * pageSize;
      rows.forEach(function(row, index){
        var visible = index >= first && index < first + pageSize;
        row.style.display = visible ? '' : 'none';
        var ctxRow = row.nextElementSibling;
        if (ctxRow && ctxRow.className.indexOf('ctx-row') !== -1) {
          ctxRow.style.display = visible && ctxRow.className.indexOf(' open') !== -1 ? '' : 'none';
        }
      });
      var start = rows.length === 0 ? 0 : first + 1;
      var end = Math.min(first + pageSize, rows.length);
      pager.innerHTML = totalPages <= 1 ? '' :
        '<button data-go="prev"' + (page <= 1 ? ' disabled' : '') + '>上一页</button>' +
        '<span class="page-info">' + start + '-' + end + ' / ' + rows.length + '</span>' +
        '<button data-go="next"' + (page >= totalPages ? ' disabled' : '') + '>下一页</button>';
    }
    pager.addEventListener('click', function(event){
      var go = event.target.getAttribute && event.target.getAttribute('data-go');
      if (go === 'prev' && page > 1) { page--; apply(); }
      if (go === 'next' && page < totalPages) { page++; apply(); }
    });
    apply();
  });

  // Context toggle: the button sits in the endpoint row; the pre block lives
  // in the full-width ctx-row right below it.
  document.addEventListener('click', function(event){
    var button = event.target.closest ? event.target.closest('.ctx-toggle') : null;
    if (!button) return;
    var row = button.closest('tr');
    var ctxRow = row.nextElementSibling;
    if (!ctxRow || ctxRow.className.indexOf('ctx-row') === -1) return;
    var open = ctxRow.className.indexOf(' open') === -1;
    ctxRow.className = open ? ctxRow.className + ' open' : ctxRow.className.replace(' open', '');
    if (open && row.style.display !== 'none') ctxRow.style.display = '';
    else ctxRow.style.display = 'none';
    button.textContent = open ? '收起上下文' : '上下文';
  });

  document.addEventListener('click', function(event){
    var button = event.target.closest('[data-copy]');
    if (!button) return;
    var text = button.getAttribute('data-copy');
    var done = function(){ button.textContent = '已复制'; setTimeout(function(){ button.textContent = '复制'; }, 1200); };
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(done, function(){ fallbackCopy(text, done); });
    } else {
      fallbackCopy(text, done);
    }
  });
  function fallbackCopy(text, done){
    var area = document.createElement('textarea');
    area.value = text;
    area.style.position = 'fixed'; area.style.opacity = '0';
    document.body.appendChild(area);
    area.select();
    try { document.execCommand('copy'); done(); } catch (e) {}
    document.body.removeChild(area);
  }
})();
</script>
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
	sort.SliceStable(endpoints, func(i, j int) bool {
		return apiPath(endpoints[i]) < apiPath(endpoints[j])
	})

	relative, absolute, full := 0, 0, 0
	relativeRows, absoluteRows := &strings.Builder{}, &strings.Builder{}
	for _, endpoint := range endpoints {
		switch _, kind := classifyAPIPath(endpoint); kind {
		case apiPathURL:
			// Full http(s) URLs live in the URL report, not the path report.
			full++
		case apiPathRelative:
			renderAPIRow(relativeRows, endpoint)
			relative++
		default:
			renderAPIRow(absoluteRows, endpoint)
			absolute++
		}
	}

	var b strings.Builder
	b.WriteString(`<div class="filterbar"><span class="muted">点击路径旁的“复制”按钮复制纯路径；每条路径可展开查看 JS 上下文（路径已高亮）。完整 http(s) URL 见“完整 URL 报告”。</span></div>`)
	writeAPISection := func(title string, rows *strings.Builder, count int) {
		fmt.Fprintf(&b, `<h2 class="section-title">%s（%d）</h2><table class="paginated" data-page-size="50"><thead><tr><th>路径</th><th style="width:70px">方法</th><th style="width:90px">证据</th><th style="width:280px">来源</th><th style="width:60px">状态</th></tr></thead><tbody>%s</tbody></table>`,
			htmlEscape(title), count, rows.String())
	}
	writeAPISection("相对路径", relativeRows, relative)
	writeAPISection("绝对路径", absoluteRows, absolute)
	if full > 0 {
		fmt.Fprintf(&b, `<h2 class="section-title">完整 URL（%d）</h2><p class="muted">已移至 <a href="URL报告.html">完整 URL 报告</a>。</p>`, full)
	}
	return relative + absolute, b.String(), nil
}

// apiPathKind classifies one endpoint reference for the path reports. The
// HTML sections and the txt files must agree on this split, otherwise their
// counts never line up.
type apiPathKind int

const (
	apiPathRelative apiPathKind = iota
	apiPathAbsolute
	apiPathURL
)

// classifyAPIPath returns the reference as written in the source plus its
// kind. A complete http(s) URL is never a path.
func classifyAPIPath(endpoint model.Endpoint) (string, apiPathKind) {
	path := apiPath(endpoint)
	if isFullURL(path) {
		return path, apiPathURL
	}
	if isRelativeRaw(path) {
		return path, apiPathRelative
	}
	return path, apiPathAbsolute
}

// apiPath returns the path as written in the source, without folding it
// into a full URL.
func apiPath(endpoint model.Endpoint) string {
	if endpoint.Raw != "" {
		return endpoint.Raw
	}
	return endpoint.URL
}

func renderAPIRow(b *strings.Builder, endpoint model.Endpoint) {
	path := apiPath(endpoint)
	method := endpoint.Method
	if method == "" {
		method = "—"
	}
	source := endpoint.SourceURL
	if source == "" {
		source = "—"
	}
	location := source
	if endpoint.Line > 0 {
		location = fmt.Sprintf("%s:%d:%d", source, endpoint.Line, endpoint.Column)
	}
	bodyNote := ""
	if len(endpoint.BodyParams) > 0 {
		bodyNote = `<div class="muted">body: ` + htmlEscape(strings.Join(endpoint.BodyParams, ", ")) + `</div>`
	}
	// Context expands in its own full-width row: a pre block inside the
	// narrow path cell would wrap at the column width, not the table width.
	contextToggle := ""
	if len(endpoint.ContextLines) > 0 {
		contextToggle = `<button class="copy-btn ctx-toggle">上下文</button>`
	}
	if endpoint.Vendor {
		contextToggle = `<span class="sev vendor">vendor</span>` + contextToggle
	}
	fmt.Fprintf(b,
		"<tr><td><code>%s</code><button class=\"copy-btn\" data-copy=\"%s\">复制</button>%s%s</td>"+
			"<td><b>%s</b></td><td><span class=\"sev %s\">%s</span></td>"+
			"<td><code>%s</code></td><td>%d</td></tr>",
		htmlEscape(path), htmlEscape(path), bodyNote, contextToggle,
		htmlEscape(method), evidenceClass(endpoint.Evidence), htmlEscape(evidenceLabel(endpoint.Evidence)),
		htmlEscape(location), endpoint.StatusCode)
	if len(endpoint.ContextLines) > 0 {
		fmt.Fprintf(b,
			`<tr class="ctx-row"><td colspan="5">%s</td></tr>`,
			renderContextBlock(endpoint.ContextLines, endpoint.Raw, endpoint.URL))
	}
}

// renderContextBlock formats endpoint context lines as a hidden pre block
// spanning the full table width; the extracted path fragments are
// highlighted inside the matched line so the context can be pasted straight
// into an LLM prompt.
func renderContextBlock(lines []model.ContextLine, raw, resolved string) string {
	if len(lines) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(`<div class="ctx-block"><pre class="ctx-pre">`)
	for _, line := range lines {
		marker := " "
		content := htmlEscape(line.Content)
		if line.MatchStart >= 0 && line.MatchEnd > line.MatchStart {
			marker = ">"
			content = highlightFragments(line.Content, pathFragments(raw, resolved))
		}
		// Defense in depth: discover already trims minified lines, but
		// results loaded from older JSON or external files may still carry
		// whole-bundle lines; cap them so one row cannot blow up the page.
		if len(content) > 2000 {
			content = content[:2000] + "…"
		}
		fmt.Fprintf(&b, "%s %4d | %s\n", marker, line.LineNumber, content)
	}
	b.WriteString("</pre></div>")
	return b.String()
}

// pathFragments splits an endpoint reference into literal segments around
// {} placeholders and query strings so template URLs can still be
// highlighted piecewise.
func pathFragments(raw, resolved string) []string {
	source := raw
	if source == "" {
		source = resolved
	}
	if source == "" {
		return nil
	}
	fragments := strings.FieldsFunc(source, func(char rune) bool {
		return char == '{' || char == '}' || char == '?'
	})
	kept := make([]string, 0, len(fragments))
	for _, fragment := range fragments {
		fragment = strings.Trim(fragment, "/")
		if fragment != "" {
			kept = append(kept, fragment)
		}
	}
	return kept
}

// highlightFragments wraps every occurrence of the fragments with <mark>,
// escaping both the content and the fragments.
func highlightFragments(content string, fragments []string) string {
	escaped := htmlEscape(content)
	for _, fragment := range fragments {
		needle := htmlEscape(fragment)
		if needle == "" || !strings.Contains(escaped, needle) {
			continue
		}
		escaped = strings.Replace(escaped, needle, `<mark>`+needle+`</mark>`, 1)
	}
	return escaped
}

// renderURLReport lists every full http(s) URL with its host and source.
func renderURLReport(result *model.Result) (int, string, error) {
	seen := make(map[string]struct{})
	urls := make([]model.Endpoint, 0)
	for _, endpoint := range result.Endpoints {
		raw := endpoint.Raw
		if raw == "" {
			raw = endpoint.URL
		}
		if !isFullURL(raw) {
			continue
		}
		if _, duplicate := seen[raw]; duplicate {
			continue
		}
		seen[raw] = struct{}{}
		urls = append(urls, endpoint)
	}
	resourceSeen := make(map[string]struct{})
	for raw := range seen {
		resourceSeen[raw] = struct{}{}
	}
	for _, resource := range result.Resources {
		if !isFullURL(resource.URL) {
			continue
		}
		if _, duplicate := resourceSeen[resource.URL]; duplicate {
			continue
		}
		resourceSeen[resource.URL] = struct{}{}
		seen[resource.URL] = struct{}{}
		urls = append(urls, model.Endpoint{Raw: resource.URL, URL: resource.URL})
	}
	sort.SliceStable(urls, func(i, j int) bool { return urls[i].Raw < urls[j].Raw })

	var b strings.Builder
	b.WriteString(`<div class="filterbar"><span class="muted">API 端点与资源中出现的完整 http(s) URL，去重后的全集；纯路径见 API 报告。纯文本版本见 url.txt。</span></div>`)
	fmt.Fprintf(&b, `<table class="paginated" data-page-size="50"><thead><tr><th>URL</th><th style="width:140px">方法</th><th style="width:90px">证据</th><th style="width:280px">来源</th><th style="width:60px">状态</th></tr></thead><tbody>`)
	for _, endpoint := range urls {
		method := endpoint.Method
		if method == "" {
			method = "—"
		}
		source := endpoint.SourceURL
		if source == "" {
			source = "—"
		}
		fmt.Fprintf(&b,
			"<tr><td><code>%s</code><button class=\"copy-btn\" data-copy=\"%s\">复制</button></td>"+
				"<td><b>%s</b></td><td><span class=\"sev %s\">%s</span></td>"+
				"<td><code>%s</code></td><td>%d</td></tr>",
			htmlEscape(endpoint.Raw), htmlEscape(endpoint.Raw),
			htmlEscape(method),
			evidenceClass(endpoint.Evidence), htmlEscape(evidenceLabel(endpoint.Evidence)),
			htmlEscape(source), endpoint.StatusCode)
	}
	b.WriteString(`</tbody></table>`)
	return len(urls), b.String(), nil
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
		vendorMark := ""
		if finding.Vendor {
			vendorMark = ` <span class="sev vendor">vendor</span>`
		}
		fmt.Fprintf(&b,
			"<tr><td><span class=\"sev %s\">%s</span></td><td>%s%s<div class=\"muted\">%s</div></td><td><code>%s</code></td><td><code>%s</code><div class=\"muted\">行 %d 列 %d</div></td></tr>",
			htmlEscape(string(finding.Severity)), htmlEscape(string(finding.Severity)),
			htmlEscape(finding.RuleName), vendorMark, htmlEscape(finding.RuleID),
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
	Response  bool
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
		response  bool
	}
	stats := map[string]*entry{}
	add := func(name, value, sourceURL, extractor string, isBody, isResponse bool) {
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
		if isResponse {
			stat.response = true
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
				add(key, value, endpoint.URL, extractor, false, false)
			}
		}
		for _, name := range endpoint.BodyParams {
			add(name, "(body)", endpoint.URL, extractor, true, false)
		}
		for _, name := range endpoint.ResponseParams {
			add(name, "(response)", endpoint.URL, extractor, false, true)
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
			add(key, value, resource.URL, "url", false, false)
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
			Example: stat.example, FirstSeen: stat.firstSeen,
			Body: stat.body, Response: stat.response,
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
		if row.Response {
			markers += ` <span class="sev runtime">response</span>`
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
// a relative path such as "a/b" or "./a"; "/a/b" counts as absolute.
func isRelativeRaw(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "" || parsed.Host != "" {
		return false
	}
	return !strings.HasPrefix(raw, "/")
}

func htmlEscape(value string) string {
	// Pages served in legacy charsets (e.g. GBK) leak invalid UTF-8 bytes;
	// drop them so every generated report stays valid UTF-8.
	value = strings.ToValidUTF8(value, "�")
	return strings.NewReplacer(
		"&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;",
	).Replace(value)
}
