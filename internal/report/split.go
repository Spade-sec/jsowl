package report

import (
	"fmt"
	"html/template"
	"net/url"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/youmulijiang/jsowl/internal/analyze"
	"github.com/youmulijiang/jsowl/internal/extract"
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
		{"主机资产报告.html", "主机资产报告", renderHostReport},
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
		linkItem{File: "domain.txt", Name: "域名清单", Desc: "纯文本域名列表（标准化、去重）"},
		linkItem{File: "ip.txt", Name: "IP 清单", Desc: "纯文本 IPv4/IPv6 列表"},
		linkItem{File: "internal_hosts.txt", Name: "内部主机", Desc: "纯文本内部主机候选列表"},
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
.sev.scen{background:var(--accent-soft);color:var(--accent);text-transform:none}
.sev.runtime{background:#e6f6ef;color:var(--success)}
.sev.full-url{background:#fdf3e3;color:var(--warn)}
.sev.vendor{background:#f0f1f3;color:var(--muted);border:1px dashed var(--line)}
.muted{color:var(--muted);font-size:12px}
.section-title{margin:18px 0 10px;font-size:15px;color:var(--text);font-weight:600}
.copy-btn{background:var(--panel);border:1px solid var(--line);color:var(--muted);border-radius:6px;padding:1px 8px;font-size:11px;cursor:pointer;margin-left:8px;vertical-align:middle}
.copy-btn:hover{color:var(--accent);border-color:var(--accent)}
.pkt-wrap{margin-top:8px}
.pkt-pre{background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:10px 12px;font-size:12px;line-height:1.6;overflow-x:auto;white-space:pre-wrap;word-break:break-all}
.pkt-method{color:var(--accent);font-weight:700}
.pkt-ph{color:#e6a23c;font-weight:600}
.pkt-note{color:var(--muted)}
.pkt-legend{margin-top:4px;font-size:11px}
.sev.ai{background:linear-gradient(90deg,#7c5cff,#4a9eff);color:#fff}
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
tr.api-row{cursor:pointer}
tr.api-row td:first-child{position:relative}
tr.api-row.open td{background:#f4f7ff}
.detail{padding:12px 14px;display:grid;gap:10px}
.detail-k{font-size:12px;color:var(--muted);margin:0 0 2px}
.detail-v{font-size:13px;word-break:break-all}
.detail-section{border:1px solid var(--line);border-radius:8px;padding:10px 12px;background:#fbfcfe}
.spec-table{width:100%;border-collapse:collapse;background:transparent;margin-top:4px}
.spec-table th{position:static;background:transparent;color:var(--muted);font-size:11px;padding:3px 10px 3px 0;border-bottom:1px solid var(--line)}
.spec-table td{padding:3px 10px 3px 0;border-bottom:1px dashed var(--line);font-size:12px;background:transparent}
.spec-table tr:last-child td{border-bottom:none}
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
  {{interactions}}
  document.querySelectorAll('table').forEach(function(table){
    var tbody = table.tBodies[0];
    if (!tbody) return;
    var rows = Array.from(tbody.rows).filter(function(row){ return !row.classList.contains('ctx-row'); });
    var details = new Map(rows.map(function(row){
      var next = row.nextElementSibling;
      return [row, next && next.classList.contains('ctx-row') ? next : null];
    }));
    var paginated = table.classList.contains('paginated');
    var pageSize = Number(table.dataset.pageSize || 50), page = 1, totalPages = 1;
    var pager = document.createElement('div');
    pager.className = 'pager';
    if (paginated) table.after(pager);
    var filters = table.id === 'sensitive-table' ? document.getElementById('sensitive-filters') : null;
    if (filters) {
      ['severity', 'rule', 'source'].forEach(function(key){
        var select = filters.querySelector('[data-filter="' + key + '"]');
        Array.from(new Set(rows.map(function(row){ return row.dataset[key]; }))).sort(reportCollator.compare).forEach(function(value){
          var option = document.createElement('option'); option.value = value; option.textContent = value; select.appendChild(option);
        });
      });
      filters.addEventListener('change', function(){ page = 1; apply(); });
      filters.addEventListener('input', function(){ page = 1; apply(); });
      filters.querySelector('button').addEventListener('click', function(){
        filters.querySelectorAll('select,input').forEach(function(control){ control.value = ''; }); page = 1; apply();
      });
    }
    function apply(){
      var filtered = rows.filter(function(row){
        if (!filters) return true;
        var matches = Array.from(filters.querySelectorAll('[data-filter]')).every(function(control){
          return !control.value || row.dataset[control.dataset.filter] === control.value;
        });
        var query = filters.querySelector('input').value.trim().toLowerCase();
        return matches && (!query || row.textContent.toLowerCase().includes(query));
      });
      totalPages = Math.max(1, Math.ceil(filtered.length / pageSize)); page = Math.min(page, totalPages);
      var first = (page - 1) * pageSize;
      var visible = new Set(paginated ? filtered.slice(first, first + pageSize) : filtered);
      rows.forEach(function(row){
        row.style.display = visible.has(row) ? '' : 'none';
        var detail = details.get(row);
        if (detail) detail.style.display = visible.has(row) && detail.classList.contains('open') ? '' : 'none';
      });
      if (filters) document.getElementById('sensitive-count').textContent = '显示 ' + filtered.length + ' / ' + rows.length + ' 条';
      pager.innerHTML = !paginated || totalPages <= 1 ? '' :
        '<button data-go="prev"' + (page <= 1 ? ' disabled' : '') + '>上一页</button>' +
        '<span class="page-info">' + (filtered.length ? first + 1 : 0) + '-' + Math.min(first + pageSize, filtered.length) + ' / ' + filtered.length + '</span>' +
        '<button data-go="next"' + (page >= totalPages ? ' disabled' : '') + '>下一页</button>';
    }
    bindReportSort(table, function(column, direction){
      rows.sort(function(a,b){ return direction * compareReportValues(reportCellValue(a,column), reportCellValue(b,column)); });
      rows.forEach(function(row){ tbody.appendChild(row); if (details.get(row)) tbody.appendChild(details.get(row)); });
      page = 1; if (table.id !== 'param-table') apply();
    });
    pager.addEventListener('click', function(event){
      var go = event.target.dataset.go;
      if (go === 'prev' && page > 1) { page--; apply(); }
      if (go === 'next' && page < totalPages) { page++; apply(); }
    });
    // Existing parameter controls own their visibility; sorting must preserve it.
    if (table.id === 'param-table') return;
    apply();
  });

  // Row detail panel: clicking an endpoint row (tr.api-row) toggles the
  // full-width ctx-row right below it; the copy button is excluded so a
  // copy click never flips the panel.
  document.addEventListener('click', function(event){
    if (event.target.closest && event.target.closest('[data-copy]')) return;
    var row = event.target.closest ? event.target.closest('tr.api-row') : null;
    if (!row) return;
    var ctxRow = row.nextElementSibling;
    if (!ctxRow || ctxRow.className.indexOf('ctx-row') === -1) return;
    var open = ctxRow.className.indexOf(' open') === -1;
    ctxRow.className = open ? ctxRow.className + ' open' : ctxRow.className.replace(' open', '');
    row.className = open ? row.className + ' open' : row.className.replace(' open', '');
    if (open && row.style.display !== 'none') ctxRow.style.display = '';
    else ctxRow.style.display = 'none';
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
	tmpl, err := template.New("split").Funcs(reportFuncs).Parse(splitBase)
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
	b.WriteString(`<div class="filterbar"><span class="muted">点击路径旁的“复制”按钮复制纯路径；点击任意单元行展开详情面板：来源定位、RequestSpec（参数值、类型、置信度）、BaseURL 及 JS 上下文。完整 http(s) URL 见“完整 URL 报告”。</span></div>`)
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
	// The context button is gone: the whole row is the toggle now, and the
	// detail panel (context + request spec) expands in the full-width row
	// below so wide content wraps at the table width, not the path column.
	detail := renderAPIDetail(endpoint)
	rowClass := ""
	if detail != "" {
		rowClass = ` class="api-row"`
	}
	vendorMark := ""
	if endpoint.Vendor {
		vendorMark = `<span class="sev vendor">vendor</span>`
	}
	fmt.Fprintf(b,
		"<tr%s><td><code>%s</code><button class=\"copy-btn\" data-copy=\"%s\">复制</button>%s%s</td>"+
			"<td><b>%s</b></td><td><span class=\"sev %s\">%s</span></td>"+
			"<td><code>%s</code></td><td>%d</td></tr>",
		rowClass,
		htmlEscape(path), htmlEscape(path), bodyNote, vendorMark,
		htmlEscape(method), evidenceClass(endpoint.Evidence), htmlEscape(evidenceLabel(endpoint.Evidence)),
		htmlEscape(location), endpoint.StatusCode)
	if detail != "" {
		fmt.Fprintf(b,
			`<tr class="ctx-row"><td colspan="5">%s</td></tr>`,
			detail)
	}
}

// renderAPIDetail builds the expandable panel for one endpoint row: source
// location, the recovered RequestSpec (base URL and content type with their
// confidence, query/body parameters with value, type, and evidence), and the
// highlighted JS context. Empty when there is nothing beyond the table row.
func renderAPIDetail(endpoint model.Endpoint) string {
	var sections []string

	if endpoint.SourceURL != "" {
		location := htmlEscape(endpoint.SourceURL)
		if endpoint.Line > 0 {
			location += fmt.Sprintf(":%d:%d", endpoint.Line, endpoint.Column)
		}
		sections = append(sections,
			`<div><div class="detail-k">来源定位（回溯 JS 位置）</div><div class="detail-v"><code>`+location+`</code></div></div>`)
	}

	if spec := endpoint.Spec; spec != nil {
		var specRows []string
		if spec.BaseURL != "" {
			specRows = append(specRows, detailRow("BaseURL",
				`<code>`+htmlEscape(spec.BaseURL)+`</code> `+evidenceBadge(spec.BaseURLKind)))
		}
		if spec.ContentType != "" {
			specRows = append(specRows, detailRow("Content-Type",
				`<code>`+htmlEscape(spec.ContentType)+`</code> `+evidenceBadge(spec.ContentTypeEvidence)))
		}
		if len(spec.Query) > 0 {
			specRows = append(specRows, detailRow("Query 参数", renderParamTable(spec.Query)))
		}
		if len(spec.Body) > 0 {
			specRows = append(specRows, detailRow("Body 参数", renderParamTable(spec.Body)))
		}
		if len(specRows) > 0 {
			sections = append(sections,
				`<div class="detail-section"><div class="detail-k">RequestSpec</div>`+
					strings.Join(specRows, "")+`</div>`)
		}
	}

	if packet := renderRequestPacket(endpoint.Template); packet != "" {
		sections = append(sections,
			`<div class="detail-section"><div class="detail-k">请求包复原</div>`+packet+`</div>`)
	}

	if ai := renderTemplateAI(endpoint.Template); ai != "" {
		sections = append(sections,
			`<div class="detail-section"><div class="detail-k">AI 分析 <span class="sev ai">AI</span></div>`+ai+`</div>`)
	}

	if context := renderContextBlock(endpoint.ContextLines, endpoint.Raw, endpoint.URL); context != "" {
		sections = append(sections,
			`<div><div class="detail-k">匹配上下文（路径已高亮）</div>`+context+`</div>`)
	}

	if len(sections) == 0 {
		return ""
	}
	return `<div class="detail">` + strings.Join(sections, "") + `</div>`
}

func detailRow(label, value string) string {
	return `<div><div class="detail-k">` + label + `</div><div class="detail-v">` + value + `</div></div>`
}

// renderRequestPacket formats the reconstructed request as a copy-paste
// ready block: the method line and placeholders are highlighted, notes render
// as comments, and a copy button ships the plain text. Empty when the
// endpoint carries no template.
func renderRequestPacket(t *model.RequestTemplate) string {
	if t == nil || t.URL == "" {
		return ""
	}
	packet := analyze.RenderPacket(t)
	lines := strings.Split(packet, "\n")
	escaped := make([]string, 0, len(lines))
	for _, line := range lines {
		out := htmlEscape(line)
		switch {
		case strings.HasPrefix(line, "#"):
			out = `<span class="pkt-note">` + out + `</span>`
		default:
			out = highlightPlaceholders(out)
			if strings.Contains(line, " HTTP/1.1") {
				out = `<span class="pkt-method">` + out + `</span>`
			}
		}
		escaped = append(escaped, out)
	}
	body := strings.Join(escaped, "\n")
	return `<div class="pkt-wrap"><pre class="pkt-pre">` + body + `</pre>` +
		`<button class="copy-btn" data-copy="` + htmlEscape(packet) + `">复制请求包</button>` +
		`<div class="muted pkt-legend">{{fuzz:}} = 需构造测试值；{{cookie:}} = 需会话 cookie；# 开头为注意事项</div></div>`
}

// renderTemplateAI formats the AI review of one packet: completeness badge,
// authenticity assessment and suggested (not injected) parameters. Empty
// when no AI review exists.
func renderTemplateAI(t *model.RequestTemplate) string {
	if t == nil || t.AI == nil {
		return ""
	}
	var b strings.Builder
	if t.AI.Completeness != "" {
		class := "low"
		switch t.AI.Completeness {
		case "complete":
			class = "runtime"
		case "missing-fields":
			class = "high"
		}
		b.WriteString(`<div style="margin-bottom:6px"><span class="sev ` + class + `">` +
			htmlEscape(t.AI.Completeness) + `</span></div>`)
	}
	if t.AI.Assessment != "" {
		b.WriteString(`<div>` + htmlEscape(t.AI.Assessment) + `</div>`)
	}
	if len(t.AI.SuggestedParams) > 0 {
		b.WriteString(`<div class="muted">AI 建议关注的参数: ` +
			htmlEscape(strings.Join(t.AI.SuggestedParams, ", ")) + `</div>`)
	}
	if b.Len() == 0 {
		return ""
	}
	return b.String()
}

// highlightPlaceholders wraps {{...}} tokens in a colored span so fuzzer
// substitution points stand out from literal values.
func highlightPlaceholders(escapedLine string) string {
	if !strings.Contains(escapedLine, "{{") {
		return escapedLine
	}
	var b strings.Builder
	for {
		start := strings.Index(escapedLine, "{{")
		if start < 0 {
			b.WriteString(escapedLine)
			return b.String()
		}
		end := strings.Index(escapedLine[start:], "}}")
		if end < 0 {
			b.WriteString(escapedLine)
			return b.String()
		}
		end += start + 2
		b.WriteString(escapedLine[:start])
		b.WriteString(`<span class="pkt-ph">` + escapedLine[start:end] + `</span>`)
		escapedLine = escapedLine[end:]
	}
}

// renderParamTable lists one parameter list with the recovered value, the
// value's inferred type, and the evidence for the recovery — the triple an
// LLM (or a fuzzer) needs to decide what a field accepts.
func renderParamTable(params []model.Param) string {
	var b strings.Builder
	b.WriteString(`<table class="spec-table"><thead><tr><th>键</th><th>值</th><th>类型</th><th>置信度</th></tr></thead><tbody>`)
	for _, param := range params {
		value := htmlEscape(param.Value)
		if taint := taintHint(param.Taint); taint != "" {
			value += ` <span class="muted">← ` + taint + `</span>`
		}
		fmt.Fprintf(&b, "<tr><td><code>%s</code></td><td><code>%s</code></td><td>%s</td><td>%s</td></tr>",
			htmlEscape(param.Key), value,
			htmlEscape(paramValueType(param)), evidenceBadge(param.Evidence))
	}
	b.WriteString(`</tbody></table>`)
	return b.String()
}

// taintHint renders a one-line origin label for annotated placeholders.
func taintHint(t *model.Taint) string {
	if t == nil {
		return ""
	}
	switch t.Kind {
	case model.TaintUpstream:
		source := htmlEscape(t.Upstream)
		if t.UpstreamField != "" {
			source += " 的 " + htmlEscape(t.UpstreamField)
		}
		return "上游 " + source
	case model.TaintStorage:
		return "本地存储"
	case model.TaintRoute:
		return "路由参数"
	}
	return ""
}

// paramValueType classifies a recovered value so readers know what a field
// accepts without parsing the JS themselves.
func paramValueType(param model.Param) string {
	value := param.Value
	switch {
	case value == "{" || value == "[":
		return "对象/数组"
	case value == "" || value == "{}":
		return "未知"
	case param.Evidence == model.EvidencePlaceholder || strings.Contains(value, "{}"):
		return "动态"
	case value == "true" || value == "false":
		return "布尔"
	case value == "null" || value == "undefined":
		return "空值"
	case isNumericLiteral(value):
		return "数字"
	default:
		return "字符串"
	}
}

func isNumericLiteral(value string) bool {
	if value == "" {
		return false
	}
	_, err := strconv.ParseFloat(value, 64)
	return err == nil
}

// evidenceBadge renders a confidence level as a colored chip.
func evidenceBadge(evidence string) string {
	if evidence == "" {
		return ""
	}
	class := "static"
	switch evidence {
	case model.EvidenceLiteral:
		class = "runtime" // green: verbatim from source
	case model.EvidenceConstant:
		class = "full-url" // amber: resolved through a binding
	case model.EvidenceInferred:
		class = "low" // blue: deduced from payload shape
	}
	return `<span class="sev ` + class + `">` + htmlEscape(paramEvidenceLabel(evidence)) + `</span>`
}

func paramEvidenceLabel(evidence string) string {
	switch evidence {
	case model.EvidenceLiteral:
		return "字面量"
	case model.EvidenceConstant:
		return "常量回溯"
	case model.EvidenceInferred:
		return "推断"
	case model.EvidencePlaceholder:
		return "动态占位"
	}
	return evidence
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
		if line.MatchStart >= 0 && line.MatchEnd > line.MatchStart &&
			line.MatchEnd <= utf8.RuneCountInString(line.Content) {
			// Coordinates are authoritative: mark exactly the matched runes.
			marker = ">"
			runes := []rune(line.Content)
			content = htmlEscape(string(runes[:line.MatchStart])) +
				`<mark>` + htmlEscape(string(runes[line.MatchStart:line.MatchEnd])) + `</mark>` +
				htmlEscape(string(runes[line.MatchEnd:]))
		} else if marked, found := highlightFragments(
			line.Content, pathFragments(raw, resolved),
		); found {
			// No usable coordinates: fall back to searching the path text.
			marker = ">"
			content = marked
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
	if len(kept) == 0 && strings.Trim(source, "/?{}") != "" {
		// Placeholder-only or slash-heavy values carry no static fragment;
		// the raw text itself is still the best highlight needle.
		kept = append(kept, source)
	}
	return kept
}

// highlightFragments wraps every occurrence of the fragments with <mark>,
// escaping both the content and the fragments.
// highlightFragments wraps every occurrence of the fragments with <mark>,
// escaping both the content and the fragments. Overlapping matches (one
// fragment inside another, or the same fragment repeated) are merged into
// disjoint spans first so the marks never nest or shadow each other.
func highlightFragments(content string, fragments []string) (string, bool) {
	escaped := htmlEscape(content)
	type span struct{ start, end int }
	var spans []span
	for _, fragment := range fragments {
		needle := htmlEscape(fragment)
		if needle == "" {
			continue
		}
		for from := 0; ; {
			index := strings.Index(escaped[from:], needle)
			if index < 0 {
				break
			}
			start := from + index
			spans = append(spans, span{start, start + len(needle)})
			from = start + len(needle)
		}
	}
	if len(spans) == 0 {
		return escaped, false
	}
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].start != spans[j].start {
			return spans[i].start < spans[j].start
		}
		return spans[i].end > spans[j].end
	})
	merged := spans[:1]
	for _, current := range spans[1:] {
		last := &merged[len(merged)-1]
		if current.start <= last.end {
			if current.end > last.end {
				last.end = current.end
			}
			continue
		}
		merged = append(merged, current)
	}
	var b strings.Builder
	cursor := 0
	for _, current := range merged {
		if current.start < cursor {
			continue
		}
		b.WriteString(escaped[cursor:current.start])
		b.WriteString(`<mark>`)
		b.WriteString(escaped[current.start:current.end])
		b.WriteString(`</mark>`)
		cursor = current.end
	}
	b.WriteString(escaped[cursor:])
	return b.String(), true
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
	b.WriteString(`<div class="filterbar" id="sensitive-filters">
<label>严重性 <select data-filter="severity"><option value="">全部</option></select></label>
<label>规则 <select data-filter="rule"><option value="">全部</option></select></label>
<label>来源 <select data-filter="source"><option value="">全部</option></select></label>
<label>关键词 <input type="search" placeholder="搜索规则、值、来源或 AI 评估"></label>
<button type="button">重置筛选</button><span class="muted" id="sensitive-count" aria-live="polite"></span>
</div><table id="sensitive-table" class="paginated" data-page-size="50"><thead><tr><th style="width:90px">严重性</th><th style="width:200px">规则</th><th>完整值</th><th style="width:280px">来源</th><th style="width:220px">AI 评估</th></tr></thead><tbody>`)
	for _, finding := range findings {
		vendorMark := ""
		if finding.Vendor {
			vendorMark = ` <span class="sev vendor">vendor</span>`
		}
		aiCell := ""
		if ai := finding.AI; ai != nil {
			class := "low"
			switch ai.Rating {
			case "high":
				class = "high"
			case "medium":
				class = "full-url"
			}
			aiCell = `<span class="sev ` + class + `">` + htmlEscape(ai.Rating) + `</span>`
			if ai.Reason != "" {
				aiCell += `<div class="muted">` + htmlEscape(ai.Reason) + `</div>`
			}
			if ai.Suggestion != "" {
				aiCell += `<div class="muted">建议: ` + htmlEscape(ai.Suggestion) + `</div>`
			}
			aiCell += ` <span class="sev vendor">AI</span>`
		}
		fmt.Fprintf(&b,
			"<tr data-severity=\"%s\" data-rule=\"%s\" data-source=\"%s\"><td><span class=\"sev %s\">%s</span></td><td>%s%s<div class=\"muted\">%s</div></td><td><code>%s</code></td><td><code>%s</code><div class=\"muted\">行 %d 列 %d</div></td><td>%s</td></tr>",
			htmlEscape(string(finding.Severity)), htmlEscape(finding.RuleName+" ("+finding.RuleID+")"), htmlEscape(finding.SourceURL),
			htmlEscape(string(finding.Severity)), htmlEscape(string(finding.Severity)),
			htmlEscape(finding.RuleName), vendorMark, htmlEscape(finding.RuleID),
			htmlEscape(finding.Value), htmlEscape(finding.SourceURL),
			finding.Line, finding.Column, aiCell)
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
	Name     string
	Count    int
	Hosts    []string
	Sources  []string
	Body     bool
	Response bool
	// Scenarios lists the extraction scenarios the name was recovered from
	// (对象属性 / 解构赋值 / ...), ordered by model.ParamScenarioLabel.
	Scenarios []string
	// CodeLocs carries the distinct JS files a name was found in (no line
	// numbers), for the 来源 column.
	CodeLocs []string
}

// maxSourceLinks caps how many distinct JS files the 来源 column lists for one
// parameter, so a name spread across a bundle farm cannot bloat the cell.
const maxSourceLinks = 3

// codeShapeScenarios lists the ParamHit scenarios that exist only as source
// shapes. They never appear in a URL, so the endpoint pass below cannot see
// them and their count/host/extractor cells would render empty unless the
// inventory merge counts them itself.
var codeShapeScenarios = map[string]bool{
	model.ParamScenarioObjectProperty:     true,
	model.ParamScenarioDestructuring:      true,
	model.ParamScenarioNestedDestructurin: true,
	model.ParamScenarioFunctionParam:      true,
	model.ParamScenarioVariable:           true,
	model.ParamScenarioConfigObject:       true,
}

// collectParameterStats merges URL query parameters and AST body parameters
// into per-name statistics.
func collectParameterStats(result *model.Result) []parameterStat {
	type entry struct {
		count    int
		hosts    map[string]bool
		sources  map[string]bool
		body     bool
		response bool
	}
	stats := map[string]*entry{}
	add := func(name, sourceURL, extractor string, isBody, isResponse bool) {
		stat, exists := stats[name]
		if !exists {
			stat = &entry{hosts: map[string]bool{}, sources: map[string]bool{}}
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
	// Scenario badges for the URL-derivable shapes; code-shape scenarios
	// come from result.Params further down.
	urlScenario := map[string]bool{}
	bodyScenario := map[string]bool{}
	routeScenario := map[string]map[string]bool{}
	for _, endpoint := range result.Endpoints {
		if endpoint.Type == "route" {
			set := map[string]bool{}
			for _, name := range model.RouteParamNames(endpoint.URL) {
				set[name] = true
			}
			routeScenario[endpoint.URL] = set
			continue
		}
		if parsed, err := url.Parse(endpoint.URL); err == nil {
			for key := range parsed.Query() {
				urlScenario[key] = true
			}
		}
		for _, name := range endpoint.BodyParams {
			bodyScenario[name] = true
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
		if endpoint.Type == "route" {
			for name := range routeScenario[endpoint.URL] {
				add(name, endpoint.URL, extractor, false, false)
			}
			continue
		}
		if parsed, err := url.Parse(endpoint.URL); err == nil {
			for key := range parsed.Query() {
				add(key, endpoint.URL, extractor, false, false)
			}
		}
		for _, name := range endpoint.BodyParams {
			add(name, endpoint.URL, extractor, true, false)
		}
		for _, name := range endpoint.ResponseParams {
			add(name, endpoint.URL, extractor, false, true)
		}
	}
	for _, resource := range result.Resources {
		parsed, err := url.Parse(resource.URL)
		if err != nil {
			continue
		}
		for key := range parsed.Query() {
			add(key, resource.URL, "url", false, false)
		}
	}

	// Merge the scenario-tagged parameter inventory (result.Params) into the
	// same per-name statistics: scenario badges plus code locations.
	scenarios := map[string]map[string]bool{}
	for name := range urlScenario {
		scenarios[name] = map[string]bool{model.ParamScenarioURLQuery: true}
	}
	for name := range bodyScenario {
		if scenarios[name] == nil {
			scenarios[name] = map[string]bool{}
		}
		scenarios[name][model.ParamScenarioAPIRequest] = true
	}
	for _, sets := range routeScenario {
		for name := range sets {
			if scenarios[name] == nil {
				scenarios[name] = map[string]bool{}
			}
			scenarios[name][model.ParamScenarioRouteParam] = true
		}
	}
	locations := map[string][]string{}
	located := map[string]map[string]bool{}
	for _, hit := range result.Params {
		if hit.Name == "" {
			continue
		}
		set, exists := scenarios[hit.Name]
		if !exists {
			set = map[string]bool{}
			scenarios[hit.Name] = set
		}
		set[hit.Scenario] = true
		// Request-shaped hits (url_query / api_request / route_param) were
		// already counted from the endpoints above, so re-adding them here
		// would double the count. Code-shape hits have no endpoint row, so
		// this is the only place that fills their count, hosts and extractor.
		if codeShapeScenarios[hit.Scenario] {
			add(hit.Name, hit.SourceURL, "ast", false, false)
		}
		// 来源 keeps the JS file the name was found in, one link per distinct
		// file and no line number. hits without a located line (url_query)
		// point at an API URL rather than a JS file, so they are skipped.
		if hit.Line > 0 && hit.SourceURL != "" {
			seen := located[hit.Name]
			if seen == nil {
				seen = map[string]bool{}
				located[hit.Name] = seen
			}
			if !seen[hit.SourceURL] && len(locations[hit.Name]) < maxSourceLinks {
				seen[hit.SourceURL] = true
				locations[hit.Name] = append(locations[hit.Name], hit.SourceURL)
			}
		}
	}

	names := make([]string, 0, len(stats))
	for name := range stats {
		names = append(names, name)
	}
	for name := range scenarios {
		if _, exists := stats[name]; !exists {
			// Code-shape-only parameters (destructuring, function params, ...)
			// never appear in a URL; they still deserve a row.
			names = append(names, name)
			stats[name] = &entry{
				hosts: map[string]bool{}, sources: map[string]bool{},
			}
		}
	}
	sort.Strings(names)
	rows := make([]parameterStat, 0, len(names))
	for _, name := range names {
		stat := stats[name]
		row := parameterStat{
			Name: name, Count: stat.count,
			Body: stat.body, Response: stat.response,
			CodeLocs: locations[name],
		}
		for scenario := range scenarios[name] {
			row.Scenarios = append(row.Scenarios, scenario)
		}
		sort.Slice(row.Scenarios, func(i, j int) bool {
			return model.ParamScenarioLabel(row.Scenarios[i]) <
				model.ParamScenarioLabel(row.Scenarios[j])
		})
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
<label>搜索 <input type="search" id="param-search" placeholder="参数名、域名或来源..."></label>
<span class="muted" id="param-count"></span>
</div>
<table id="param-table"><thead><tr><th style="width:160px">参数名</th><th style="width:200px">场景</th><th style="width:60px">次数</th><th style="width:200px">域名</th><th style="width:110px">提取方式</th><th>来源</th></tr></thead><tbody>`)
	for _, row := range rows {
		markers := ""
		if row.Body {
			markers = ` <span class="sev full-url">body</span>`
		}
		if row.Response {
			markers += ` <span class="sev runtime">response</span>`
		}
		var scenarioBadges strings.Builder
		for _, scenario := range row.Scenarios {
			scenarioBadges.WriteString(
				`<span class="sev scen">` + htmlEscape(model.ParamScenarioLabel(scenario)) + `</span> `)
		}
		// The JS source location lives in its own column, not under the name:
		// every code-shape hit contributes one source:line entry (capped
		// upstream), each on its own line.
		var sourceLocs strings.Builder
		for _, loc := range row.CodeLocs {
			sourceLocs.WriteString(`<div><code>` + htmlEscape(loc) + `</code></div>`)
		}
		fmt.Fprintf(&b,
			"<tr data-hosts=%q><td><code>%s</code>%s</td><td>%s</td><td>%d</td><td class=\"muted\">%s</td><td>%s</td><td>%s</td></tr>",
			strings.Join(row.Hosts, " "), htmlEscape(row.Name), markers,
			scenarioBadges.String(),
			row.Count, htmlEscape(strings.Join(row.Hosts, ", ")),
			htmlEscape(strings.Join(row.Sources, ", ")),
			sourceLocs.String())
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
	case "prefix":
		return "前缀拼接"
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

// hostReportEvidence is one evidence entry with the population it came from.
type hostReportEvidence struct {
	source model.HostEvidence
	origin string
}

// hostReportRow merges one host as seen in both populations.
type hostReportRow struct {
	asset    model.HostAsset
	origins  []string
	evidence []hostReportEvidence
}

// renderHostReport lists the discovered host assets, grouped by kind. It reads
// the classification the scan already computed — the same one the interactive
// report and the plain-text lists use — so every output agrees on what is a
// domain, an address or an internal-host candidate.
func renderHostReport(result *model.Result) (int, string, error) {
	index := map[string]*hostReportRow{}
	order := make([]string, 0, len(result.Hosts)+8)
	add := func(asset model.HostAsset) {
		if asset.Value == "" {
			return
		}
		// Host values are validated LDH text, so "|" cannot appear in one and
		// is safe as a composite key separator.
		key := string(asset.Kind) + "|" + asset.Value
		entry, exists := index[key]
		if !exists {
			entry = &hostReportRow{asset: asset}
			entry.asset.Sources = nil
			index[key] = entry
			order = append(order, key)
		}
		origin := "内容发现"
		if asset.Origin == model.HostOriginScan {
			origin = "扫描关联"
		}
		known := false
		for _, existing := range entry.origins {
			if existing == origin {
				known = true
			}
		}
		if !known {
			entry.origins = append(entry.origins, origin)
		}
		entry.asset.Occurrences += asset.Occurrences
		entry.asset.Vendor = entry.asset.Vendor && asset.Vendor
		if entry.asset.Zone == "" {
			entry.asset.Zone = asset.Zone
		}
		if len(entry.asset.Attributes) == 0 {
			entry.asset.Attributes = asset.Attributes
		}
		for _, source := range asset.Sources {
			entry.evidence = append(entry.evidence, hostReportEvidence{source: source, origin: origin})
		}
	}
	for _, asset := range result.Hosts {
		add(asset)
	}
	for _, asset := range ensureScanHosts(result) {
		add(asset)
	}

	rows := make([]*hostReportRow, 0, len(order))
	for _, key := range order {
		rows = append(rows, index[key])
	}
	sort.SliceStable(rows, func(i, j int) bool {
		left, right := rows[i].asset, rows[j].asset
		if left.Kind != right.Kind {
			return hostKindRank(left.Kind) < hostKindRank(right.Kind)
		}
		return left.Value < right.Value
	})

	summary := buildHostSummary(result, newHostIndex(nil))

	var b strings.Builder
	b.WriteString(`<div class="filterbar"><span class="muted">`)
	b.WriteString(htmlEscape(
		"本页列出本次扫描发现的主机资产：域名、IPv4、IPv6 与内部主机候选。" +
			"“内容发现”指出现在被分析内容（JavaScript、内联脚本、文档、source map）中的主机值；" +
			"“扫描关联”指本次扫描实际访问或被引用对象所属主机（目标、资源、端点、发现来源）。" +
			"两类使用同一套归一化与公共后缀分类规则，分别计数、不合并汇总。" +
			"提取不执行目标代码、不做 DNS 查询、不做连通性探测：出现在本页不代表主机可访问或存在漏洞；" +
			"内部主机候选不计入域名统计。",
	))
	b.WriteString(`</span></div>`)

	b.WriteString(`<h2 class="section-title">主机类型统计</h2><table><thead><tr>` +
		`<th style="width:220px">类型</th><th style="width:160px">内容发现</th>` +
		`<th style="width:160px">扫描关联</th></tr></thead><tbody>`)
	for _, metric := range summary.Metrics {
		fmt.Fprintf(&b, "<tr><td>%s</td><td>%d</td><td>%d</td></tr>",
			htmlEscape(metric.Label), metric.Content, metric.Scan)
	}
	fmt.Fprintf(&b, "<tr><td>合计（去重前）</td><td>%d</td><td>%d</td></tr>"+
		"<tr><td>两类重合主机</td><td colspan=\"2\">%d</td></tr></tbody></table>",
		summary.ContentTotal, summary.ScanTotal, summary.Correlated)
	if unresolved := unresolvedReferenceCount(result); unresolved > 0 {
		fmt.Fprintf(&b, `<p class="muted">另有 %d 条扫描引用（端点、资源或发现来源）无法解析出主机，`+
			`通常是相对路径；它们不归属目标域名，也不计入上面的主机统计。</p>`, unresolved)
	}

	currentKind := model.HostKind("")
	for _, entry := range rows {
		asset := entry.asset
		if asset.Kind != currentKind {
			if currentKind != "" {
				b.WriteString(`</tbody></table>`)
			}
			currentKind = asset.Kind
			fmt.Fprintf(&b, `<h2 class="section-title">%s（%d）</h2>`+
				`<table class="paginated" data-page-size="50"><thead><tr>`+
				`<th>主机</th><th style="width:170px">可注册域</th>`+
				`<th style="width:120px">公共后缀</th><th style="width:100px">子域</th>`+
				`<th style="width:130px">后缀状态</th><th style="width:150px">地址属性</th>`+
				`<th style="width:90px">出现次数</th><th style="width:130px">数据来源</th>`+
				`<th style="width:80px">来源数</th><th style="width:280px">首个来源位置</th>`+
				`</tr></thead><tbody>`,
				htmlEscape(hostKindLabel(string(asset.Kind))), rowsForKind(rows, asset.Kind))
		}
		b.WriteString("<tr>")
		fmt.Fprintf(&b, `<td><code>%s</code><button class="copy-btn" data-copy="%s">复制</button>`,
			htmlEscape(asset.Value), htmlEscape(asset.Value))
		if asset.Zone != "" {
			fmt.Fprintf(&b, `<div class="muted">区域: %s</div>`, htmlEscape(asset.Zone))
		}
		if asset.Vendor {
			b.WriteString(` <span class="sev vendor">vendor</span>`)
		}
		b.WriteString("</td>")
		fmt.Fprintf(&b, "<td><code>%s</code></td>", htmlEscape(asset.RegistrableDomain))
		fmt.Fprintf(&b, "<td><code>%s</code></td>", htmlEscape(asset.PublicSuffix))
		fmt.Fprintf(&b, "<td><code>%s</code></td>", htmlEscape(asset.Subdomain))
		fmt.Fprintf(&b, "<td>%s</td>", htmlEscape(hostSuffixStatusLabel(asset.SuffixStatus)))
		attributes := make([]string, 0, len(asset.Attributes))
		for _, attribute := range asset.Attributes {
			attributes = append(attributes, hostAttributeLabel(attribute))
		}
		fmt.Fprintf(&b, `<td class="muted">%s</td>`, htmlEscape(strings.Join(attributes, ", ")))
		fmt.Fprintf(&b, "<td>%d</td>", asset.Occurrences)
		fmt.Fprintf(&b, `<td class="muted">%s</td>`, htmlEscape(strings.Join(entry.origins, " / ")))
		fmt.Fprintf(&b, "<td>%d</td>", len(entry.evidence))
		b.WriteString("<td>")
		if len(entry.evidence) == 0 {
			b.WriteString(`<span class="muted">无来源记录</span>`)
		} else {
			first := entry.evidence[0]
			location := first.source.SourceURL
			if first.source.Line > 0 {
				location = fmt.Sprintf("%s:%d:%d", location, first.source.Line, first.source.Column)
			}
			fmt.Fprintf(&b, "<code>%s</code>", htmlEscape(location))
			fmt.Fprintf(&b, `<div class="muted">%s · %s%s</div>`,
				htmlEscape(hostMethodLabel(first.source.Method)),
				htmlEscape(first.origin),
				htmlEscape(hostNoteSuffix(first.source.Note)))
			if first.source.Raw != "" && first.source.Raw != asset.Value {
				fmt.Fprintf(&b, `<div class="muted">原始值: <code>%s</code></div>`,
					htmlEscape(first.source.Raw))
			}
			if len(first.source.ContextLines) > 0 {
				b.WriteString(renderContextBlock(first.source.ContextLines, first.source.Raw, asset.Value))
			}
			if len(entry.evidence) > 1 {
				fmt.Fprintf(&b, `<details class="ctx"><summary>其余 %d 条来源</summary><pre>`,
					len(entry.evidence)-1)
				for _, extra := range entry.evidence[1:] {
					source := extra.source
					line := source.SourceURL
					if source.Line > 0 {
						line = fmt.Sprintf("%s:%d:%d", line, source.Line, source.Column)
					}
					fmt.Fprintf(&b, "%s  [%s · %s%s]\n", htmlEscape(line),
						htmlEscape(hostMethodLabel(source.Method)),
						htmlEscape(extra.origin), htmlEscape(hostNoteSuffix(source.Note)))
				}
				b.WriteString("</pre></details>")
			}
		}
		b.WriteString("</td></tr>")
	}
	if currentKind != "" {
		b.WriteString(`</tbody></table>`)
	}
	if len(rows) == 0 {
		b.WriteString(`<p class="muted">本次未发现主机。</p>`)
	}
	b.WriteString(`<h2 class="section-title">统计口径与限制</h2><ul class="muted">`)
	for _, note := range summary.Notes {
		fmt.Fprintf(&b, "<li>%s</li>", htmlEscape(note))
	}
	if summary.PSLVersion != "" {
		status := "正常"
		if summary.PSLStatus != "ok" {
			status = "未解析（域名层级未计算）"
		}
		fmt.Fprintf(&b, "<li>公共后缀列表快照：%s（%s），状态 %s</li>",
			htmlEscape(summary.PSLVersion), htmlEscape(summary.PSLCommit), htmlEscape(status))
	}
	b.WriteString("</ul>")
	return len(rows), b.String(), nil
}

// unresolvedReferenceCount counts the scan references that carry no host at
// all, so the page can say how much of the scan is not represented in a host
// list instead of silently omitting it.
func unresolvedReferenceCount(result *model.Result) int {
	count := 0
	seen := map[string]bool{}
	note := func(raw string) {
		if raw == "" || seen[raw] {
			return
		}
		seen[raw] = true
		if hostOf(raw) == "" {
			count++
		}
	}
	for _, endpoint := range result.Endpoints {
		note(endpointKey(endpoint))
	}
	for _, resource := range result.Resources {
		note(resource.URL)
	}
	for _, finding := range result.Findings {
		note(finding.SourceURL)
	}
	return count
}

// rowsForKind counts the rows one kind contributes, for its section heading.
func rowsForKind(rows []*hostReportRow, kind model.HostKind) int {
	count := 0
	for _, entry := range rows {
		if entry.asset.Kind == kind {
			count++
		}
	}
	return count
}

// hostKindRank fixes the section order: domains first, then addresses, then
// internal-host candidates.
func hostKindRank(kind model.HostKind) int {
	switch kind {
	case model.HostKindDomain:
		return 0
	case model.HostKindIPv4:
		return 1
	case model.HostKindIPv6:
		return 2
	case model.HostKindInternal:
		return 3
	}
	return 4
}

// hostSuffixStatusLabel renders the suffix resolution outcome for readers.
func hostSuffixStatusLabel(status string) string {
	switch status {
	case model.SuffixRecognized:
		return "已识别后缀"
	case model.SuffixCustom:
		return "自定义/保留后缀"
	case model.SuffixUnknown:
		return "无后缀规则"
	case model.SuffixUnresolved:
		return "层级未解析"
	case model.SuffixNotApplicable:
		return "不适用"
	}
	return status
}

// hostAttributeLabel renders one address attribute. The wording never claims
// reachability: an unclassified address is simply not classified.
func hostAttributeLabel(attribute string) string {
	switch attribute {
	case model.HostAttrPrivate:
		return "私网"
	case model.HostAttrLoopback:
		return "回环"
	case model.HostAttrLinkLocal:
		return "链路本地"
	case model.HostAttrMulticast:
		return "组播"
	case model.HostAttrUnspecified:
		return "未指定"
	case model.HostAttrUnclassified:
		return "未分类（未判定可达性）"
	}
	return attribute
}

// hostMethodLabel renders how one host value was recovered.
func hostMethodLabel(method string) string {
	switch method {
	case model.HostMethodURL:
		return "URL 解析"
	case model.HostMethodASTLiteral:
		return "AST 字面量"
	case model.HostMethodStaticExpression:
		return "静态表达式"
	case model.HostMethodRegex:
		return "正则兜底"
	}
	return method
}

// hostNoteLabel renders the notes attached to one evidence entry.
func hostNoteLabel(note string) string {
	labels := map[string]string{
		extract.HostRoleTarget:        "扫描目标",
		extract.HostRoleResource:      "资源",
		extract.HostRoleEndpoint:      "端点",
		extract.HostRoleEndpointFrom:  "端点来源",
		extract.HostRoleFindingSource: "发现来源",
		"email_domain":                "邮箱域名",
		"comment":                     "注释",
		"dynamic_host":                "动态表达式",
		"reserved":                    "保留/特殊用途",
		"public_suffix_only":          "公共后缀本身",
	}
	rendered := make([]string, 0, 4)
	for _, part := range strings.Split(note, ",") {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		if label, ok := labels[trimmed]; ok {
			rendered = append(rendered, label)
			continue
		}
		rendered = append(rendered, trimmed)
	}
	return strings.Join(rendered, "、")
}

// hostNoteSuffix renders a note as an inline suffix, empty when there is none.
func hostNoteSuffix(note string) string {
	if strings.TrimSpace(note) == "" {
		return ""
	}
	return " · " + hostNoteLabel(note)
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
