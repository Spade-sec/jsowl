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
			method = "GET"
		}
		source := endpoint.SourceURL
		if source == "" {
			source = result.Target
		}
		fmt.Fprintf(&b,
			"<tr><td><b>%s</b></td><td><span class=\"sev %s\">%s</span></td><td><code>%s</code></td><td><code>%s</code></td><td>%t</td><td>%d</td></tr>",
			htmlEscape(method), evidenceClass(endpoint.Evidence), htmlEscape(evidenceLabel(endpoint.Evidence)),
			htmlEscape(endpoint.URL), htmlEscape(source), endpoint.Authorized, endpoint.StatusCode)
	}
	b.WriteString("</tbody></table>")
	return len(endpoints), b.String(), nil
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

func renderParameterReport(result *model.Result) (int, string, error) {
	rows := collectParameterRows(result)
	var b strings.Builder
	b.WriteString(`<table><thead><tr><th style="width:200px">参数名</th><th style="width:320px">示例值</th><th>首次出现</th></tr></thead><tbody>`)
	for _, row := range rows {
		fmt.Fprintf(&b, "<tr><td><code>%s</code></td><td><code>%s</code></td><td><code>%s</code></td></tr>",
			htmlEscape(row.Name), htmlEscape(row.Value), htmlEscape(row.Source))
	}
	b.WriteString("</tbody></table>")
	return len(rows), b.String(), nil
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

func htmlEscape(value string) string {
	return strings.NewReplacer(
		"&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;",
	).Replace(value)
}
