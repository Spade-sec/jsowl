package report

import (
	"fmt"
	"net/url"
	"path/filepath"
	"sort"
	"strings"

	"github.com/youmulijiang/jsowl/internal/model"
)

// WriteTextReports writes the plain-text companion reports next to the
// JSON/HTML reports: api绝对路径.txt, api相对路径.txt, url.txt,
// 参数.txt, 敏感信息.txt and 路由.txt.
func WriteTextReports(directory string, result *model.Result) error {
	files := []struct {
		name string
		data func() []byte
	}{
		{"api绝对路径.txt", func() []byte { return renderAPIAbsolute(result) }},
		{"api相对路径.txt", func() []byte { return renderAPIRelative(result) }},
		{"url.txt", func() []byte { return renderURLs(result) }},
		{"参数.txt", func() []byte { return renderParameters(result) }},
		{"domain.txt", func() []byte { return renderHostValues(result, model.HostKindDomain) }},
		{"ip.txt", func() []byte { return renderHostValues(result, model.HostKindIPv4, model.HostKindIPv6) }},
		{"internal_hosts.txt", func() []byte { return renderHostValues(result, model.HostKindInternal) }},
		{"敏感信息.txt", func() []byte { return renderSensitive(result) }},
		{"路由.txt", func() []byte { return renderRoutes(result) }},
		{"扫描完整性.txt", func() []byte { return renderCompleteness(result) }},
		{"AI分析.txt", func() []byte { return renderAI(result) }},
	}
	for _, file := range files {
		path := filepath.Join(directory, file.name)
		if err := writeAtomic(path, file.data()); err != nil {
			return err
		}
	}
	return nil
}

// isFullURL reports whether the endpoint's source reference is a complete
// http(s) URL — those belong in the URL report, not in path reports.
func isFullURL(raw string) bool {
	parsed, err := url.Parse(raw)
	return err == nil &&
		(parsed.Scheme == "http" || parsed.Scheme == "https") &&
		parsed.Host != ""
}

// renderURLs lists every full http(s) URL observed across endpoints and
// resources, one per line, deduplicated and sorted.
func renderURLs(result *model.Result) []byte {
	var out []byte
	seen := make(map[string]struct{})
	urls := make([]string, 0)
	add := func(raw string) {
		if raw == "" || !isFullURL(raw) {
			return
		}
		if _, duplicate := seen[raw]; duplicate {
			return
		}
		seen[raw] = struct{}{}
		urls = append(urls, raw)
	}
	for _, endpoint := range result.Endpoints {
		add(endpoint.Raw)
		add(endpoint.URL)
	}
	for _, resource := range result.Resources {
		add(resource.URL)
	}
	sort.Strings(urls)
	for _, raw := range urls {
		out = append(out, []byte(raw+"\n")...)
	}
	if len(urls) == 0 {
		return append(out, []byte("（未发现完整 URL）\n")...)
	}
	return out
}

// sanitizeText drops invalid UTF-8 bytes from legacy-charset page bodies.
func sanitizeText(value string) string {
	return strings.ToValidUTF8(value, "�")
}

// renderAPIAbsolute lists every absolute path ("/a/b/c?x=1"), one per line,
// deduplicated and sorted. It uses the same classification as the API report
// so the counts agree; full URLs live in url.txt instead.
func renderAPIAbsolute(result *model.Result) []byte {
	var out []byte
	seen := make(map[string]struct{}, len(result.Endpoints))
	paths := make([]string, 0, len(result.Endpoints))
	for _, endpoint := range result.Endpoints {
		path, kind := classifyAPIPath(endpoint)
		if kind != apiPathAbsolute {
			continue
		}
		if _, duplicate := seen[path]; duplicate {
			continue
		}
		seen[path] = struct{}{}
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		out = append(out, []byte(path+"\n")...)
	}
	return out
}

// renderAPIRelative lists every relative path ("a/b/c", "./a/b?x=1"), one per
// line, deduplicated and sorted.
func renderAPIRelative(result *model.Result) []byte {
	var out []byte
	seen := make(map[string]struct{}, len(result.Endpoints))
	paths := make([]string, 0, len(result.Endpoints))
	for _, endpoint := range result.Endpoints {
		path, kind := classifyAPIPath(endpoint)
		if kind != apiPathRelative || path == "" {
			continue
		}
		if _, duplicate := seen[path]; duplicate {
			continue
		}
		seen[path] = struct{}{}
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		out = append(out, []byte(path+"\n")...)
	}
	return out
}

// renderRoutes lists every framework route path, one per line.
func renderRoutes(result *model.Result) []byte {
	var out []byte
	count := 0
	for _, endpoint := range result.Endpoints {
		if endpoint.Type != "route" {
			continue
		}
		count++
		line := endpoint.URL
		if endpoint.Probe != "" {
			line += "\t[" + endpoint.Probe + "]"
		}
		out = append(out, []byte(sanitizeText(line+"\n"))...)
	}
	if count == 0 {
		return append(out, []byte("（未发现路由）\n")...)
	}
	return out
}

// renderParameters lists every unique query or body parameter name, one per
// line, with no values or annotations so the file can feed tools directly. It
// shares collectParameterNames with the report summary so the two agree.
func renderParameters(result *model.Result) []byte {
	var out strings.Builder
	for _, name := range collectParameterNames(result) {
		out.WriteString(name + "\n")
	}
	return []byte(out.String())
}

// renderSensitive lists every sensitive-category finding with its severity,
// matched value and source location.
func renderSensitive(result *model.Result) []byte {
	var out []byte
	count := 0
	for _, finding := range result.Findings {
		if finding.Category != model.RuleCategorySensitive {
			continue
		}
		count++
		line := fmt.Sprintf(
			"[%s] %s (%s)\n  值: %s\n  来源: %s:%d:%d\n\n",
			finding.Severity, finding.RuleName, finding.RuleID,
			finding.Value, finding.SourceURL, finding.Line, finding.Column,
		)
		out = append(out, []byte(line)...)
	}
	if count == 0 {
		return append(out, []byte("（未发现敏感信息）\n")...)
	}
	return out
}

// renderAI writes the agent's report-level supplement (ai.mode: agent): an
// executive overview, the prioritized testing queue and phase statistics.
// Everything here is advisory prose; the deterministic reports above carry
// the scan's actual findings.
func renderAI(result *model.Result) []byte {
	if result.AI == nil {
		return []byte("（本次未运行 AI agent 分析；需 -ai 且 ai.mode: agent）\n")
	}
	var out strings.Builder
	ai := result.AI
	if stats := ai.Stats; stats != nil {
		line := fmt.Sprintf("AI agent: %s（%d 轮 / %d 次请求", stats.Status, stats.Steps, stats.Requests)
		if stats.Reviews+stats.Taints+stats.Ratings > 0 {
			line += fmt.Sprintf("，合并 复核%d 污点%d 评级%d", stats.Reviews, stats.Taints, stats.Ratings)
		}
		line += "）"
		if stats.Reason != "" {
			line += "\n  说明: " + stats.Reason
		}
		out.WriteString(line + "\n\n")
	}
	if ai.Overview != "" {
		out.WriteString("## 总评\n" + sanitizeText(ai.Overview) + "\n\n")
	}
	if len(ai.Priorities) > 0 {
		out.WriteString("## 优先测试队列\n")
		for i, priority := range ai.Priorities {
			fmt.Fprintf(&out, "%d. %s", i+1, priority.Target)
			if priority.Kind != "" {
				out.WriteString(" [" + priority.Kind + "]")
			}
			out.WriteString("\n")
			if priority.Reason != "" {
				out.WriteString("   理由: " + sanitizeText(priority.Reason) + "\n")
			}
			for _, test := range priority.Tests {
				out.WriteString("   测试: " + sanitizeText(test) + "\n")
			}
		}
		out.WriteString("\n")
	}
	if len(ai.Notes) > 0 {
		out.WriteString("## 横切观察\n")
		for _, note := range ai.Notes {
			out.WriteString("- " + sanitizeText(note) + "\n")
		}
		out.WriteString("\n")
	}
	if out.Len() == 0 {
		return []byte("（AI agent 未产出摘要内容）\n")
	}
	return []byte(out.String())
}

// renderCompleteness writes the scan completeness status: whether network
// collection and local analysis each finished, the auditable per-resource
// counts, and every unfinished resource with its reason. Counts refer to
// unique canonical resources; when collection is incomplete, the discovered
// count is a lower bound, never a claim about every script the site has.
func renderCompleteness(result *model.Result) []byte {
	completeness := result.Completeness
	if completeness == nil {
		return []byte("（本次结果未记录完整性状态）\n")
	}
	var out strings.Builder
	phaseLine := func(label string, phase model.PhaseCompleteness) string {
		status := "完成"
		if !phase.Complete {
			status = "不完整"
		}
		line := label + ": " + status
		if phase.Reason != "" {
			line += "（" + sanitizeText(phase.Reason) + "）"
		}
		return line
	}
	out.WriteString(phaseLine("网络采集", completeness.Collection) + "\n")
	out.WriteString(phaseLine("JS 本地分析", completeness.Analysis) + "\n\n")
	coverage := completeness.Coverage
	out.WriteString("统计口径：唯一资源数（按解析后 URL 去重；重复发现不重复计数）。\n")
	if !completeness.Collection.Complete {
		out.WriteString("注意：采集不完整时，已发现数量是下限，不代表该网站全部 JS。\n")
	}
	fmt.Fprintf(&out, "发现 JS: %d（获取成功 %d + 获取失败 %d + 策略跳过 %d + 未抓取 %d）\n",
		coverage.Discovered, coverage.Fetched, coverage.FetchFailed,
		coverage.FetchSkipped, coverage.FetchNotAttempted)
	fmt.Fprintf(&out, "已获取 JS: %d（分析成功 %d + 分析失败 %d + 策略跳过 %d + 未分析 %d）\n",
		coverage.Fetched, coverage.Analyzed, coverage.AnalysisFailed,
		coverage.AnalysisSkipped, coverage.AnalysisPending)
	if len(coverage.Unfinished) == 0 && coverage.UnfinishedOmitted == 0 {
		out.WriteString("\n无未完成资源。\n")
		return []byte(out.String())
	}
	out.WriteString("\n未完成资源:\n")
	for _, item := range coverage.Unfinished {
		line := "- [" + item.Stage + "/" + item.State + "] " + item.URL
		if item.Reason != "" {
			line += " — " + sanitizeText(item.Reason)
		}
		out.WriteString(line + "\n")
	}
	if coverage.UnfinishedOmitted > 0 {
		fmt.Fprintf(&out, "…另有 %d 条未列出（计数已包含在上面的统计中）。\n",
			coverage.UnfinishedOmitted)
	}
	return []byte(out.String())
}

// renderHostValues writes the normalized, deduplicated values of the requested
// host kinds, one per line: the union of the hosts found in content and the
// hosts the scan touched. Values are exactly what the report and the JSON
// carry, so a tool consuming the list sees the same identity the report does.
func renderHostValues(result *model.Result, kinds ...model.HostKind) []byte {
	wanted := make(map[model.HostKind]struct{}, len(kinds))
	for _, kind := range kinds {
		wanted[kind] = struct{}{}
	}
	seen := make(map[string]struct{})
	var values []string
	collect := func(assets []model.HostAsset) {
		for _, asset := range assets {
			if _, ok := wanted[asset.Kind]; !ok {
				continue
			}
			if asset.Value == "" {
				continue
			}
			if _, duplicate := seen[asset.Value]; duplicate {
				continue
			}
			seen[asset.Value] = struct{}{}
			values = append(values, asset.Value)
		}
	}
	collect(result.Hosts)
	collect(ensureScanHosts(result))
	sort.Strings(values)

	title := hostValuesTitle(kinds)
	var out []byte
	for _, value := range values {
		out = append(out, []byte(value+"\n")...)
	}
	if len(values) == 0 {
		return append(out, []byte("（本次未发现"+title+"）\n")...)
	}
	return out
}

func hostValuesTitle(kinds []model.HostKind) string {
	switch {
	case len(kinds) == 1 && kinds[0] == model.HostKindDomain:
		return "域名"
	case len(kinds) == 1 && kinds[0] == model.HostKindInternal:
		return "内部主机候选"
	default:
		return "IP 地址"
	}
}
