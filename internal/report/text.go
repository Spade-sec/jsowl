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
	out := textHeader("完整 URL", result.Target)
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

func textHeader(title, target string) []byte {
	var b strings.Builder
	b.WriteString("# JsOwl " + title + "\n")
	b.WriteString("# 目标: " + target + "\n")
	b.WriteString("# 敏感数据，请妥善保管\n")
	return []byte(b.String())
}

// renderAPIAbsolute lists every absolute path ("/a/b/c?x=1"), one per line,
// deduplicated and sorted. It uses the same classification as the API report
// so the counts agree; full URLs live in url.txt instead.
func renderAPIAbsolute(result *model.Result) []byte {
	out := textHeader("API 绝对路径", result.Target)
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
	out := textHeader("API 相对路径", result.Target)
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
	out := textHeader("框架路由", result.Target)
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
	out := textHeader("敏感信息", result.Target)
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
	out := textHeader(title, result.Target)
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
