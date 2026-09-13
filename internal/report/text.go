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
// JSON/HTML reports: api路径.txt, 参数.txt and 敏感信息.txt.
func WriteTextReports(directory string, result *model.Result) error {
	files := []struct {
		name string
		data func() []byte
	}{
		{"api路径.txt", func() []byte { return renderAPIPaths(result) }},
		{"参数.txt", func() []byte { return renderParameters(result) }},
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

// renderAPIPaths lists every discovered/probed API endpoint URL, one per line.
func renderAPIPaths(result *model.Result) []byte {
	out := textHeader("API 路径", result.Target)
	seen := make(map[string]struct{}, len(result.Endpoints))
	urls := make([]string, 0, len(result.Endpoints))
	for _, endpoint := range result.Endpoints {
		if endpoint.URL == "" {
			continue
		}
		if _, ok := seen[endpoint.URL]; ok {
			continue
		}
		seen[endpoint.URL] = struct{}{}
		urls = append(urls, endpoint.URL)
	}
	sort.Strings(urls)
	for _, u := range urls {
		line := u
		if endpoint := lookupEndpoint(result, u); endpoint != nil &&
			endpoint.Method != "" && !strings.EqualFold(endpoint.Method, "GET") {
			line = strings.ToUpper(endpoint.Method) + " " + u
		}
		out = append(out, []byte(line+"\n")...)
	}
	return out
}

func lookupEndpoint(result *model.Result, rawURL string) *model.Endpoint {
	for i := range result.Endpoints {
		if result.Endpoints[i].URL == rawURL {
			return &result.Endpoints[i]
		}
	}
	return nil
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

// renderParameters lists every unique query parameter name=value pair with the
// first URL it was observed on.
func renderParameters(result *model.Result) []byte {
	out := textHeader("请求参数", result.Target)
	type entry struct {
		value  string
		source string
	}
	params := map[string]entry{}
	collect := func(raw string) {
		if raw == "" {
			return
		}
		parsed, err := url.Parse(raw)
		if err != nil {
			return
		}
		for key, values := range parsed.Query() {
			if _, ok := params[key]; ok {
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
	names := make([]string, 0, len(params))
	for name := range params {
		names = append(names, name)
	}
	sort.Strings(names)
	if len(names) == 0 {
		return append(out, []byte("（未发现参数）\n")...)
	}
	for _, name := range names {
		entry := params[name]
		line := name + "=" + entry.value + "\t" + entry.source + "\n"
		out = append(out, []byte(line)...)
	}
	return out
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
