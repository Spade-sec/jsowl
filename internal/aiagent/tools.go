package aiagent

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/youmulijiang/jsowl/internal/model"
)

// maxToolResultBytes caps one tool reply so a single call cannot flood the
// transcript; the model can page instead (smaller windows, prefix filters).
const maxToolResultBytes = 4000

// Tool is one read-only query over the evidence base. Fn returns the text
// the model sees; errors are reported to the model as text, never fatal.
type Tool struct {
	Name        string
	Description string
	ArgsHint    string
	Fn          func(args json.RawMessage) string
}

// Toolset owns the tool registry and the evidence the tools read.
type Toolset struct {
	evidence *Evidence
	tools    map[string]Tool
}

// NewToolset wires the five read-only tools over one evidence base.
func NewToolset(evidence *Evidence) *Toolset {
	set := &Toolset{evidence: evidence, tools: map[string]Tool{}}
	register := func(tool Tool) { set.tools[tool.Name] = tool }
	register(Tool{
		Name:        "list_endpoints",
		Description: "列出扫描发现的接口（api 与框架路由），带序号、方法、路径、状态码与证据等级。",
		ArgsHint:    `{"prefix":"/api","type":"api|route","limit":50}`,
		Fn:          set.listEndpoints,
	})
	register(Tool{
		Name:        "get_endpoint",
		Description: "读取一个接口的完整细节：参数表（含证据等级与污点来源）、重建的请求包、响应字段、源码上下文。",
		ArgsHint:    `{"index":3}`,
		Fn:          set.getEndpoint,
	})
	register(Tool{
		Name:        "get_findings",
		Description: "列出敏感信息发现，带序号、规则、严重性、匹配值与源码位置。",
		ArgsHint:    `{"severity":"high","limit":30}`,
		Fn:          set.getFindings,
	})
	register(Tool{
		Name:        "get_context",
		Description: "读取某源码文件指定行号附近的代码（需要该文件已被扫描持久化）。",
		ArgsHint:    `{"source_url":"http://x/app.js","line":120,"before":8,"after":8}`,
		Fn:          set.getContext,
	})
	register(Tool{
		Name:        "search_code",
		Description: "在所有已持久化的源码里按正则搜索，返回 文件:行号:内容。",
		ArgsHint:    `{"pattern":"apiKey|accessKey","limit":20}`,
		Fn:          set.searchCode,
	})
	return set
}

// List returns the registered tools sorted by name for a stable prompt.
func (t *Toolset) List() []Tool {
	names := make([]string, 0, len(t.tools))
	for name := range t.tools {
		names = append(names, name)
	}
	sort.Strings(names)
	list := make([]Tool, 0, len(names))
	for _, name := range names {
		list = append(list, t.tools[name])
	}
	return list
}

// Execute runs one tool call; unknown tools, bad arguments and tool bugs
// come back as an explanatory string so the model can correct itself next
// round instead of taking the scan down.
func (t *Toolset) Execute(name string, args json.RawMessage) (result string) {
	tool, known := t.tools[name]
	if !known {
		return fmt.Sprintf("错误: 未知工具 %q，可用工具: %s", name, strings.Join(t.toolNames(), ", "))
	}
	defer func() {
		if r := recover(); r != nil {
			result = fmt.Sprintf("错误: 工具 %s 内部失败: %v", name, r)
		}
	}()
	return tool.Fn(args)
}

func (t *Toolset) toolNames() []string {
	names := make([]string, 0, len(t.tools))
	for name := range t.tools {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// toolArgs decodes one tool's argument object; args may be null.
func toolArgs(args json.RawMessage, dst any) error {
	if len(args) == 0 || string(args) == "null" {
		return nil
	}
	return json.Unmarshal(args, dst)
}

// truncateTool caps a tool reply with an explicit truncation marker.
func truncateTool(text string) string {
	if len(text) <= maxToolResultBytes {
		return text
	}
	return text[:maxToolResultBytes] + "\n…(已截断，请缩小查询范围)"
}

// ── list_endpoints ─────────────────────────────────────────────────────

type listEndpointsArgs struct {
	Prefix string `json:"prefix"`
	Type   string `json:"type"`
	Limit  int    `json:"limit"`
}

func (t *Toolset) listEndpoints(raw json.RawMessage) string {
	var args listEndpointsArgs
	if err := toolArgs(raw, &args); err != nil {
		return "错误: 参数不是合法 JSON 对象"
	}
	limit := args.Limit
	if limit <= 0 {
		limit = 50
	}
	var out strings.Builder
	count := 0
	for i := range t.evidence.result.Endpoints {
		ep := &t.evidence.result.Endpoints[i]
		if args.Prefix != "" && !strings.HasPrefix(ep.Raw, args.Prefix) {
			continue
		}
		if args.Type != "" && ep.Type != args.Type {
			continue
		}
		if count >= limit {
			out.WriteString("…(还有更多，请用 prefix 过滤)\n")
			break
		}
		method := ep.Method
		if method == "" {
			method = "GET"
		}
		fmt.Fprintf(&out, "[%d] %s %s status=%d evidence=%s type=%s\n",
			i, method, ep.Raw, ep.StatusCode, ep.Evidence, ep.Type)
		count++
	}
	if count == 0 {
		return "（没有匹配的接口）"
	}
	return truncateTool(out.String())
}

// ── get_endpoint ───────────────────────────────────────────────────────

type getEndpointArgs struct {
	Index int `json:"index"`
}

func (t *Toolset) getEndpoint(raw json.RawMessage) string {
	var args getEndpointArgs
	if err := toolArgs(raw, &args); err != nil {
		return "错误: 参数不是合法 JSON 对象"
	}
	endpoints := t.evidence.result.Endpoints
	if args.Index < 0 || args.Index >= len(endpoints) {
		return fmt.Sprintf("错误: 序号 %d 越界（共 %d 个接口）", args.Index, len(endpoints))
	}
	ep := &endpoints[args.Index]
	var out strings.Builder
	method := ep.Method
	if method == "" {
		method = "GET"
	}
	fmt.Fprintf(&out, "接口 %d: %s %s\n", args.Index, method, ep.Raw)
	if ep.URL != "" && ep.URL != ep.Raw {
		fmt.Fprintf(&out, "绝对地址: %s\n", ep.URL)
	}
	fmt.Fprintf(&out, "状态: %d 证据: %s 类型: %s 来源: %s\n", ep.StatusCode, ep.Evidence, ep.Type, ep.Source)
	if ep.Authorized {
		out.WriteString("已探测授权: 是\n")
	}
	if len(ep.ResponseParams) > 0 {
		fmt.Fprintf(&out, "探测响应字段: %s\n", strings.Join(ep.ResponseParams, ", "))
	}
	if spec := ep.Spec; spec != nil {
		if spec.ContentType != "" {
			fmt.Fprintf(&out, "Content-Type: %s (%s)\n", spec.ContentType, spec.ContentTypeEvidence)
		}
		writeParamList(&out, "Query", spec.Query)
		writeParamList(&out, "Body", spec.Body)
	}
	if tpl := ep.Template; tpl != nil {
		fmt.Fprintf(&out, "请求包: %s %s\n", tpl.Method, tpl.URL)
		if tpl.Body != "" {
			fmt.Fprintf(&out, "请求体: %s\n", tpl.Body)
		}
		for _, header := range tpl.Headers {
			fmt.Fprintf(&out, "头: %s: %s (%s)\n", header.Key, header.Value, header.Evidence)
		}
		for _, note := range tpl.Notes {
			fmt.Fprintf(&out, "注意: %s\n", note)
		}
	}
	if len(ep.BodyParams) > 0 {
		fmt.Fprintf(&out, "历史请求体字段: %s\n", strings.Join(ep.BodyParams, ", "))
	}
	writeContext(&out, ep.ContextLines, 5)
	return truncateTool(out.String())
}

// ── get_findings ───────────────────────────────────────────────────────

type getFindingsArgs struct {
	Severity string `json:"severity"`
	Limit    int    `json:"limit"`
}

func (t *Toolset) getFindings(raw json.RawMessage) string {
	var args getFindingsArgs
	if err := toolArgs(raw, &args); err != nil {
		return "错误: 参数不是合法 JSON 对象"
	}
	limit := args.Limit
	if limit <= 0 {
		limit = 30
	}
	var out strings.Builder
	count := 0
	for i := range t.evidence.result.Findings {
		f := &t.evidence.result.Findings[i]
		if args.Severity != "" && string(f.Severity) != args.Severity {
			continue
		}
		if count >= limit {
			out.WriteString("…(还有更多，请提高 limit 或按 severity 过滤)\n")
			break
		}
		fmt.Fprintf(&out, "[%d] %s 规则=%s (%s)\n  值: %s\n  来源: %s:%d:%d\n",
			i, f.Severity, f.RuleName, f.RuleID, f.Value, f.SourceURL, f.Line, f.Column)
		count++
		writeContext(&out, f.ContextLines, 2)
	}
	if count == 0 {
		return "（没有匹配的发现）"
	}
	return truncateTool(out.String())
}

// ── get_context ────────────────────────────────────────────────────────

type getContextArgs struct {
	SourceURL string `json:"source_url"`
	Line      int    `json:"line"`
	Before    int    `json:"before"`
	After     int    `json:"after"`
}

func (t *Toolset) getContext(raw json.RawMessage) string {
	var args getContextArgs
	if err := toolArgs(raw, &args); err != nil {
		return "错误: 参数不是合法 JSON 对象"
	}
	if args.SourceURL == "" {
		return "错误: 缺少 source_url"
	}
	body, ok := t.evidence.source(args.SourceURL)
	if !ok {
		return fmt.Sprintf("错误: %s 没有持久化的源码（未下载、被截断或保存失败），只能依赖报告里的上下文行", args.SourceURL)
	}
	if args.Line < 1 {
		return "错误: line 必须从 1 开始"
	}
	before, after := args.Before, args.After
	if before <= 0 {
		before = 8
	}
	if after <= 0 {
		after = 8
	}
	if before > 40 {
		before = 40
	}
	if after > 40 {
		after = 40
	}
	start := args.Line - before
	if start < 1 {
		start = 1
	}
	end := args.Line + after
	lines := lineWindow(body, start, end)
	if len(lines) == 0 {
		return fmt.Sprintf("错误: 行号 %d 超出文件范围", args.Line)
	}
	var out strings.Builder
	fmt.Fprintf(&out, "%s 第 %d-%d 行:\n", args.SourceURL, start, start+len(lines)-1)
	for i, line := range lines {
		fmt.Fprintf(&out, "%d: %s\n", start+i, line)
	}
	return truncateTool(out.String())
}

// ── search_code ────────────────────────────────────────────────────────

type searchCodeArgs struct {
	Pattern string `json:"pattern"`
	Limit   int    `json:"limit"`
}

func (t *Toolset) searchCode(raw json.RawMessage) string {
	var args searchCodeArgs
	if err := toolArgs(raw, &args); err != nil {
		return "错误: 参数不是合法 JSON 对象"
	}
	if strings.TrimSpace(args.Pattern) == "" {
		return "错误: 缺少 pattern"
	}
	pattern, err := regexp.Compile(args.Pattern)
	if err != nil {
		return fmt.Sprintf("错误: 正则不合法: %v", err)
	}
	limit := args.Limit
	if limit <= 0 {
		limit = 20
	}
	var out strings.Builder
	matches := 0
	for _, url := range t.evidence.sourceURLs() {
		body, ok := t.evidence.source(url)
		if !ok {
			continue
		}
		for lineNo, line := range strings.Split(body, "\n") {
			if matches >= limit {
				return truncateTool(out.String() + "…(达到上限)\n")
			}
			if pattern.MatchString(line) {
				fmt.Fprintf(&out, "%s:%d: %s\n", url, lineNo+1, strings.TrimSpace(line))
				matches++
			}
		}
	}
	if matches == 0 {
		return "（无匹配；注意只有已持久化的脚本可搜索）"
	}
	return truncateTool(out.String())
}

// ── shared renderers ───────────────────────────────────────────────────

func writeParamList(out *strings.Builder, label string, params []model.Param) {
	if len(params) == 0 {
		return
	}
	fmt.Fprintf(out, "%s参数:\n", label)
	for _, param := range params {
		line := fmt.Sprintf("  %s = %s (证据:%s)", param.Key, param.Value, param.Evidence)
		if param.Taint != nil {
			line += fmt.Sprintf(" [污点:%s", param.Taint.Kind)
			if param.Taint.Upstream != "" {
				line += " ← " + param.Taint.Upstream
			}
			line += "]"
		}
		out.WriteString(line + "\n")
	}
}

func writeContext(out *strings.Builder, lines []model.ContextLine, max int) {
	for i, line := range lines {
		if i >= max {
			break
		}
		fmt.Fprintf(out, "  上下文 %d: %s\n", line.LineNumber, truncate(line.Content, 200))
	}
}

func truncate(value string, max int) string {
	value = strings.TrimSpace(value)
	if len(value) > max {
		return value[:max]
	}
	return value
}
