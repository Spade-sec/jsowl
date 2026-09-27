package analyze

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/youmulijiang/jsowl/internal/aiclient"
	"github.com/youmulijiang/jsowl/internal/model"
)

// aiBudget caps concurrent AI spend; the per-scan request allowance is shared
// by all three enrichers so one noisy pass cannot starve the others.
type aiBudget struct {
	mu        sync.Mutex
	remaining int
}

func (b *aiBudget) take() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.remaining <= 0 {
		return false
	}
	b.remaining--
	return true
}

// AIThird is the shared state of the three AI enrichers: one client, one
// request budget.
type AIThird struct {
	client *aiclient.Client
	budget aiBudget
}

// AITemplateEnricher implements TemplateEnricher.
type AITemplateEnricher struct{ third *AIThird }

// AITaintEnricher implements TaintEnricher.
type AITaintEnricher struct{ third *AIThird }

// AIFindingEnricher implements FindingEnricher.
type AIFindingEnricher struct{ third *AIThird }

// NewAIThird builds the three AI enrichers over one client and one shared
// request budget.
func NewAIThird(client *aiclient.Client, maxRequests int) (*AITemplateEnricher, *AITaintEnricher, *AIFindingEnricher) {
	if maxRequests <= 0 {
		maxRequests = 20
	}
	third := &AIThird{client: client}
	third.budget.remaining = maxRequests
	return (&AITemplateEnricher{third}), (&AITaintEnricher{third}), (&AIFindingEnricher{third})
}

const aiSystemPrompt = `你是 Web 渗透测试辅助分析器。输入是从已打包前端 JS 中静态提取的结构化证据（调用点上下文、参数表、兄弟接口等），不是完整源码。
只基于给出的证据做判断；证据不足时如实输出 uncertain 或 unknown，不要编造。
严格输出 JSON，不要输出任何其它文字或 markdown 代码块。`

// ── Template enrichment ──────────────────────────────────────────────

type templateBatchItem struct {
	index int
	ep    *model.Endpoint
}

type aiTemplateReview struct {
	Index           int      `json:"index"`
	Completeness    string   `json:"completeness"`
	Assessment      string   `json:"assessment"`
	SuggestedParams []string `json:"suggested_params"`
}

// Enrich reviews reconstructed packets in batches of ten: parameter
// completeness, value authenticity, and fuzz suggestions land in
// Template.AI. Literal/recovered values are never rewritten — the review is
// advisory metadata plus suggested (not injected) parameters.
func (a *AITemplateEnricher) Enrich(templates []*model.RequestTemplate, endpoints []*model.Endpoint) []*model.RequestTemplate {
	pack := make([]templateBatchItem, 0, len(templates))
	for i, tpl := range templates {
		if tpl != nil && i < len(endpoints) {
			pack = append(pack, templateBatchItem{index: i, ep: endpoints[i]})
		}
	}
	if len(pack) == 0 {
		return templates
	}
	siblings := siblingIndex(endpoints)
	results := make([]*model.AIReview, len(templates))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for start := 0; start < len(pack); start += 10 {
		end := start + 10
		if end > len(pack) {
			end = len(pack)
		}
		if !a.third.budget.take() {
			break
		}
		batch := pack[start:end]
		wg.Add(1)
		go func(batch []templateBatchItem) {
			defer wg.Done()
			reviews := a.reviewBatch(batch, siblings)
			mu.Lock()
			defer mu.Unlock()
			for _, r := range reviews {
				if r.index >= 0 && r.index < len(results) {
					results[r.index] = r.review
				}
			}
		}(batch)
	}
	wg.Wait()
	for i, review := range results {
		if review != nil && templates[i] != nil {
			templates[i].AI = review
		}
	}
	return templates
}

type templateReview struct {
	index  int
	review *model.AIReview
}

func (a *AITemplateEnricher) reviewBatch(batch []templateBatchItem, siblings map[string][]string) []templateReview {
	var user strings.Builder
	for _, item := range batch {
		ep := item.ep
		if ep.Template == nil {
			continue
		}
		fmt.Fprintf(&user, "### 接口 %d\n方法: %s\nURL: %s\n", item.index, ep.Template.Method, ep.Template.URL)
		if spec := ep.Spec; spec != nil {
			if spec.ContentType != "" {
				fmt.Fprintf(&user, "Content-Type: %s\n", spec.ContentType)
			}
			writeParams := func(label string, params []model.Param) {
				if len(params) == 0 {
					return
				}
				fmt.Fprintf(&user, "%s参数:\n", label)
				for _, p := range params {
					line := fmt.Sprintf("  %s = %s (证据:%s)", p.Key, p.Value, p.Evidence)
					if p.Taint != nil && p.Taint.Kind == model.TaintUpstream {
						line += fmt.Sprintf(" [来自上游 %s]", p.Taint.Upstream)
					}
					user.WriteString(line + "\n")
				}
			}
			writeParams("Query", spec.Query)
			writeParams("Body", spec.Body)
		}
		if len(ep.Template.Notes) > 0 {
			fmt.Fprintf(&user, "已知注意事项: %s\n", strings.Join(ep.Template.Notes, "；"))
		}
		if keys := siblings[firstSegment(ep.Raw)]; len(keys) > 0 {
			fmt.Fprintf(&user, "同模块兄弟接口参数键(风格参考): %s\n", strings.Join(keys, ", "))
		}
		for k, line := range ep.ContextLines {
			if k >= 3 {
				break
			}
			fmt.Fprintf(&user, "上下文: %s\n", truncate(line.Content, 200))
		}
		user.WriteString("\n")
	}
	content, err := a.third.client.Chat(context.Background(), aiSystemPrompt,
		"对下面每个接口判断参数完整性(complete/missing-fields/uncertain)与真实性，推断占位符载荷的可能字段，给出 fuzz 建议。\n"+
			`输出 JSON 数组，每项: {"index":<接口序号>,"completeness":"...","assessment":"<一句话>","suggested_params":["字段名",...]}`+"\n\n"+user.String())
	if err != nil {
		return nil
	}
	var reviews []aiTemplateReview
	if err := json.Unmarshal([]byte(extractJSON(content)), &reviews); err != nil {
		return nil
	}
	out := make([]templateReview, 0, len(reviews))
	for _, r := range reviews {
		if r.Completeness == "" && r.Assessment == "" && len(r.SuggestedParams) == 0 {
			continue
		}
		out = append(out, templateReview{r.Index, &model.AIReview{
			Completeness: r.Completeness, Assessment: r.Assessment, SuggestedParams: r.SuggestedParams,
		}})
	}
	return out
}

// siblingIndex maps each first path segment to the deduped body/query keys of
// the endpoints under it — the naming-style reference that lets the model
// interpolate placeholder keys instead of guessing them cold.
func siblingIndex(endpoints []*model.Endpoint) map[string][]string {
	seen := map[string]map[string]bool{}
	for _, ep := range endpoints {
		if ep == nil || ep.Spec == nil {
			continue
		}
		segment := firstSegment(ep.Raw)
		for _, param := range append(append([]model.Param{}, ep.Spec.Query...), ep.Spec.Body...) {
			if param.Key == "" {
				continue
			}
			if seen[segment] == nil {
				seen[segment] = map[string]bool{}
			}
			seen[segment][param.Key] = true
		}
	}
	index := make(map[string][]string, len(seen))
	for segment, keys := range seen {
		list := make([]string, 0, len(keys))
		for key := range keys {
			list = append(list, key)
		}
		sort.Strings(list)
		if len(list) > 15 {
			list = list[:15]
		}
		index[segment] = list
	}
	return index
}

// firstSegment returns the first path segment of an endpoint path.
func firstSegment(raw string) string {
	raw = strings.TrimLeft(raw, "/")
	if idx := strings.Index(raw, "/"); idx >= 0 {
		return raw[:idx]
	}
	return raw
}

func truncate(value string, max int) string {
	value = strings.TrimSpace(value)
	if len(value) > max {
		return value[:max]
	}
	return value
}

// ── Taint enrichment ─────────────────────────────────────────────────

type aiTaintJob struct {
	epIndex  int
	pi       int
	symbol   string
	endpoint *model.Endpoint
}

// EnrichTaint refines Kind=unknown placeholders by reading their call
// contexts. An upstream guess is only accepted when the claimed endpoint
// exists in the discovered set; otherwise the honest kernel verdict stands.
func (a *AITaintEnricher) EnrichTaint(result *model.Result) *model.Result {
	var jobs []aiTaintJob
	for ei := range result.Endpoints {
		spec := result.Endpoints[ei].Spec
		if spec == nil {
			continue
		}
		for pi := range spec.Body {
			param := &spec.Body[pi]
			if param.Taint != nil && param.Taint.Kind == model.TaintUnknown {
				jobs = append(jobs, aiTaintJob{epIndex: ei, pi: pi, symbol: param.Taint.Symbol, endpoint: &result.Endpoints[ei]})
			}
		}
	}
	if len(jobs) == 0 || !a.third.budget.take() {
		return result
	}
	var user strings.Builder
	shown := len(jobs)
	if shown > 30 {
		shown = 30
	}
	for i := 0; i < shown; i++ {
		job := jobs[i]
		fmt.Fprintf(&user, "### 占位符 %d\n参数符号: %s\n所属接口: %s %s\n", i, job.symbol, job.endpoint.Method, job.endpoint.Raw)
		for k, line := range job.endpoint.ContextLines {
			if k >= 3 {
				break
			}
			fmt.Fprintf(&user, "上下文: %s\n", truncate(line.Content, 200))
		}
		user.WriteString("\n")
	}
	content, err := a.third.client.Chat(context.Background(), aiSystemPrompt,
		"以下占位符参数的运行时对象来源未知。根据上下文判断来源类别。\n"+
			`输出 JSON 数组: {"index":<序号>,"kind":"upstream|storage|route|unknown","upstream":"<猜测的上游接口路径,可为空>","field":"<响应字段,可为空>"}`+"\n\n"+user.String())
	if err != nil {
		return result
	}
	var refined []struct {
		Index    int    `json:"index"`
		Kind     string `json:"kind"`
		Upstream string `json:"upstream"`
		Field    string `json:"field"`
	}
	if err := json.Unmarshal([]byte(extractJSON(content)), &refined); err != nil {
		return result
	}
	for _, r := range refined {
		if r.Index < 0 || r.Index >= shown {
			continue
		}
		if r.Kind != model.TaintUpstream && r.Kind != model.TaintStorage &&
			r.Kind != model.TaintRoute {
			continue // unknown stays unknown
		}
		job := jobs[r.Index]
		taint := result.Endpoints[job.epIndex].Spec.Body[job.pi].Taint
		if taint == nil || taint.Kind != model.TaintUnknown {
			continue
		}
		if r.Kind == model.TaintUpstream && !knownEndpoint(result, r.Upstream) {
			continue // hallucinated upstream — keep unknown
		}
		taint.Kind = r.Kind
		taint.Symbol = job.symbol
		taint.Upstream = r.Upstream
		taint.UpstreamField = r.Field
	}
	return result
}

// knownEndpoint reports whether url suffix-matches any discovered endpoint.
func knownEndpoint(result *model.Result, url string) bool {
	if url == "" {
		return false
	}
	for i := range result.Endpoints {
		if strings.HasSuffix(result.Endpoints[i].Raw, strings.TrimLeft(url, "/")) ||
			strings.HasSuffix(result.Endpoints[i].URL, strings.TrimLeft(url, "/")) {
			return true
		}
	}
	return false
}

// ── Finding enrichment ───────────────────────────────────────────────

// EnrichFindings rates the top sensitive findings by exploitability: real
// credentials rate high, placeholder-looking values rate invalid. Findings
// are never dropped and values never modified.
func (a *AIFindingEnricher) EnrichFindings(result *model.Result) *model.Result {
	var candidates []*model.Finding
	for i := range result.Findings {
		if result.Findings[i].Category == model.RuleCategorySensitive {
			candidates = append(candidates, &result.Findings[i])
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		return candidates[i].Severity > candidates[j].Severity
	})
	if len(candidates) > 30 {
		candidates = candidates[:30]
	}
	if len(candidates) == 0 || !a.third.budget.take() {
		return result
	}
	var user strings.Builder
	for i, f := range candidates {
		fmt.Fprintf(&user, "### 发现 %d\n规则: %s\n严重性: %s\n值: %s\n", i, f.RuleName, f.Severity, truncate(f.Value, 120))
		for k, line := range f.ContextLines {
			if k >= 2 {
				break
			}
			fmt.Fprintf(&user, "上下文: %s\n", truncate(line.Content, 200))
		}
		user.WriteString("\n")
	}
	content, err := a.third.client.Chat(context.Background(), aiSystemPrompt,
		"评估以下敏感信息发现在渗透测试中的真实价值（占位符/示例/文档值无效；真实密钥、内网地址、证书价值高）。\n"+
			`输出 JSON 数组: {"index":<序号>,"rating":"high|medium|low|invalid","reason":"<一句话>","suggestion":"<下一步测试建议,可空>"}`+"\n\n"+user.String())
	if err != nil {
		return result
	}
	var ratings []struct {
		Index      int    `json:"index"`
		Rating     string `json:"rating"`
		Reason     string `json:"reason"`
		Suggestion string `json:"suggestion"`
	}
	if err := json.Unmarshal([]byte(extractJSON(content)), &ratings); err != nil {
		return result
	}
	valid := map[string]bool{"high": true, "medium": true, "low": true, "invalid": true}
	for _, r := range ratings {
		if r.Index < 0 || r.Index >= len(candidates) || !valid[r.Rating] {
			continue
		}
		candidates[r.Index].AI = &model.AIAssessment{
			Rating: r.Rating, Reason: r.Reason, Suggestion: r.Suggestion,
		}
	}
	return result
}

// extractJSON pulls the outermost JSON array/object out of a model reply,
// tolerating markdown fences and stray prose around it.
func extractJSON(content string) string {
	content = strings.TrimSpace(content)
	content = strings.TrimPrefix(content, "```json")
	content = strings.TrimPrefix(content, "```")
	content = strings.TrimSuffix(content, "```")
	content = strings.TrimSpace(content)
	start := strings.IndexAny(content, "[{")
	if start < 0 {
		return content
	}
	opener := content[start]
	closer := "]"
	if opener == '{' {
		closer = "}"
	}
	if end := strings.LastIndex(content[start:], closer); end >= 0 {
		return content[start : start+end+1]
	}
	return content[start:]
}
