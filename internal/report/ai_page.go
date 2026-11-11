package report

import (
	"fmt"
	"strings"

	"github.com/youmulijiang/jsowl/internal/model"
)

// renderAIReport builds the AI 分析报告 page: the agent's report-level
// supplement (overview, priority queue, notes, phase statistics) plus every
// AI verdict attached to endpoints and findings. One page answers "what did
// the AI actually claim", while the deterministic reports keep the scan's
// own results.
func renderAIReport(result *model.Result) (int, string, error) {
	var b strings.Builder
	count := 0

	if ai := result.AI; ai != nil {
		b.WriteString(renderAIPhaseHeader(ai))
		if ai.Overview != "" {
			b.WriteString(`<div class="section-title">总评</div><div class="detail-section">` +
				htmlEscape(ai.Overview) + `</div>`)
		}
		if len(ai.Priorities) > 0 {
			b.WriteString(`<div class="section-title">优先测试队列</div><table class="paginated" data-page-size="50" data-filterable data-empty="没有符合当前筛选条件的优先项"><thead><tr>` +
				`<th style="width:44px">#</th><th style="width:340px">目标</th><th style="width:110px">类型</th>` +
				`<th>理由</th><th style="width:300px">建议测试</th></tr></thead><tbody>`)
			for i, priority := range ai.Priorities {
				kind := `<span class="sev info">未归类</span>`
				if priority.Kind != "" {
					kind = `<span class="sev scen">` + htmlEscape(priority.Kind) + `</span>`
				}
				tests := ""
				for _, test := range priority.Tests {
					tests += `<div>` + htmlEscape(test) + `</div>`
				}
				fmt.Fprintf(&b, "<tr><td>%d</td><td><code>%s</code></td><td>%s</td><td>%s</td><td>%s</td></tr>",
					i+1, htmlEscape(priority.Target), kind,
					htmlEscape(priority.Reason), tests)
			}
			b.WriteString(`</tbody></table>`)
			count += len(ai.Priorities)
		}
		if len(ai.Notes) > 0 {
			b.WriteString(`<div class="section-title">横切观察</div><div class="detail-section">`)
			for _, note := range ai.Notes {
				b.WriteString(`<div>· ` + htmlEscape(note) + `</div>`)
			}
			b.WriteString(`</div>`)
		}
	}

	reviewCount := renderAIReviewTable(&b, result)
	ratingCount := renderAIRatingTable(&b, result)
	count += reviewCount + ratingCount

	if count == 0 && result.AI == nil {
		return 0, `<div class="muted">本次没有 AI 分析内容。开启 <code>-ai</code>（可选 <code>--ai-mode agent</code>）后，AI 的摘要、接口复核与发现评级会汇总在本页。</div>`, nil
	}
	// The search bar only makes sense once at least one table exists.
	if len(b.String()) == 0 || count == 0 {
		return count, b.String(), nil
	}
	var page strings.Builder
	page.WriteString(`<div class="filterbar" data-for="*">` +
		`<label>搜索 <input type="search" placeholder="目标、理由、规则或 AI 评估..."></label>` +
		`<button type="button" data-reset>重置筛选</button>` +
		`<span class="muted" data-count aria-live="polite"></span></div>`)
	page.WriteString(b.String())
	return count, page.String(), nil
}

// renderAIPhaseHeader shows how the agent phase ran: one status chip plus
// the counters a reader needs to judge how much to trust the supplement.
func renderAIPhaseHeader(ai *model.AISummary) string {
	stats := ai.Stats
	if stats == nil {
		return ""
	}
	class, label := "info", stats.Status
	switch stats.Status {
	case "ok":
		class, label = "runtime", "完成"
	case "partial":
		class, label = "full-url", "部分完成"
	case "failed":
		class, label = "high", "失败"
	}
	line := fmt.Sprintf(`<div class="detail-section"><span class="sev %s">%s</span> `+
		`<span class="muted">%d 轮 / %d 次 AI 请求`, class, htmlEscape(label), stats.Steps, stats.Requests)
	if merged := stats.Reviews + stats.Taints + stats.Ratings; merged > 0 {
		line += fmt.Sprintf(`，合并 复核 %d / 污点 %d / 评级 %d`, stats.Reviews, stats.Taints, stats.Ratings)
	}
	line += `</span>`
	if stats.Reason != "" {
		line += `<div class="muted">` + htmlEscape(stats.Reason) + `</div>`
	}
	return line + `</div>`
}

// renderAIReviewTable lists every endpoint whose reconstructed packet
// carries an AI review, mirroring the per-endpoint detail blocks.
func renderAIReviewTable(b *strings.Builder, result *model.Result) int {
	rows := 0
	for i := range result.Endpoints {
		endpoint := &result.Endpoints[i]
		if endpoint.Template == nil || endpoint.Template.AI == nil {
			continue
		}
		ai := endpoint.Template.AI
		if rows == 0 {
			b.WriteString(`<div class="section-title">接口请求包复核</div><table class="paginated" data-page-size="50" data-filterable data-empty="没有符合当前筛选条件的复核记录"><thead><tr>` +
				`<th style="width:90px">方法</th><th style="width:320px">接口</th><th style="width:130px">完整性</th>` +
				`<th>AI 评估</th></tr></thead><tbody>`)
		}
		rows++
		method := endpoint.Method
		if method == "" {
			method = "GET"
		}
		class := "info"
		switch ai.Completeness {
		case "complete":
			class = "runtime"
		case "missing-fields":
			class = "high"
		}
		var detail strings.Builder
		if ai.Assessment != "" {
			detail.WriteString(htmlEscape(ai.Assessment))
		}
		if len(ai.SuggestedParams) > 0 {
			detail.WriteString(`<div class="muted">建议关注参数: ` +
				htmlEscape(strings.Join(ai.SuggestedParams, ", ")) + `</div>`)
		}
		for _, plan := range ai.FuzzPlans {
			line := `<div class="muted">fuzz 计划: <code>` + htmlEscape(plan.Field) + `</code>`
			if plan.Strategy != "" {
				line += ` <span class="sev ai">` + htmlEscape(plan.Strategy) + `</span>`
			}
			if len(plan.Values) > 0 {
				line += ` 候选值: ` + htmlEscape(strings.Join(plan.Values, ", "))
			}
			if plan.Note != "" {
				line += ` — ` + htmlEscape(plan.Note)
			}
			detail.WriteString(line + `</div>`)
		}
		fmt.Fprintf(b,
			"<tr><td><span class=\"pkt-method\">%s</span></td><td><code>%s</code></td><td><span class=\"sev %s\">%s</span></td><td>%s</td></tr>",
			htmlEscape(method), htmlEscape(endpoint.Raw), class,
			htmlEscape(ai.Completeness), detail.String())
	}
	if rows > 0 {
		b.WriteString(`</tbody></table>`)
	}
	return rows
}

// renderAIRatingTable lists every finding the AI rated, with the rating
// chip colored the same way the sensitive report colors it.
func renderAIRatingTable(b *strings.Builder, result *model.Result) int {
	rows := 0
	for i := range result.Findings {
		finding := &result.Findings[i]
		ai := finding.AI
		if ai == nil {
			continue
		}
		if rows == 0 {
			b.WriteString(`<div class="section-title">敏感发现评级</div><table class="paginated" data-page-size="50" data-filterable data-empty="没有符合当前筛选条件的评级记录"><thead><tr>` +
				`<th style="width:90px">严重性</th><th style="width:200px">规则</th><th>完整值</th>` +
				`<th style="width:300px">AI 评级</th></tr></thead><tbody>`)
		}
		rows++
		class := "info"
		switch ai.Rating {
		case "high":
			class = "high"
		case "medium":
			class = "full-url"
		case "low":
			class = "low"
		}
		var detail strings.Builder
		detail.WriteString(`<span class="sev ` + class + `">` + htmlEscape(ai.Rating) + `</span> <span class="sev vendor">AI</span>`)
		if ai.Reason != "" {
			detail.WriteString(`<div class="muted">` + htmlEscape(ai.Reason) + `</div>`)
		}
		if ai.Suggestion != "" {
			detail.WriteString(`<div class="muted">建议: ` + htmlEscape(ai.Suggestion) + `</div>`)
		}
		fmt.Fprintf(b,
			"<tr><td><span class=\"sev %s\">%s</span></td><td>%s<div class=\"muted\">%s</div></td><td><code>%s</code></td><td>%s</td></tr>",
			htmlEscape(string(finding.Severity)), htmlEscape(string(finding.Severity)),
			htmlEscape(finding.RuleName), htmlEscape(finding.RuleID),
			htmlEscape(finding.Value), detail.String())
	}
	if rows > 0 {
		b.WriteString(`</tbody></table>`)
	}
	return rows
}
