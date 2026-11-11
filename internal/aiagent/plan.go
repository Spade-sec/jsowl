package aiagent

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/youmulijiang/jsowl/internal/model"
)

// Plan is one round of the agent protocol. The model must reply with this
// exact JSON object: either it names tool calls to gather more evidence, or
// it commits its final report — never both, and it may not stay silent.
type Plan struct {
	Thought string       `json:"thought"`
	Calls   []PlanCall   `json:"calls"`
	Final   *FinalReport `json:"final"`
}

// PlanCall is one tool invocation the model requests.
type PlanCall struct {
	Tool string          `json:"tool"`
	Args json.RawMessage `json:"args"`
}

// FinalReport is the agent's structured verdict. Items reference scan
// results by their stable identity (endpoint raw path, rule id + value);
// the merge layer re-validates every reference against the result, so a
// hallucinated path or value is dropped rather than merged.
type FinalReport struct {
	Reviews []TemplateReview `json:"reviews"`
	Taints  []TaintFix       `json:"taints"`
	Ratings []FindingRating  `json:"ratings"`
	Summary SummaryOut       `json:"summary"`
}

// TemplateReview is the agent's verdict on one reconstructed request packet.
type TemplateReview struct {
	Endpoint string `json:"endpoint"`
	Method   string `json:"method,omitempty"`
	// Completeness: complete / missing-fields / uncertain.
	Completeness    string           `json:"completeness,omitempty"`
	Assessment      string           `json:"assessment,omitempty"`
	SuggestedParams []string         `json:"suggested_params,omitempty"`
	FuzzPlans       []model.FuzzPlan `json:"fuzz_plans,omitempty"`
}

// TaintFix refines one placeholder parameter's unknown origin.
type TaintFix struct {
	Endpoint string `json:"endpoint"`
	Param    string `json:"param"`
	// Kind: upstream / storage / route (unknown stays unknown).
	Kind     string `json:"kind"`
	Upstream string `json:"upstream,omitempty"`
	Field    string `json:"field,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

// FindingRating rates one sensitive finding's real-world value.
type FindingRating struct {
	RuleID string `json:"rule_id"`
	Value  string `json:"value"`
	// Rating: high / medium / low / invalid.
	Rating     string `json:"rating"`
	Reason     string `json:"reason,omitempty"`
	Suggestion string `json:"suggestion,omitempty"`
}

// SummaryOut is the report-level supplement.
type SummaryOut struct {
	Overview   string        `json:"overview,omitempty"`
	Priorities []PriorityOut `json:"priorities,omitempty"`
	Notes      []string      `json:"notes,omitempty"`
}

// PriorityOut is one entry of the "test these first" queue.
type PriorityOut struct {
	Target string   `json:"target"`
	Kind   string   `json:"kind,omitempty"`
	Reason string   `json:"reason,omitempty"`
	Tests  []string `json:"tests,omitempty"`
}

// ParsePlan decodes one model reply into a Plan, tolerating markdown fences
// and stray prose around the JSON object.
func ParsePlan(content string) (*Plan, error) {
	jsonText := extractJSONObject(content)
	if jsonText == "" {
		return nil, fmt.Errorf("回复中没有找到 JSON 对象")
	}
	var plan Plan
	if err := json.Unmarshal([]byte(jsonText), &plan); err != nil {
		return nil, fmt.Errorf("JSON 解析失败: %w", err)
	}
	if plan.Final == nil && len(plan.Calls) == 0 {
		return nil, fmt.Errorf("既没有 calls 也没有 final，模型未推进分析")
	}
	if plan.Final != nil && len(plan.Calls) > 0 {
		// A final report wins: drop the trailing calls so the loop ends
		// instead of executing commands the model no longer needs.
		plan.Calls = nil
	}
	for i := range plan.Calls {
		plan.Calls[i].Tool = strings.TrimSpace(plan.Calls[i].Tool)
	}
	return &plan, nil
}

// extractJSONObject pulls the outermost JSON object out of a reply,
// tolerating markdown fences and prose. Unlike the fast enrichers' array
// variant this must find a balanced object, because the plan carries nested
// arrays whose brackets would confuse a naive bracket search.
func extractJSONObject(content string) string {
	content = strings.TrimSpace(content)
	content = strings.TrimPrefix(content, "```json")
	content = strings.TrimPrefix(content, "```")
	content = strings.TrimSuffix(content, "```")
	content = strings.TrimSpace(content)
	start := strings.IndexByte(content, '{')
	if start < 0 {
		return ""
	}
	depth := 0
	inString := false
	escaped := false
	for i := start; i < len(content); i++ {
		c := content[i]
		if inString {
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			continue
		}
		switch c {
		case '"':
			inString = true
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return content[start : i+1]
			}
		}
	}
	return content[start:]
}
