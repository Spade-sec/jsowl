package analyze

import (
	"bytes"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/youmulijiang/jsowl/internal/model"
)

const contextRadius = 160

type ResourceRef struct {
	URL  string
	Type model.ResourceType
}

type Candidate struct {
	Raw    string
	RuleID string
	Offset int
}

type compiledRule struct {
	rule model.Rule
	re   *regexp.Regexp
}

type Engine struct {
	rules []compiledRule
}

func New(custom []model.Rule, disabled []string) (*Engine, error) {
	disabledSet := make(map[string]struct{}, len(disabled))
	for _, id := range disabled {
		disabledSet[id] = struct{}{}
	}

	byID := make(map[string]model.Rule)
	for _, rule := range BuiltinRules() {
		if _, disabled := disabledSet[rule.ID]; !disabled {
			byID[rule.ID] = rule
		}
	}
	for _, rule := range custom {
		if _, disabled := disabledSet[rule.ID]; disabled || !rule.Enabled {
			delete(byID, rule.ID)
			continue
		}
		byID[rule.ID] = rule
	}

	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	engine := &Engine{rules: make([]compiledRule, 0, len(ids))}
	for _, id := range ids {
		rule := byID[id]
		if rule.ID == "" {
			return nil, fmt.Errorf("rule ID is empty")
		}
		compiled, err := regexp.Compile(rule.Pattern)
		if err != nil {
			return nil, fmt.Errorf("compile rule %s: %w", rule.ID, err)
		}
		if rule.Group < 0 || rule.Group > compiled.NumSubexp() {
			return nil, fmt.Errorf(
				"compile rule %s: capture group %d exceeds %d",
				rule.ID,
				rule.Group,
				compiled.NumSubexp(),
			)
		}
		engine.rules = append(engine.rules, compiledRule{rule: rule, re: compiled})
	}
	return engine, nil
}

func (e *Engine) Analyze(source ResourceRef, body []byte) ([]model.Finding, []Candidate) {
	type locatedFinding struct {
		finding model.Finding
		offset  int
	}

	located := make([]locatedFinding, 0)
	candidates := make([]Candidate, 0)
	seenFindings := make(map[string]struct{})
	seenCandidates := make(map[string]struct{})

	for _, rule := range e.rules {
		for _, indices := range rule.re.FindAllSubmatchIndex(body, -1) {
			groupOffset := rule.rule.Group * 2
			start, end := indices[groupOffset], indices[groupOffset+1]
			if start < 0 || end < start {
				continue
			}
			value := string(body[start:end])
			key := rule.rule.ID + "\x00" + source.URL + "\x00" + value
			if _, duplicate := seenFindings[key]; duplicate {
				continue
			}
			seenFindings[key] = struct{}{}

			line, column := location(body, start)
			finding := model.Finding{
				RuleID:    rule.rule.ID,
				RuleName:  rule.rule.Name,
				Category:  rule.rule.Category,
				Severity:  rule.rule.Severity,
				Value:     value,
				SourceURL: source.URL,
				Line:      line,
				Column:    column,
				Context:   matchContext(body, start, end),
			}
			located = append(located, locatedFinding{finding: finding, offset: start})

			if rule.rule.Category == model.RuleCategoryURL {
				candidateKey := source.URL + "\x00" + value
				if _, duplicate := seenCandidates[candidateKey]; !duplicate {
					seenCandidates[candidateKey] = struct{}{}
					candidates = append(candidates, Candidate{
						Raw: value, RuleID: rule.rule.ID, Offset: start,
					})
				}
			}
		}
	}

	sort.SliceStable(located, func(i, j int) bool {
		if located[i].offset != located[j].offset {
			return located[i].offset < located[j].offset
		}
		return located[i].finding.RuleID < located[j].finding.RuleID
	})
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].Offset != candidates[j].Offset {
			return candidates[i].Offset < candidates[j].Offset
		}
		return candidates[i].RuleID < candidates[j].RuleID
	})

	findings := make([]model.Finding, len(located))
	for i := range located {
		findings[i] = located[i].finding
	}
	return findings, candidates
}

func location(body []byte, offset int) (int, int) {
	line := bytes.Count(body[:offset], []byte{'\n'}) + 1
	lastNewline := bytes.LastIndexByte(body[:offset], '\n')
	lineStart := lastNewline + 1
	column := utf8.RuneCount(body[lineStart:offset]) + 1
	return line, column
}

func matchContext(body []byte, start, end int) string {
	contextStart := max(0, start-contextRadius)
	for contextStart < start && !utf8.RuneStart(body[contextStart]) {
		contextStart++
	}
	contextEnd := min(len(body), end+contextRadius)
	for contextEnd < len(body) && !utf8.RuneStart(body[contextEnd]) {
		contextEnd++
	}
	return strings.TrimSpace(string(body[contextStart:contextEnd]))
}
