package analyze

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/youmulijiang/jsowl/internal/model"
)

const contextLines = 2

// Minified bundles keep megabytes on a single physical line; report contexts
// are trimmed around the match so reports stay openable.
const maxContextLineRunes = 400
const maxValueRunes = 2000

// ResourceRef identifies the source being analyzed without retaining its body.
type ResourceRef struct {
	URL  string
	Type model.ResourceType
}

// Candidate records a URL-like rule capture and its byte offset.
type Candidate struct {
	Raw    string
	RuleID string
	Offset int
	// Method is the HTTP verb captured by rules with a method group.
	Method string
}

type compiledRule struct {
	rule model.Rule
	m    matcher
	// sm applies the rule's optional second-stage regex to each extracted
	// value: no match discards the finding, a capture in SGroup replaces it.
	sm matcher
}

// extractMethod returns the normalised HTTP verb captured by the rule's
// method group, or "" when the rule has none or the verb is unrecognised.
func (c compiledRule) extractMethod(body []byte, indices []int) string {
	if c.rule.MethodGroup <= 0 {
		return ""
	}
	groupOffset := c.rule.MethodGroup * 2
	start, end := indices[groupOffset], indices[groupOffset+1]
	if start < 0 || end <= start || end > len(body) {
		return ""
	}
	return normalizeMethod(string(body[start:end]))
}

// normalizeMethod maps verb-bearing capture text (axios.get, fetch,
// jQuery.ajax) to a canonical HTTP method; unknown verbs return "".
func normalizeMethod(raw string) string {
	verb := strings.ToLower(strings.TrimSpace(raw))
	if index := strings.LastIndex(verb, "."); index >= 0 {
		verb = verb[index+1:]
	}
	switch verb {
	case "$fetch", "ofetch", "ky":
		// fetch-style callables default to GET.
		return "GET"
	case "get":
		return "GET"
	case "post":
		return "POST"
	case "put":
		return "PUT"
	case "patch":
		return "PATCH"
	case "delete":
		return "DELETE"
	case "head":
		return "HEAD"
	case "options":
		return "OPTIONS"
	}
	return ""
}

// Engine owns an immutable, compiled set of extraction rules.
type Engine struct {
	rules []compiledRule
}

// New compiles built-in and custom rules after applying disabled rule IDs.
// The built-in API (URL) rules are always compiled: they are hard-wired in
// code and can be neither disabled nor replaced through rule files.
func New(custom []model.Rule, disabled []string) (*Engine, error) {
	disabledSet := make(map[string]struct{}, len(disabled))
	for _, id := range disabled {
		disabledSet[id] = struct{}{}
	}

	apiIDs := make(map[string]struct{})
	for _, rule := range APIRules() {
		apiIDs[rule.ID] = struct{}{}
	}

	byID := make(map[string]model.Rule)
	for _, rule := range DefaultRules() {
		if _, disabled := disabledSet[rule.ID]; !disabled {
			byID[rule.ID] = rule
		}
	}
	for _, rule := range custom {
		if _, reserved := apiIDs[rule.ID]; reserved {
			continue // API rules are code-owned and cannot be overridden
		}
		if _, disabled := disabledSet[rule.ID]; disabled || !rule.Enabled {
			delete(byID, rule.ID)
			continue
		}
		byID[rule.ID] = rule
	}

	ids := make([]string, 0, len(byID)+len(apiIDs))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	engine := &Engine{rules: make([]compiledRule, 0, len(ids)+len(apiIDs))}
	compile := func(rule model.Rule) error {
		if rule.ID == "" {
			return fmt.Errorf("rule ID is empty")
		}
		compiled, err := compileMatcher(rule, rule.Pattern)
		if err != nil {
			return fmt.Errorf("compile rule %s: %w", rule.ID, err)
		}
		groupCount := compiled.groupCount()
		if rule.Group < 0 || rule.Group > groupCount {
			return fmt.Errorf(
				"compile rule %s: capture group %d exceeds %d",
				rule.ID,
				rule.Group,
				groupCount,
			)
		}
		if rule.MethodGroup < 0 || rule.MethodGroup > groupCount {
			return fmt.Errorf(
				"compile rule %s: method group %d exceeds %d",
				rule.ID,
				rule.MethodGroup,
				groupCount,
			)
		}
		if rule.SGroup < 0 {
			return fmt.Errorf("compile rule %s: capture groups must not be negative", rule.ID)
		}
		var second matcher
		if rule.SRegex != "" {
			second, err = compileMatcher(rule, rule.SRegex)
			if err != nil {
				return fmt.Errorf("compile rule %s s_regex: %w", rule.ID, err)
			}
		}
		engine.rules = append(engine.rules, compiledRule{rule: rule, m: compiled, sm: second})
		return nil
	}
	for _, rule := range APIRules() {
		if err := compile(rule); err != nil {
			return nil, err
		}
	}
	for _, id := range ids {
		if err := compile(byID[id]); err != nil {
			return nil, err
		}
	}
	return engine, nil
}

// Analyze extracts stable, deduplicated findings and URL candidates from one body.
func (e *Engine) Analyze(source ResourceRef, body []byte) ([]model.Finding, []Candidate) {
	type locatedFinding struct {
		finding model.Finding
		offset  int
	}

	located := make([]locatedFinding, 0)
	candidates := make([]Candidate, 0)
	seenFindings := make(map[string]struct{})
	seenCandidates := make(map[string]struct{})

	// Convert once per body: regexp2 counts capture offsets in runes, and
	// every rule reuses the same rune→byte translation table.
	text := string(body)
	offsets := runeOffsets(text)

	for _, rule := range e.rules {
		matches, matchErr := rule.m.findAll(text, offsets)
		// A regexp2 timeout aborts the rest of this rule's pass; matches
		// recovered before the deadline are still reported.
		_ = matchErr
		for _, indices := range matches {
			groupOffset := rule.rule.Group * 2
			if groupOffset+1 >= len(indices) {
				continue // pattern has fewer groups than the rule declares
			}
			start, end := indices[groupOffset], indices[groupOffset+1]
			if start < 0 || end < start {
				continue
			}
			value := text[start:end]
			if rule.sm != nil {
				second := rule.sm.findFirst(value)
				if second == nil || second[0] < 0 {
					continue // second-stage filter rejected the value
				}
				switch {
				case rule.rule.Format != "":
					value = expandFormat(rule.rule.Format, value, second)
				case rule.rule.SGroup > 0:
					value = groupText(value, second, rule.rule.SGroup)
				}
			} else if rule.rule.Format != "" {
				value = expandFormat(rule.rule.Format, text, indices)
			}
			key := rule.rule.ID + "\x00" + source.URL + "\x00" + value
			if _, duplicate := seenFindings[key]; duplicate {
				continue
			}
			seenFindings[key] = struct{}{}

			line, column := location(body, start)
			finding := model.Finding{
				RuleID:       rule.rule.ID,
				RuleName:     rule.rule.Name,
				Category:     rule.rule.Category,
				Severity:     rule.rule.Severity,
				Value:        truncateRunes(value, maxValueRunes),
				SourceURL:    source.URL,
				Line:         line,
				Column:       column,
				ContextLines: matchContext(body, start, end),
			}
			located = append(located, locatedFinding{finding: finding, offset: start})

			if rule.rule.Category == model.RuleCategoryURL {
				candidateKey := source.URL + "\x00" + value
				if _, duplicate := seenCandidates[candidateKey]; !duplicate {
					seenCandidates[candidateKey] = struct{}{}
					candidates = append(candidates, Candidate{
						Raw: value, RuleID: rule.rule.ID, Offset: start,
						Method: rule.extractMethod(body, indices),
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

func matchContext(body []byte, start, end int) []model.ContextLine {
	startLine := bytes.Count(body[:start], []byte{'\n'})
	endLine := startLine
	if end > start {
		endLine += bytes.Count(body[start:end], []byte{'\n'})
	}
	lines := strings.Split(string(body), "\n")
	firstLine := max(0, startLine-contextLines)
	lastLine := min(len(lines)-1, endLine+contextLines)

	lineOffsets := make([]int, len(lines))
	for i := 1; i < len(lines); i++ {
		lineOffsets[i] = lineOffsets[i-1] + len(lines[i-1]) + 1
	}

	result := make([]model.ContextLine, 0, lastLine-firstLine+1)
	for index := firstLine; index <= lastLine; index++ {
		content := strings.TrimSuffix(lines[index], "\r")
		lineStart := lineOffsets[index]

		matchStart, matchEnd := -1, -1
		if index >= startLine && index <= endLine {
			if index == startLine {
				matchStart = start - lineStart
			} else {
				matchStart = 0
			}
			if index == endLine {
				matchEnd = end - lineStart
			} else {
				matchEnd = len(content)
			}
			if matchStart < 0 {
				matchStart = 0
			}
			if matchEnd > len(content) {
				matchEnd = len(content)
			}
			if matchEnd < matchStart {
				matchEnd = matchStart
			}
			matchStart = utf8.RuneCountInString(content[:matchStart])
			matchEnd = utf8.RuneCountInString(content[:matchEnd])
		}

		content, matchStart, matchEnd = trimContextLine(content, matchStart, matchEnd)

		result = append(result, model.ContextLine{
			LineNumber: index + 1,
			Content:    content,
			MatchStart: matchStart,
			MatchEnd:   matchEnd,
		})
	}
	return result
}

// trimContextLine shortens one context line to maxContextLineRunes runes,
// keeping the highlighted match fully visible: the side budgets are balanced
// around the match, so a long match can never be clipped by the window.
func trimContextLine(content string, matchStart, matchEnd int) (string, int, int) {
	if utf8.RuneCountInString(content) <= maxContextLineRunes {
		return content, matchStart, matchEnd
	}
	const ellipsis = "…"
	runes := []rune(content)
	if matchEnd > len(runes) {
		matchEnd = len(runes)
	}
	if matchStart > matchEnd {
		matchStart = matchEnd
	}
	matchLen := matchEnd - matchStart
	ellipsisRunes := utf8.RuneCountInString(ellipsis)
	side := (maxContextLineRunes - ellipsisRunes - matchLen) / 2
	if matchStart < 0 || matchEnd <= matchStart {
		trimmed := runes[:maxContextLineRunes]
		return string(trimmed) + ellipsis, matchStart, matchEnd
	}
	if side < 0 {
		// The match alone exceeds the budget: show its head.
		windowStart := max(0, matchStart)
		windowEnd := min(len(runes), windowStart+maxContextLineRunes-ellipsisRunes)
		return windowString(runes, windowStart, windowEnd, matchStart, matchEnd)
	}
	windowStart := max(0, matchStart-side)
	windowEnd := min(len(runes), matchEnd+side)
	// Rebalance whatever side budget went unused at the boundaries.
	if windowStart == 0 {
		windowEnd = min(len(runes), windowStart+maxContextLineRunes-ellipsisRunes)
	} else if windowEnd == len(runes) {
		windowStart = max(0, len(runes)-maxContextLineRunes+ellipsisRunes)
	}
	return windowString(runes, windowStart, windowEnd, matchStart, matchEnd)
}

func windowString(
	runes []rune, windowStart, windowEnd, matchStart, matchEnd int,
) (string, int, int) {
	const ellipsis = "…"
	prefix, suffix := "", ""
	if windowStart > 0 {
		prefix = ellipsis
	}
	if windowEnd < len(runes) {
		suffix = ellipsis
	}
	shift := utf8.RuneCountInString(prefix) - windowStart
	return prefix + string(runes[windowStart:windowEnd]) + suffix,
		matchStart + shift, matchEnd + shift
}

func truncateRunes(value string, limit int) string {
	if utf8.RuneCountInString(value) <= limit {
		return value
	}
	return string([]rune(value)[:limit]) + "…"
}
