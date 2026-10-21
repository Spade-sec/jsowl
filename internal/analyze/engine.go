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
	return e.extract(source, body, true)
}

// AnalyzeCandidates runs only the URL-category rules and returns their
// candidates, without building findings or their context lines. Candidate
// extraction is restricted to URL rules in Analyze as well, so the result is
// exactly the candidate set Analyze would return — it only skips the
// sensitive-rule passes whose findings the caller would discard.
func (e *Engine) AnalyzeCandidates(source ResourceRef, body []byte) []Candidate {
	_, candidates := e.extract(source, body, false)
	return candidates
}

func (e *Engine) extract(
	source ResourceRef,
	body []byte,
	wantFindings bool,
) ([]model.Finding, []Candidate) {
	type locatedFinding struct {
		finding model.Finding
		offset  int
	}

	located := make([]locatedFinding, 0)
	candidates := make([]Candidate, 0)
	seenFindings := make(map[string]struct{})
	seenCandidates := make(map[string]struct{})

	// Convert once per body: regexp2 counts capture offsets in runes, and
	// every rule reuses the same rune→byte translation table. ASCII bodies
	// skip the table entirely (rune index == byte index).
	text := string(body)
	offsets := runeOffsets(text)
	var lines *findingLines
	if wantFindings {
		lines = newFindingLines(body)
	}

	for _, rule := range e.rules {
		isURL := rule.rule.Category == model.RuleCategoryURL
		if !wantFindings && !isURL {
			continue
		}
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
			if wantFindings {
				key := rule.rule.ID + "\x00" + source.URL + "\x00" + value
				if _, duplicate := seenFindings[key]; duplicate {
					continue
				}
				seenFindings[key] = struct{}{}

				line, column := lines.location(start)
				finding := model.Finding{
					RuleID:       rule.rule.ID,
					RuleName:     rule.rule.Name,
					Category:     rule.rule.Category,
					Severity:     rule.rule.Severity,
					Value:        truncateRunes(value, maxValueRunes),
					SourceURL:    source.URL,
					Line:         line,
					Column:       column,
					ContextLines: lines.matchContext(start, end),
				}
				located = append(located, locatedFinding{finding: finding, offset: start})
			}

			if isURL {
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

// findingLines caches the line layout of one analyzed body. Building it once
// keeps per-finding line/column and context lookups independent of the body
// size; the previous implementation split the whole body for every finding,
// which made a match-heavy minified bundle quadratic.
type findingLines struct {
	body   []byte
	starts []int
	// ascii caches the body's encoding: 0 unknown, 1 ASCII, -1 non-ASCII.
	ascii int8
}

func newFindingLines(body []byte) *findingLines {
	starts := make([]int, 0, bytes.Count(body, []byte{'\n'})+1)
	starts = append(starts, 0)
	for index, char := range body {
		if char == '\n' {
			starts = append(starts, index+1)
		}
	}
	return &findingLines{body: body, starts: starts}
}

func (lines *findingLines) isASCII() bool {
	switch lines.ascii {
	case 1:
		return true
	case -1:
		return false
	}
	lines.ascii = 1
	for _, char := range lines.body {
		if char >= utf8.RuneSelf {
			lines.ascii = -1
			return false
		}
	}
	return true
}

// countUpTo returns how many line starts are <= offset.
func (lines *findingLines) countUpTo(offset int) int {
	return sort.Search(len(lines.starts), func(i int) bool {
		return lines.starts[i] > offset
	})
}

func (lines *findingLines) location(offset int) (int, int) {
	line := max(0, lines.countUpTo(offset)-1)
	lineStart := lines.starts[line]
	return line + 1, utf8.RuneCount(lines.body[lineStart:offset]) + 1
}

// lineContent returns one line without its separating newline and trailing CR,
// matching the strings.Split(body, "\n") semantics the previous implementation
// used (including the empty last line after a trailing newline).
func (lines *findingLines) lineContent(index int) (string, int) {
	start := lines.starts[index]
	end := len(lines.body)
	if index+1 < len(lines.starts) {
		end = lines.starts[index+1] - 1
	}
	content := strings.TrimSuffix(string(lines.body[start:end]), "\r")
	return content, start
}

func (lines *findingLines) matchContext(start, end int) []model.ContextLine {
	startLine := max(0, lines.countUpTo(start)-1)
	endLine := startLine
	if end > start {
		endLine += lines.countUpTo(end) - lines.countUpTo(start)
	}
	firstLine := max(0, startLine-contextLines)
	lastLine := min(len(lines.starts)-1, endLine+contextLines)

	if lines.isASCII() {
		return lines.matchContextASCII(start, end, startLine, endLine, firstLine, lastLine)
	}

	result := make([]model.ContextLine, 0, lastLine-firstLine+1)
	for index := firstLine; index <= lastLine; index++ {
		content, lineStart := lines.lineContent(index)

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

// matchContextASCII is the fast path for ASCII bodies: byte offsets equal rune
// offsets, so a long minified line is sliced into a short window instead of
// being copied and converted to runes for every finding.
func (lines *findingLines) matchContextASCII(
	start, end, startLine, endLine, firstLine, lastLine int,
) []model.ContextLine {
	result := make([]model.ContextLine, 0, lastLine-firstLine+1)
	for index := firstLine; index <= lastLine; index++ {
		lineStart := lines.starts[index]
		lineEnd := len(lines.body)
		if index+1 < len(lines.starts) {
			lineEnd = lines.starts[index+1] - 1
		}
		content := lines.body[lineStart:lineEnd]
		if size := len(content); size > 0 && content[size-1] == '\r' {
			content = content[:size-1]
		}

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
			matchStart = min(max(matchStart, 0), len(content))
			matchEnd = min(max(matchEnd, matchStart), len(content))
		}

		text, matchStart, matchEnd := trimContextBytes(content, matchStart, matchEnd)
		result = append(result, model.ContextLine{
			LineNumber: index + 1,
			Content:    text,
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

// trimContextBytes is trimContextLine for an ASCII line: the budget and the
// match coordinates are measured in bytes, which equal runes there, so no
// whole-line conversion is performed.
func trimContextBytes(content []byte, matchStart, matchEnd int) (string, int, int) {
	if len(content) <= maxContextLineRunes {
		return string(content), matchStart, matchEnd
	}
	if matchEnd > len(content) {
		matchEnd = len(content)
	}
	if matchStart > matchEnd {
		matchStart = matchEnd
	}
	if matchStart < 0 || matchEnd <= matchStart {
		return string(content[:maxContextLineRunes]) + "…", matchStart, matchEnd
	}
	matchLen := matchEnd - matchStart
	side := (maxContextLineRunes - 1 - matchLen) / 2
	if side < 0 {
		windowStart := max(0, matchStart)
		windowEnd := min(len(content), windowStart+maxContextLineRunes-1)
		return windowBytes(content, windowStart, windowEnd, matchStart, matchEnd)
	}
	windowStart := max(0, matchStart-side)
	windowEnd := min(len(content), matchEnd+side)
	if windowStart == 0 {
		windowEnd = min(len(content), windowStart+maxContextLineRunes-1)
	} else if windowEnd == len(content) {
		windowStart = max(0, len(content)-maxContextLineRunes+1)
	}
	return windowBytes(content, windowStart, windowEnd, matchStart, matchEnd)
}

func windowBytes(
	content []byte, windowStart, windowEnd, matchStart, matchEnd int,
) (string, int, int) {
	prefix, suffix := "", ""
	if windowStart > 0 {
		prefix = "…"
	}
	if windowEnd < len(content) {
		suffix = "…"
	}
	shift := utf8.RuneCountInString(prefix) - windowStart
	return prefix + string(content[windowStart:windowEnd]) + suffix,
		matchStart + shift, matchEnd + shift
}

func truncateRunes(value string, limit int) string {
	if utf8.RuneCountInString(value) <= limit {
		return value
	}
	return string([]rune(value)[:limit]) + "…"
}
