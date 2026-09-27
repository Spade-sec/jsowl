package analyze

import (
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/dlclark/regexp2"

	"github.com/youmulijiang/jsowl/internal/model"
)

// nfaMatchTimeout bounds one regexp2 scan so a catastrophic-backtracking
// pattern cannot hang the analysis; a timeout keeps the matches found so far
// and drops the rest of that rule's pass.
const nfaMatchTimeout = 2 * time.Second

// The analysis engine is HaE-compatible: every rule compiles with regexp2
// (.NET-style NFA), so HaE patterns — lookarounds, backreferences, named
// groups — run verbatim. Capture indices there count runes, so matches are
// translated to byte offsets in the standard-library layout: two entries per
// capture group, group 0 first, -1 for non-participating groups.
type matcher interface {
	// findAll returns indices for every match in text. An error aborts the
	// remaining matches of the rule (e.g. a regexp2 timeout).
	findAll(text string, offsets []int) ([][]int, error)
	// findFirst applies the pattern to one extracted value, same index
	// layout, nil when it does not match.
	findFirst(value string) []int
	// groupCount is the number of capture groups, group 0 excluded.
	groupCount() int
}

type nfaMatcher struct{ re *regexp2.Regexp }

// compileMatcher compiles one rule pattern with regexp2, honouring the
// rule's case-insensitivity flag (HaE's `sensitive: false`) as an engine
// option so inline (?i) flags keep working alongside it.
func compileMatcher(rule model.Rule, pattern string) (matcher, error) {
	options := regexp2.None
	if rule.IgnoreCase {
		options |= regexp2.IgnoreCase
	}
	re, err := regexp2.Compile(pattern, options)
	if err != nil {
		return nil, err
	}
	re.MatchTimeout = nfaMatchTimeout
	return nfaMatcher{re: re}, nil
}

func (m nfaMatcher) findAll(text string, offsets []int) ([][]int, error) {
	results := make([][]int, 0)
	match, err := m.re.FindStringMatch(text)
	for match != nil && err == nil {
		if indices := nfaIndices(match, offsets); indices != nil {
			results = append(results, indices)
		}
		match, err = m.re.FindNextMatch(match)
	}
	return results, err
}

func (m nfaMatcher) findFirst(value string) []int {
	match, err := m.re.FindStringMatch(value)
	if err != nil || match == nil {
		return nil
	}
	return nfaIndices(match, runeOffsets(value))
}

func (m nfaMatcher) groupCount() int {
	return len(m.re.GetGroupNumbers()) - 1
}

// runeOffsets maps each rune start (and the text end) to its byte offset.
func runeOffsets(text string) []int {
	offsets := make([]int, 0, utf8.RuneCountInString(text)+1)
	for index := range text {
		offsets = append(offsets, index)
	}
	return append(offsets, len(text))
}

// nfaIndices converts one regexp2 match into RE2-style byte indices; it
// returns nil when the match lies outside the translated offsets.
func nfaIndices(match *regexp2.Match, offsets []int) []int {
	groups := match.Groups()
	indices := make([]int, 0, len(groups)*2)
	for _, group := range groups {
		start, end := -1, -1
		if len(group.Captures) > 0 {
			capture := group.Captures[0]
			runeStart := capture.Index
			runeEnd := capture.Index + capture.Length
			if runeStart >= 0 && runeEnd < len(offsets) {
				start, end = offsets[runeStart], offsets[runeEnd]
			}
		}
		indices = append(indices, start, end)
	}
	return indices
}

// groupText slices one capture group out of text using match indices; a
// group that did not participate or is out of range renders as empty.
func groupText(text string, indices []int, group int) string {
	offset := group * 2
	if offset+1 >= len(indices) {
		return ""
	}
	start, end := indices[offset], indices[offset+1]
	if start < 0 || end < start || end > len(text) {
		return ""
	}
	return text[start:end]
}

// expandFormat renders a HaE-style format string ("id: {1}") against match
// indices: {0} is the whole match, {N} the Nth capture group; anything that
// is not a {N} token is copied through verbatim.
func expandFormat(format string, text string, indices []int) string {
	var out strings.Builder
	for i := 0; i < len(format); {
		if format[i] == '{' {
			if end := strings.IndexByte(format[i:], '}'); end > 0 {
				if group, err := strconv.Atoi(format[i+1 : i+end]); err == nil {
					out.WriteString(groupText(text, indices, group))
					i += end + 1
					continue
				}
			}
		}
		out.WriteByte(format[i])
		i++
	}
	return out.String()
}
