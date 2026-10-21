package discover

import (
	"bytes"
	"strings"
	"unicode/utf8"

	"github.com/youmulijiang/jsowl/internal/model"
)

const contextSpanLines = 2

// maxContextLineRunes caps one context line so a minified single-line bundle
// does not drag the whole file into reports. The matched region stays visible;
// everything around it collapses to ellipses.
const maxContextLineRunes = 400

// lineIndex caches the line starts of one body so every match in the same
// body reuses them. The previous implementation rebuilt the index for each
// hit, which turned a match-heavy minified bundle into repeated full scans.
type lineIndex struct {
	body   []byte
	starts []int
	// ascii caches the body's encoding: 0 unknown, 1 ASCII, -1 non-ASCII.
	// Minified bundles are ASCII, which lets extraction work on short windows
	// instead of converting the whole (possibly megabyte) line per match.
	ascii int8
}

func newLineIndex(body []byte) *lineIndex {
	return &lineIndex{body: body, starts: lineStarts(body)}
}

func (li *lineIndex) isASCII() bool {
	switch li.ascii {
	case 1:
		return true
	case -1:
		return false
	}
	li.ascii = 1
	for _, char := range li.body {
		if char >= utf8.RuneSelf {
			li.ascii = -1
			return false
		}
	}
	return true
}

// position reports the 1-based line and rune column of a byte offset.
func (li *lineIndex) position(offset int) (int, int) {
	if len(li.body) == 0 || offset < 0 || offset > len(li.body) {
		return 0, 0
	}
	line := countLine(li.starts, offset) + 1
	lineStart := li.starts[line-1]
	column := utf8.RuneCount(li.body[lineStart:offset]) + 1
	return line, column
}

// extract returns the source line at the byte offset plus span lines on each
// side. When `value` is found in the matched line, the coordinates point at
// the actual value text; otherwise they mark a +-100-rune window around the
// offset so reports still have a region to highlight.
func (li *lineIndex) extract(offset, span int, value string) []model.ContextLine {
	if len(li.body) == 0 || offset < 0 || offset > len(li.body) {
		return nil
	}
	if li.isASCII() {
		return li.extractASCII(offset, span, value)
	}
	return li.extractRunes(offset, span, value)
}

// extractASCII is the scan path for ASCII bodies: it never converts a whole
// long line to runes, so a 1 MB minified line with thousands of matches costs
// one short window per match instead of a full-line scan.
func (li *lineIndex) extractASCII(offset, span int, value string) []model.ContextLine {
	body, starts := li.body, li.starts
	line := countLine(starts, offset)
	first := max(0, line-span)
	last := min(len(starts)-1, line+span)
	lines := make([]model.ContextLine, 0, last-first+1)
	for index := first; index <= last; index++ {
		start := starts[index]
		end := len(body)
		if index+1 < len(starts) {
			end = starts[index+1]
		}
		if index == line {
			content, matchStart, matchEnd := asciiMatchedLine(
				body[start:end], offset-start, value,
			)
			lines = append(lines, model.ContextLine{
				LineNumber: index + 1,
				Content:    content,
				MatchStart: matchStart,
				MatchEnd:   matchEnd,
			})
			continue
		}
		raw := body[start:end]
		if size := len(raw); size > 0 && raw[size-1] == '\r' {
			raw = raw[:size-1]
		}
		content := ""
		if len(raw) > maxContextLineRunes {
			content = string(raw[:maxContextLineRunes]) + "…"
		} else {
			content = string(raw)
		}
		lines = append(lines, model.ContextLine{
			LineNumber: index + 1, Content: content,
			MatchStart: -1, MatchEnd: -1,
		})
	}
	return lines
}

// asciiMatchedLine renders one matched line: the whole line when it fits the
// context budget, a window around the match otherwise. matchOffset is the
// match byte offset inside line.
func asciiMatchedLine(line []byte, matchOffset int, value string) (string, int, int) {
	if size := len(line); size > 0 && line[size-1] == '\r' {
		line = line[:size-1]
	}
	matchOffset = min(max(matchOffset, 0), len(line))
	matchStart, matchEnd := locateValueBytes(line, matchOffset, value)
	if matchStart < 0 {
		matchStart = max(0, matchOffset-100)
		matchEnd = min(len(line), matchOffset+100)
	}
	if len(line) <= maxContextLineRunes {
		return string(line), matchStart, matchEnd
	}
	return trimBytesLine(line, matchStart, matchEnd)
}

// locateValueBytes finds the occurrence of value nearest to the match offset.
// It checks the offset itself first (the common case), then the first
// occurrence at or after it, and only searches backwards within that distance
// — so a call site on a megabyte-long minified line costs a short window, not
// a whole-line scan. Ties keep the earlier occurrence, matching the old
// left-to-right rune scan.
func locateValueBytes(line []byte, offset int, value string) (int, int) {
	if value == "" {
		return -1, -1
	}
	needle := []byte(value)
	if offset+len(needle) <= len(line) &&
		string(line[offset:offset+len(needle)]) == value {
		return offset, offset + len(needle)
	}
	best, bestDistance := -1, 0
	if offset < len(line) {
		if found := bytes.Index(line[offset:], needle); found >= 0 {
			best = offset + found
			bestDistance = found
		}
	}
	// Any closer occurrence must start within bestDistance bytes before the
	// offset; when there is no forward occurrence the whole prefix is checked.
	windowStart := 0
	if best >= 0 {
		windowStart = max(0, offset-bestDistance)
	}
	searchEnd := min(len(line), offset+len(needle)-1)
	for searchEnd > windowStart {
		found := bytes.LastIndex(line[windowStart:searchEnd], needle)
		if found < 0 {
			break
		}
		index := windowStart + found
		if index < offset {
			distance := offset - index
			if best < 0 || distance <= bestDistance {
				best, bestDistance = index, distance
			}
			break
		}
		// This occurrence starts at or after the offset; keep looking left.
		searchEnd = index
	}
	if best < 0 {
		return -1, -1
	}
	return best, best + len(needle)
}

// trimBytesLine is trimContextLine for an ASCII line, measured in bytes.
func trimBytesLine(line []byte, matchStart, matchEnd int) (string, int, int) {
	if len(line) <= maxContextLineRunes {
		return string(line), matchStart, matchEnd
	}
	forMatchEnd := min(max(matchEnd, 0), len(line))
	forMatchStart := min(max(matchStart, 0), forMatchEnd)
	matchStart, matchEnd = forMatchStart, forMatchEnd
	matchLen := matchEnd - matchStart
	side := (maxContextLineRunes - 1 - matchLen) / 2
	if side < 0 {
		windowStart := matchStart
		windowEnd := min(len(line), windowStart+maxContextLineRunes-1)
		return prefixWindowBytes(line, windowStart, windowEnd, matchStart, matchEnd)
	}
	windowStart := max(0, matchStart-side)
	windowEnd := min(len(line), matchEnd+side)
	if windowStart == 0 {
		windowEnd = min(len(line), windowStart+maxContextLineRunes-1)
	} else if windowEnd == len(line) {
		windowStart = max(0, len(line)-maxContextLineRunes+1)
	}
	return prefixWindowBytes(line, windowStart, windowEnd, matchStart, matchEnd)
}

func prefixWindowBytes(
	line []byte, windowStart, windowEnd, matchStart, matchEnd int,
) (string, int, int) {
	prefix, suffix := "", ""
	if windowStart > 0 {
		prefix = "…"
	}
	if windowEnd < len(line) {
		suffix = "…"
	}
	shift := utf8.RuneCountInString(prefix) - windowStart
	return prefix + string(line[windowStart:windowEnd]) + suffix,
		matchStart + shift, matchEnd + shift
}

// extractRunes is the original path, kept for bodies carrying multi-byte
// text where rune offsets and byte offsets diverge.
func (li *lineIndex) extractRunes(offset, span int, value string) []model.ContextLine {
	body := li.body
	starts := li.starts
	line := countLine(starts, offset)
	first := max(0, line-span)
	last := min(len(starts)-1, line+span)
	lines := make([]model.ContextLine, 0, last-first+1)
	for index := first; index <= last; index++ {
		end := len(body)
		if index+1 < len(starts) {
			end = starts[index+1]
		}
		content := strings.TrimSuffix(string(body[starts[index]:end]), "\r")
		matchStart, matchEnd := -1, -1
		if index == line {
			// The match offset is a byte offset, but the reported
			// coordinates and the trim window are rune-based. Convert once
			// here: on a minified bundle carrying multi-byte text the two
			// differ by thousands, and mixing them shifts the window away
			// from the match.
			matchByte := min(max(offset-starts[index], 0), len(content))
			matchRune := utf8.RuneCountInString(content[:matchByte])
			total := utf8.RuneCountInString(content)
			matchStart, matchEnd = locateValueRunes(content, matchRune, value)
			if matchStart < 0 {
				matchStart = max(0, matchRune-100)
				matchEnd = min(total, matchRune+100)
			}
		}
		if matchStart >= 0 {
			content, matchStart, matchEnd = trimContextLine(
				content, matchStart, matchEnd,
			)
		} else if utf8.RuneCountInString(content) > maxContextLineRunes {
			runes := []rune(content)
			content = string(runes[:maxContextLineRunes]) + "…"
		}
		lines = append(lines, model.ContextLine{
			LineNumber: index + 1,
			Content:    content,
			MatchStart: matchStart,
			MatchEnd:   matchEnd,
		})
	}
	return lines
}

// extractContext is the one-off wrapper for callers that hold no index.
func extractContext(body []byte, offset, span int, value string) []model.ContextLine {
	return newLineIndex(body).extract(offset, span, value)
}

// locateValueRunes finds `value` in `content` near the offset rune (the AST
// callee sits at or shortly before the URL literal) and returns rune
// coordinates for the actual text, so report highlights wrap the real match
// instead of an arbitrary window. -1 when the value is not in the line —
// the source spelling can differ from the decoded value (escapes,
// concatenation).
func locateValueRunes(content string, offsetRune int, value string) (int, int) {
	if value == "" {
		return -1, -1
	}
	runes := []rune(content)
	need := []rune(value)
	if len(need) > len(runes) {
		return -1, -1
	}
	// Prefer the nearest occurrence to the offset, searching outward.
	best, bestDistance := -1, 1<<30
	for index := 0; index+len(need) <= len(runes); index++ {
		match := true
		for i, char := range need {
			if runes[index+i] != char {
				match = false
				break
			}
		}
		if !match {
			continue
		}
		distance := index - offsetRune
		if distance < 0 {
			distance = -distance
		}
		if distance < bestDistance {
			best, bestDistance = index, distance
		}
	}
	if best < 0 {
		return -1, -1
	}
	return best, best + len(need)
}

// trimContextLine shortens the matched line to maxContextLineRunes runes
// while keeping the matched region fully visible: the side budgets are
// balanced around the match, so a long match can never be clipped by the
// window the way a symmetric +-half window could.
func trimContextLine(content string, matchStart, matchEnd int) (string, int, int) {
	if utf8.RuneCountInString(content) <= maxContextLineRunes {
		return content, matchStart, matchEnd
	}
	const ellipsis = "…"
	ellipsisRunes := utf8.RuneCountInString(ellipsis)
	runes := []rune(content)
	if matchEnd > len(runes) {
		matchEnd = len(runes)
	}
	if matchStart > matchEnd {
		matchStart = matchEnd
	}
	matchLen := matchEnd - matchStart
	side := (maxContextLineRunes - ellipsisRunes - matchLen) / 2
	if side < 0 {
		// The match alone exceeds the budget: show its head.
		windowStart := max(0, matchStart)
		windowEnd := min(len(runes), windowStart+maxContextLineRunes-ellipsisRunes)
		return prefixWindow(runes, windowStart, windowEnd, matchStart, matchEnd)
	}
	windowStart := max(0, matchStart-side)
	windowEnd := min(len(runes), matchEnd+side)
	// Rebalance whatever side budget went unused at the boundaries.
	if windowStart == 0 {
		windowEnd = min(len(runes), windowStart+maxContextLineRunes-ellipsisRunes)
	} else if windowEnd == len(runes) {
		windowStart = max(0, len(runes)-maxContextLineRunes+ellipsisRunes)
	}
	return prefixWindow(runes, windowStart, windowEnd, matchStart, matchEnd)
}

func prefixWindow(
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

// lineStarts returns the byte offset of every line start.
func lineStarts(body []byte) []int {
	starts := []int{0}
	for index, char := range body {
		if char == '\n' && index+1 < len(body) {
			starts = append(starts, index+1)
		}
	}
	return starts
}

func countLine(starts []int, offset int) int {
	return sortSearchInts(starts, offset+1) - 1
}

// sortSearchInts mirrors sort.SearchInts without importing sort here.
func sortSearchInts(starts []int, value int) int {
	low, high := 0, len(starts)
	for low < high {
		mid := int(uint(low+high) >> 1)
		if starts[mid] < value {
			low = mid + 1
		} else {
			high = mid
		}
	}
	return low
}
