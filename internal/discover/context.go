package discover

import (
	"strings"
	"unicode/utf8"

	"github.com/youmulijiang/jsowl/internal/model"
)

const contextSpanLines = 2

// maxContextLineRunes caps one context line so a minified single-line bundle
// does not drag the whole file into reports. The matched region stays visible;
// everything around it collapses to ellipses.
const maxContextLineRunes = 400

// extractContext returns the source line at the byte offset plus span lines
// on each side. When `value` is found in the matched line, the coordinates
// point at the actual value text; otherwise they mark a +-100-rune window
// around the offset so reports still have a region to highlight.
func extractContext(body []byte, offset, span int, value string) []model.ContextLine {
	if len(body) == 0 || offset < 0 || offset > len(body) {
		return nil
	}
	starts := lineStarts(body)
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
