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
// on each side. The matched line is marked; coordinates stay unset (-1) so
// callers only get line-level highlighting.
func extractContext(body []byte, offset, span int) []model.ContextLine {
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
			matchStart = max(0, matchRune-100)
			matchEnd = min(total, matchRune+100)
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

// trimContextLine shortens the matched line to maxContextLineRunes runes,
// centering the window on the matched region.
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
	half := (maxContextLineRunes - utf8.RuneCountInString(ellipsis)) / 2
	windowStart := max(0, min(matchStart-half, len(runes)-maxContextLineRunes))
	windowEnd := min(len(runes), windowStart+maxContextLineRunes)
	prefix, suffix := "", ""
	if windowStart > 0 {
		prefix = ellipsis
	}
	if windowEnd < len(runes) {
		suffix = ellipsis
	}
	newStart := matchStart - windowStart
	newEnd := matchEnd - windowStart
	if prefix != "" {
		newStart += utf8.RuneCountInString(prefix)
		newEnd += utf8.RuneCountInString(prefix)
	}
	return prefix + string(runes[windowStart:windowEnd]) + suffix, newStart, newEnd
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
