package discover

import (
	"strings"

	"github.com/youmulijiang/jsowl/internal/model"
)

const contextSpanLines = 3

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
			matchStart = 0
			matchEnd = len(content)
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
