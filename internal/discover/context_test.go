package discover

import (
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestExtractContextLocatesValueText(t *testing.T) {
	prefix := "// padding to push the literal far from the callee "
	code := "axios.get(\"" + prefix + "/api/v1/doc_json\")"
	lines := extractContext([]byte(code), 0, 0, "/api/v1/doc_json")
	if len(lines) == 0 {
		t.Fatal("no context lines")
	}
	matched := lines[0]
	if matched.MatchStart < 0 || matched.MatchEnd <= matched.MatchStart {
		t.Fatalf("match region unset: %+v", matched)
	}
	runes := []rune(matched.Content)
	marked := string(runes[matched.MatchStart:matched.MatchEnd])
	if marked != "/api/v1/doc_json" {
		t.Fatalf("marked %q, want the value text", marked)
	}
}

func TestTrimContextLineKeepsLongMatchFullyVisible(t *testing.T) {
	content := strings.Repeat("x", 300) + strings.Repeat("M", 250) + strings.Repeat("y", 300)
	trimmed, start, end := trimContextLine(content, 300, 550)
	runes := []rune(trimmed)
	if start < 0 || end > len(runes) || end <= start {
		t.Fatalf("coords out of range: %d..%d in %d", start, end, len(runes))
	}
	if got := string(runes[start:end]); got != strings.Repeat("M", 250) {
		t.Fatalf("match clipped: %d runes of M", len(got))
	}
	if utf8.RuneCountInString(trimmed) > 402 {
		t.Fatalf("trimmed line too long: %d", utf8.RuneCountInString(trimmed))
	}
}

func TestExtractASCIIMatchesRunePath(t *testing.T) {
	bodies := []string{
		"a\nbb\nccc\ndddd",
		"one\r\ntwo\r\nthree\r\n",
		strings.Repeat("x", 300) + "/api/endpoint" + strings.Repeat("y", 700),
		"short line with /api/x and /api/x again",
		strings.Repeat("single-line-bundle/", 2000),
		"no newline at all",
	}
	values := []string{"/api/endpoint", "/api/x", "missing", "", "single-line-bundle/"}
	for _, body := range bodies {
		li := newLineIndex([]byte(body))
		if !li.isASCII() {
			t.Fatalf("fixture should be ASCII: %q", body[:min(len(body), 20)])
		}
		for offset := 0; offset <= len(body); offset += max(1, len(body)/13) {
			for _, value := range values {
				want := li.extractRunes(offset, contextSpanLines, value)
				got := li.extractASCII(offset, contextSpanLines, value)
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("extract(%d, %q) in body len %d:\ngot=%#v\nwant=%#v",
						offset, value, len(body), got, want)
				}
			}
		}
	}
}

// locateValueRowScan is the reference implementation: a full left-to-right
// scan picking the first occurrence with the smallest distance.
func locateValueRowScan(line []byte, offset int, value string) (int, int) {
	if value == "" {
		return -1, -1
	}
	needle := []byte(value)
	best, bestDistance := -1, 1<<60
	for index := 0; index+len(needle) <= len(line); index++ {
		if string(line[index:index+len(needle)]) != value {
			continue
		}
		distance := index - offset
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
	return best, best + len(needle)
}

func TestLocateValueBytesMatchesRowScan(t *testing.T) {
	lines := []string{
		"fetch(\"/api/users\");fetch(\"/api/users\");fetch(\"/api/users\")",
		strings.Repeat("x", 50) + "/api/a" + strings.Repeat("y", 50) + "/api/a",
		"/api/a/api/a/api/a",
		"no match here",
		"",
		strings.Repeat("ab", 100),
	}
	values := []string{"/api/users", "/api/a", "ab", "no match here", "missing", ""}
	for _, line := range lines {
		raw := []byte(line)
		for offset := 0; offset <= len(line); offset++ {
			for _, value := range values {
				wantStart, wantEnd := locateValueRowScan(raw, offset, value)
				gotStart, gotEnd := locateValueBytes(raw, offset, value)
				if gotStart != wantStart || gotEnd != wantEnd {
					t.Fatalf("locateValueBytes(%q, %d, %q) = (%d,%d), want (%d,%d)",
						line, offset, value, gotStart, gotEnd, wantStart, wantEnd)
				}
			}
		}
	}
}

func TestIsNoiseEndpoint(t *testing.T) {
	for _, raw := range []string{"//", "///", "////", "/"} {
		if !IsNoiseEndpoint(raw) {
			t.Fatalf("%q should be noise", raw)
		}
	}
	for _, raw := range []string{"/api/v1", "a/b", "./x", "/x/{}"} {
		if IsNoiseEndpoint(raw) {
			t.Fatalf("%q should not be noise", raw)
		}
	}
}
