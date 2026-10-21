package analyze

import (
	"reflect"
	"strings"
	"testing"

	"github.com/youmulijiang/jsowl/internal/model"
)

// TestAnalyzeCandidatesMatchesAnalyze verifies the download-phase entry point:
// running only the URL rules must yield exactly the candidates the full pass
// derives, because a candidate can only come from a URL-category rule.
func TestAnalyzeCandidatesMatchesAnalyze(t *testing.T) {
	engine, err := New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	source := ResourceRef{URL: "https://example.test/app.js", Type: model.ResourceTypeScript}
	bodies := []string{
		`fetch("/api/users");const token="fixture";client_secret="DemoSecret_123=-"`,
		"import('/chunk/one.js');axios.post('/api/v1/orders',{id:1,name:'x'})",
		`var t="https://api.example.test/v2/items";window.location="/admin#/users"`,
		`const s="中文";fetch("/api/中文/路径");client_secret="秘密值12345678"`,
		"",
		"const onlySecret = 'client_secret = \"abcdefgh12345678\"';",
	}
	for _, body := range bodies {
		_, full := engine.Analyze(source, []byte(body))
		discovery := engine.AnalyzeCandidates(source, []byte(body))
		if !reflect.DeepEqual(full, discovery) {
			t.Fatalf("candidate mismatch for %q:\nfull=%#v\ndiscovery=%#v", body, full, discovery)
		}
	}
}

// legacyMatchContext is the previous implementation, kept verbatim so the
// table-based version can be compared against it.
func legacyMatchContext(body []byte, start, end int) []model.ContextLine {
	startLine := strings.Count(string(body[:start]), "\n")
	endLine := startLine
	if end > start {
		endLine += strings.Count(string(body[start:end]), "\n")
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
			matchStart = len([]rune(content[:matchStart]))
			matchEnd = len([]rune(content[:matchEnd]))
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

func TestFindingLinesMatchesLegacyContext(t *testing.T) {
	bodies := []string{
		"a\nb\nc\nd\ne",
		"line one\r\nline two\r\nline three\r\n",
		"one line without newline at all",
		"",
		"\n\n\n",
		"中文第一行\nsecond 行 with 中文\nthird",
		strings.Repeat("x", 500) + "/api/endpoint" + strings.Repeat("y", 700),
	}
	for _, body := range bodies {
		lines := newFindingLines([]byte(body))
		for offset := 0; offset <= len(body); offset++ {
			wantLine, wantColumn := legacyLocation([]byte(body), offset)
			gotLine, gotColumn := lines.location(offset)
			if gotLine != wantLine || gotColumn != wantColumn {
				t.Fatalf("location(%d) in %q = (%d,%d), want (%d,%d)",
					offset, body, gotLine, gotColumn, wantLine, wantColumn)
			}
		}
		for start := 0; start <= len(body); start += max(1, len(body)/7) {
			for end := start; end <= len(body); end += max(1, len(body)/5) {
				want := legacyMatchContext([]byte(body), start, end)
				got := lines.matchContext(start, end)
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("matchContext(%d,%d) in %q:\ngot=%#v\nwant=%#v",
						start, end, body, got, want)
				}
			}
		}
	}
}

func legacyLocation(body []byte, offset int) (int, int) {
	line := strings.Count(string(body[:offset]), "\n") + 1
	lastNewline := strings.LastIndex(string(body[:offset]), "\n")
	lineStart := lastNewline + 1
	column := len([]rune(string(body[lineStart:offset]))) + 1
	return line, column
}
