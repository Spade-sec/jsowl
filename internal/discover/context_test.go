package discover

import (
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
