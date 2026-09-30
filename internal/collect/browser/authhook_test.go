package browser

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestAuthHookScriptEmptyWithoutReplayableHeaders(t *testing.T) {
	t.Parallel()
	headers := http.Header{
		"Cookie":     {"session=abc"},
		"User-Agent": {"Mozilla/5.0"},
	}
	if script := authHookScript("https://example.com/", headers); script != "" {
		t.Fatalf("expected empty script for transport-managed headers, got %d bytes", len(script))
	}
}

func TestAuthHookScriptEmbedsReplayableHeaders(t *testing.T) {
	t.Parallel()
	headers := http.Header{
		"Authorization":  {"Bearer tok-1"},
		"X-Custom-Trace": {"v=1"},
	}
	script := authHookScript("https://example.com/", headers)
	for _, want := range []string{"Authorization", "X-Custom-Trace", "tok-1"} {
		if !strings.Contains(script, want) {
			t.Fatalf("script missing %q:\n%s", want, script)
		}
	}
	// Cookie and User-Agent must never be replayed from a script: the
	// browser transport owns both through SetCookies and the UA override.
	for _, banned := range []string{"session=abc", "Mozilla/5.0"} {
		if strings.Contains(script, banned) {
			t.Fatalf("script leaked transport-managed header %q", banned)
		}
	}
	// Override semantics: -H replaces page-set values. fetch uses set()
	// (replace), and XHR swallows page setRequestHeader calls for replayed
	// names instead of appending after them.
	for _, want := range []string{"provided.set(", "replayed[name.toLowerCase()]"} {
		if !strings.Contains(script, want) {
			t.Fatalf("script lost override semantics marker %q:\n%s", want, script)
		}
	}
	if strings.Contains(script, "provided.append(") {
		t.Fatal("script must not append under existing values; override required")
	}
	var config struct {
		Headers map[string][]string `json:"headers"`
		Origin  string              `json:"origin"`
		Bearer  string              `json:"bearer"`
	}
	start := strings.Index(script, "var CONFIG = ") + len("var CONFIG = ")
	decoder := json.NewDecoder(strings.NewReader(script[start:]))
	if err := decoder.Decode(&config); err != nil {
		t.Fatalf("decode embedded CONFIG: %v", err)
	}
	if config.Origin != "https://example.com/" {
		t.Fatalf("origin = %q", config.Origin)
	}
	if config.Bearer != "tok-1" {
		t.Fatalf("bearer = %q", config.Bearer)
	}
	if got := config.Headers["X-Custom-Trace"]; len(got) != 1 || got[0] != "v=1" {
		t.Fatalf("replay headers = %v", config.Headers["X-Custom-Trace"])
	}
}

func TestAuthHookScriptHandlesQuotesAndNewlines(t *testing.T) {
	t.Parallel()
	headers := http.Header{
		"X-Evil": {"a\"b\nc(); alert(1)"},
	}
	script := authHookScript("https://example.com/", headers)
	if strings.Contains(script, "\n    a\"b") {
		t.Fatal("header value was not JSON-encoded into the script")
	}
	if !strings.Contains(script, `a\"b\nc(); alert(1)`) {
		t.Fatal("expected JSON-escaped header value in script")
	}
}

func TestBearerToken(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"Bearer abc":         "abc",
		"bearer abc":         "abc",
		"BEARER  spaced  ":   "spaced",
		"Basic dXNlcjpwYXNz": "",
		"Bearer":             "",
		"":                   "",
	}
	for input, want := range cases {
		if got := bearerToken(input); got != want {
			t.Errorf("bearerToken(%q) = %q, want %q", input, got, want)
		}
	}
}
