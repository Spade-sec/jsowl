package main

import (
	"testing"

	"github.com/youmulijiang/jsowl"
)

// TestApplyBaseURLAcceptsAbsoluteAndPathOnly pins the two shapes the flag
// accepts: a full http(s) URL, and a path-only prefix that the pipeline
// resolves against each target's own origin.
func TestApplyBaseURLAcceptsAbsoluteAndPathOnly(t *testing.T) {
	for _, testCase := range []struct {
		raw  string
		want string
	}{
		{"https://static.example/assets/", "https://static.example/assets/"},
		{"/api", "/api"},
		{"/api/", "/api/"},
		{"/", "/"},
	} {
		targets := []jsowl.Target{
			{URL: "https://a.example"},
			{URL: "https://b.example"},
		}
		if err := applyBaseURL(targets, testCase.raw); err != nil {
			t.Fatalf("applyBaseURL(%q): %v", testCase.raw, err)
		}
		for _, target := range targets {
			if target.BaseURL != testCase.want {
				t.Fatalf("ApplyBaseURL(%q) stored %q, want %q",
					testCase.raw, target.BaseURL, testCase.want)
			}
		}
	}
}

func TestApplyBaseURLRejectsOtherShapes(t *testing.T) {
	for _, raw := range []string{
		"api",                 // bare relative: ambiguous prefix
		"//other.example/x",   // protocol-relative
		"ftp://example/x",     // non-http scheme
		"mailto:user@example", // no host
	} {
		targets := []jsowl.Target{{URL: "https://a.example"}}
		if err := applyBaseURL(targets, raw); err == nil {
			t.Fatalf("applyBaseURL(%q) = nil error", raw)
		}
		if targets[0].BaseURL != "" {
			t.Fatalf("applyBaseURL(%q) mutated the target", raw)
		}
	}
}

// TestLocalBaseURLRequiresAbsoluteURL pins the --location rule: without -u a
// path-only prefix has no host, so it must be rejected instead of guessed.
func TestLocalBaseURLRequiresAbsoluteURL(t *testing.T) {
	for _, raw := range []string{
		"", "https://api.example.test", "https://api.example.test/v1",
		"http://127.0.0.1:8080/api",
	} {
		if _, err := localBaseURL(raw); err != nil {
			t.Fatalf("localBaseURL(%q): %v", raw, err)
		}
	}
	for _, raw := range []string{
		"/api", "/", "api", "//api.example.test/x", "ftp://api.example.test/x",
	} {
		if _, err := localBaseURL(raw); err == nil {
			t.Fatalf("localBaseURL(%q) = nil error", raw)
		}
	}
}
