package pipeline

import (
	"net/url"
	"testing"

	"github.com/youmulijiang/jsowl/internal/model"
	"github.com/youmulijiang/jsowl/internal/scope"
)

// testScope builds a scope rooted at one target URL.
func testScope(t *testing.T, raw string) *scope.Scope {
	t.Helper()
	instance, err := scope.New(mustParse(t, raw), model.ScopeConfig{})
	if err != nil {
		t.Fatal(err)
	}
	return instance
}

func mustParse(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

// TestResolveCandidateTreatsBaseURLAsPrefix is the regression test for
// --base-url dropping its own path: with a base of https://host/api the
// reference "/users" used to resolve to https://host/users.
func TestResolveCandidateTreatsBaseURLAsPrefix(t *testing.T) {
	targetScope := testScope(t, "https://host/")
	source := mustParse(t, "https://host/static/app.js")
	base := mustParse(t, "https://host/api")

	cases := []struct {
		raw  string
		want string
	}{
		// A leading-slash reference is prefixed, not resolved from the root.
		{"/users", "https://host/api/users"},
		{"/users?page=2", "https://host/api/users?page=2"},
		{"/v1/orders/42", "https://host/api/v1/orders/42"},
		// A bare relative reference keeps the base path by itself.
		{"users", "https://host/api/users"},
		// A reference already written with the prefix is left alone.
		{"/api/users", "https://host/api/users"},
		{"/api", "https://host/api"},
		// Absolute URLs and protocol-relative references keep their own host.
		{"https://cdn.example.net/app.js", "https://cdn.example.net/app.js"},
		{"//cdn.example.net/app.js", "https://cdn.example.net/app.js"},
	}
	for _, testCase := range cases {
		resolved, err := resolveCandidate(targetScope, testCase.raw, source, base)
		if err != nil {
			t.Fatalf("resolveCandidate(%q): %v", testCase.raw, err)
		}
		if resolved.String() != testCase.want {
			t.Errorf("resolveCandidate(%q) = %q, want %q",
				testCase.raw, resolved.String(), testCase.want)
		}
	}
}

// TestResolveCandidateWithoutBaseURLIsUnchanged guards the default path: with
// no --base-url the resolution must behave exactly as before, including for a
// target that itself carries a path.
func TestResolveCandidateWithoutBaseURLIsUnchanged(t *testing.T) {
	targetScope := testScope(t, "https://host/app/")
	source := mustParse(t, "https://host/app/static/app.js")
	for _, testCase := range []struct {
		raw  string
		want string
	}{
		{"/users", "https://host/users"},
		{"users", "https://host/app/static/users"},
	} {
		resolved, err := resolveCandidate(targetScope, testCase.raw, source, nil)
		if err != nil {
			t.Fatal(err)
		}
		if resolved.String() != testCase.want {
			t.Errorf("resolveCandidate(%q) = %q, want %q",
				testCase.raw, resolved.String(), testCase.want)
		}
	}
}

func TestBasePathReference(t *testing.T) {
	for raw, want := range map[string]string{
		"/users":        "/users",
		"/users?page=1": "/users",
		"users":         "",
		"https://h/x":   "",
		"//h/x":         "",
		"/":             "",
		"/a/b/c":        "/a/b/c",
		"/users list":   "",
	} {
		if got := basePathReference(raw); got != want {
			t.Errorf("basePathReference(%q) = %q, want %q", raw, got, want)
		}
	}
}
