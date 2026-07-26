package scope

import (
	"net/url"
	"testing"

	"github.com/youmulijiang/jsowl/internal/model"
)

func TestScopeSeparatesScriptFetchFromEndpointProbe(t *testing.T) {
	root := parseURL(t, "https://app.example.com/start")
	s, err := New(root, model.ScopeConfig{
		FetchExternalScripts: true,
		AllowDomains:         []string{"api.example.net"},
	})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		raw       string
		wantURL   string
		wantFetch bool
		wantProbe bool
	}{
		{"/api/users#top", "https://app.example.com/api/users", true, true},
		{"//cdn.example.net/app.js", "https://cdn.example.net/app.js", true, false},
		{"https://api.example.net/v1", "https://api.example.net/v1", true, true},
		{"https://outside.test/v1", "https://outside.test/v1", true, false},
	}

	for _, test := range tests {
		t.Run(test.raw, func(t *testing.T) {
			resolved, resolveErr := s.Resolve(test.raw, root)
			if resolveErr != nil {
				t.Fatal(resolveErr)
			}
			if got := Canonical(resolved); got != test.wantURL {
				t.Fatalf("Canonical() = %q, want %q", got, test.wantURL)
			}
			if got := s.CanFetchScript(resolved); got != test.wantFetch {
				t.Fatalf("CanFetchScript() = %t, want %t", got, test.wantFetch)
			}
			if got := s.CanProbe(resolved); got != test.wantProbe {
				t.Fatalf("CanProbe() = %t, want %t", got, test.wantProbe)
			}
		})
	}
}

func TestCanonicalNormalizesEquivalentHTTPURLs(t *testing.T) {
	got := Canonical(parseURL(t, "HTTPS://Example.COM:443/a/../b/./c.js?q=1#fragment"))
	want := "https://example.com/b/c.js?q=1"
	if got != want {
		t.Fatalf("Canonical() = %q, want %q", got, want)
	}

	got = Canonical(parseURL(t, "http://Example.COM:80"))
	if got != "http://example.com/" {
		t.Fatalf("Canonical(default port) = %q", got)
	}
}

func TestResolveRejectsUnsafeSchemesAndCredentials(t *testing.T) {
	root := parseURL(t, "https://example.com")
	s, err := New(root, model.ScopeConfig{})
	if err != nil {
		t.Fatal(err)
	}

	for _, raw := range []string{
		"javascript:alert(1)",
		"data:text/plain,secret",
		"ftp://example.com/file",
		"https://user:pass@example.com/private",
	} {
		t.Run(raw, func(t *testing.T) {
			if _, resolveErr := s.Resolve(raw, root); resolveErr == nil {
				t.Fatalf("Resolve(%q) error = nil", raw)
			}
		})
	}
}

func TestAllowlistSupportsExactAndExplicitSubdomainEntries(t *testing.T) {
	root := parseURL(t, "https://example.com")
	s, err := New(root, model.ScopeConfig{
		AllowDomains: []string{"api.example.net", ".trusted.test"},
	})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		raw  string
		want bool
	}{
		{"https://api.example.net/v1", true},
		{"https://sub.api.example.net/v1", false},
		{"https://a.trusted.test/v1", true},
		{"https://trusted.test/v1", false},
		{"https://eviltrusted.test/v1", false},
	}
	for _, test := range tests {
		if got := s.CanProbe(parseURL(t, test.raw)); got != test.want {
			t.Errorf("CanProbe(%q) = %t, want %t", test.raw, got, test.want)
		}
	}
}

func TestProbeExternalEndpointsRequiresExplicitOptIn(t *testing.T) {
	root := parseURL(t, "https://example.com")
	s, err := New(root, model.ScopeConfig{ProbeExternalEndpoints: true})
	if err != nil {
		t.Fatal(err)
	}

	external := parseURL(t, "https://outside.test/v1")
	if !s.CanProbe(external) {
		t.Fatal("CanProbe(external) = false with explicit opt-in")
	}
}

func TestSuffixBlacklistIgnoresCaseAndQuery(t *testing.T) {
	root := parseURL(t, "https://example.com")
	s, err := New(root, model.ScopeConfig{
		SuffixBlacklist: []string{"png", ".WOFF2"},
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, raw := range []string{
		"https://example.com/logo.PNG?cache=1",
		"https://example.com/font.woff2#fragment",
	} {
		if !s.IsSuffixBlocked(parseURL(t, raw)) {
			t.Errorf("IsSuffixBlocked(%q) = false", raw)
		}
	}
	if s.IsSuffixBlocked(parseURL(t, "https://example.com/app.js?image=.png")) {
		t.Fatal("query string incorrectly triggered suffix blacklist")
	}
}

func parseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}
