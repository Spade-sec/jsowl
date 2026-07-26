package discover

import (
	"net/url"
	"testing"
)

func TestFromHTMLFindsResourcesInlineScriptsAndSPAEvidence(t *testing.T) {
	base := mustParseURL(t, "https://example.test/app/index.html")
	body := []byte(`
<!doctype html>
<html>
  <head>
    <base href="/static/">
    <link rel="modulepreload" href="//cdn.example.test/vendor.js">
    <link rel="stylesheet" href="site.css">
    <meta http-equiv="refresh" content="10; url=/next">
  </head>
  <body>
    <div id="app"></div>
    <script type="module" src="main.js"></script>
    <script>fetch("/api/inline")</script>
    <a href="/dashboard">Dashboard</a>
    <form action="/login"></form>
    <img src="/logo.png">
  </body>
</html>`)

	got := FromHTML(base, body)

	assertCandidate(t, got.Candidates, "https://example.test/static/main.js", KindScript)
	assertCandidate(t, got.Candidates, "https://cdn.example.test/vendor.js", KindScript)
	assertCandidate(t, got.Candidates, "https://example.test/static/site.css", KindAsset)
	assertCandidate(t, got.Candidates, "https://example.test/logo.png", KindAsset)
	assertCandidate(t, got.Candidates, "https://example.test/next", KindRoute)
	assertCandidate(t, got.Candidates, "https://example.test/dashboard", KindRoute)
	assertCandidate(t, got.Candidates, "https://example.test/login", KindRoute)
	if len(got.InlineScripts) != 1 || got.InlineScripts[0] != `fetch("/api/inline")` {
		t.Fatalf("InlineScripts = %#v", got.InlineScripts)
	}
	if !got.SPA.RootNode {
		t.Fatal("SPA.RootNode = false")
	}
}

func TestFromHTMLToleratesMalformedMarkupAndDeduplicates(t *testing.T) {
	base := mustParseURL(t, "https://example.test/")
	body := []byte(`<script src="/app.js"><script src="/app.js"><img src=>`)

	got := FromHTML(base, body)

	count := 0
	for _, candidate := range got.Candidates {
		if candidate.Raw == "https://example.test/app.js" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("app.js candidate count = %d, want 1", count)
	}
}

func assertCandidate(t *testing.T, candidates []Candidate, raw string, kind Kind) {
	t.Helper()
	for _, candidate := range candidates {
		if candidate.Raw == raw && candidate.Kind == kind {
			return
		}
	}
	t.Fatalf("candidate %s (%s) not found in %#v", raw, kind, candidates)
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}
