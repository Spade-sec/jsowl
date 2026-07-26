package discover

import "testing"

func TestFromRequireJSResolvesBaseURLPathsAndModules(t *testing.T) {
	body := readDiscoverFixture(t, "requirejs.js")
	source := mustParseURL(t, "https://example.test/js/main.js")

	got := FromRequireJS(source, body, 100)

	assertCandidate(t, got, "https://example.test/assets/lib/jquery.min.js", KindChunk)
	assertCandidate(t, got, "https://example.test/assets/pages/users.js", KindChunk)
	assertCandidate(t, got, "https://cdn.example.test/vue.min.js", KindChunk)
}

func TestFromRequireJSHonorsCandidateLimit(t *testing.T) {
	body := readDiscoverFixture(t, "requirejs.js")
	source := mustParseURL(t, "https://example.test/js/main.js")

	got := FromRequireJS(source, body, 2)

	if len(got) != 2 {
		t.Fatalf("len(candidates) = %d, want 2", len(got))
	}
}
