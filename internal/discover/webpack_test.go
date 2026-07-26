package discover

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFromWebpack3ResolvesPublicPathAndChunkMap(t *testing.T) {
	body := readDiscoverFixture(t, "webpack3.js")
	source := mustParseURL(t, "https://example.test/assets/runtime.js")

	got := FromWebpack(source, body, 100)

	assertCandidate(t, got, "https://example.test/static/chunk-vendors.abc123.js", KindChunk)
	assertCandidate(t, got, "https://example.test/static/users.def456.js", KindChunk)
}

func TestFromWebpack5CombinesNameAndHashMaps(t *testing.T) {
	body := readDiscoverFixture(t, "webpack5.js")
	source := mustParseURL(t, "https://example.test/assets/runtime.js")

	got := FromWebpack(source, body, 100)

	assertCandidate(t, got, "https://example.test/static/js/users.a1b2.js", KindChunk)
	assertCandidate(t, got, "https://example.test/static/js/admin.c3d4.js", KindChunk)
}

func TestFromWebpackHonorsCandidateLimit(t *testing.T) {
	body := readDiscoverFixture(t, "webpack5.js")
	source := mustParseURL(t, "https://example.test/runtime.js")

	got := FromWebpack(source, body, 1)

	if len(got) != 1 {
		t.Fatalf("len(candidates) = %d, want 1", len(got))
	}
}

func readDiscoverFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}
