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

func TestFromWebpack5CombinesChunkIDWithHashTemplate(t *testing.T) {
	body := []byte(`
__webpack_require__.p="/assets/";
__webpack_require__.u=id=>id+"."+{123:"a1b2c3",456:"d4e5f6"}[id]+".js";
`)
	source := mustParseURL(t, "https://example.test/runtime.js")
	got := FromWebpack(source, body, 100)
	assertCandidate(
		t, got,
		"https://example.test/assets/123.a1b2c3.js",
		KindChunk,
	)
	assertCandidate(
		t, got,
		"https://example.test/assets/456.d4e5f6.js",
		KindChunk,
	)
}

func TestFromWebpackIgnoresOrdinaryObjectLiterals(t *testing.T) {
	body := []byte(`const config={primary:"blue",secondary:"green"};`)
	source := mustParseURL(t, "https://example.test/app.js")
	if got := FromWebpack(source, body, 100); len(got) != 0 {
		t.Fatalf("ordinary object produced chunk candidates: %#v", got)
	}
}

func TestFromWebpackIgnoresUnrelatedObjectInsideRuntime(t *testing.T) {
	body := []byte(`
__webpack_require__.p="/assets/";
const theme={primary:"blue",secondary:"green"};
__webpack_require__.u=id=>id+"."+{123:"a1b2c3"}[id]+".js";
`)
	source := mustParseURL(t, "https://example.test/runtime.js")
	got := FromWebpack(source, body, 100)
	if len(got) != 1 || got[0].Raw !=
		"https://example.test/assets/123.a1b2c3.js" {
		t.Fatalf("runtime candidates = %#v", got)
	}
}

func TestFromWebpack3IgnoresBracketAccessOutsideChunkExpression(t *testing.T) {
	body := []byte(`
__webpack_require__.p="/assets/";
const theme={primary:"blue"};
const chunkMap={123:"users.a1b2"};
function color(id) { return theme[id]; }
function load(id) { return __webpack_require__.p+chunkMap[id]+".js"; }
`)
	source := mustParseURL(t, "https://example.test/runtime.js")
	got := FromWebpack(source, body, 100)
	if len(got) != 1 || got[0].Raw !=
		"https://example.test/assets/users.a1b2.js" {
		t.Fatalf("runtime candidates = %#v", got)
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
