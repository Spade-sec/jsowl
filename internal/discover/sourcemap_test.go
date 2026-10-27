package discover

import (
	"encoding/base64"
	"testing"
)

func TestParseSourceMapPairsSourcesWithContent(t *testing.T) {
	body := []byte(`{
	  "version": 3,
	  "sources": ["webpack:///./src/views/user.js", "../../secret.js", "no-content.js"],
	  "sourcesContent": ["export const a = 1", "export const b = 2", null],
	  "mappings": "AAAA"
	}`)
	files := ParseSourceMap(body)
	if len(files) != 2 {
		t.Fatalf("files = %#v", files)
	}
	if files[0].Name != "src/views/user.js" || files[0].Content != "export const a = 1" {
		t.Fatalf("files[0] = %#v", files[0])
	}
	// Traversal and scheme segments are stripped, never escaped upwards.
	if files[1].Name != "secret.js" || files[1].Content != "export const b = 2" {
		t.Fatalf("files[1] = %#v", files[1])
	}
}

func TestSourceMapReferenceHandlesExternalAndInlineForms(t *testing.T) {
	external := []byte("var a=1;\n//# sourceMappingURL=app.js.map\n")
	content, reference, ok := SourceMapReference(external)
	if !ok || reference != "app.js.map" || len(content) != 0 {
		t.Fatalf("external = %q %q %v", content, reference, ok)
	}

	inline := []byte("var a=1;\n//# sourceMappingURL=data:application/json;base64," +
		base64.StdEncoding.EncodeToString([]byte(`{"sources":["a.js"],"sourcesContent":["x"]}`)))
	content, reference, ok = SourceMapReference(inline)
	if !ok || reference != "" || len(ParseSourceMap(content)) != 1 {
		t.Fatalf("inline = %q %q %v", content, reference, ok)
	}

	if _, _, ok := SourceMapReference([]byte("var a=1;")); ok {
		t.Fatal("body without a reference reported one")
	}
}

func TestParseSourceMapDetailedReportsWhySourcesAreMissing(t *testing.T) {
	corrupt := ParseSourceMapDetailed([]byte(`{not json`))
	if corrupt.Err == nil {
		t.Fatal("corrupt map did not report an error")
	}
	missing := ParseSourceMapDetailed([]byte(
		`{"version":3,"sources":["a.js","b.js"],"sourcesContent":[null,null]}`,
	))
	if missing.Err != nil {
		t.Fatalf("missing content reported an error: %v", missing.Err)
	}
	if missing.Sources != 2 || missing.Embedded != 0 || len(missing.Files) != 0 {
		t.Fatalf("missing = %#v", missing)
	}
	embedded := ParseSourceMapDetailed([]byte(
		`{"version":3,"sources":["webpack:///./src/a.js"],` +
			`"sourcesContent":["fetch(\"/x\");"]}`,
	))
	if embedded.Sources != 1 || embedded.Embedded != 1 ||
		len(embedded.Files) != 1 || embedded.Files[0].Name != "src/a.js" {
		t.Fatalf("embedded = %#v", embedded)
	}
}

func TestIsSourceMapPath(t *testing.T) {
	for _, want := range []string{"/static/js/app.6b63242c.js.map", "app.MAP"} {
		if !isSourceMapPath(want) {
			t.Errorf("isSourceMapPath(%q) = false", want)
		}
	}
	for _, unwanted := range []string{"/app.js", "/map/app.js", "/api/maps"} {
		if isSourceMapPath(unwanted) {
			t.Errorf("isSourceMapPath(%q) = true", unwanted)
		}
	}
}

func TestCleanSourceNameRejectsEscapes(t *testing.T) {
	for input, want := range map[string]string{
		"../../../../etc/passwd":   "etc/passwd",
		"webpack:///./src/main.ts": "src/main.ts",
		"http://evil.test/a/b.js":  "a/b.js",
		"a/b.js?v=1#x":             "a/b.js",
		"":                         "",
	} {
		if got := CleanSourceName(input); got != want {
			t.Errorf("CleanSourceName(%q) = %q, want %q", input, got, want)
		}
	}
}
