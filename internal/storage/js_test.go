package storage

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/youmulijiang/jsowl/internal/model"
)

func TestSaveJSStaysContainedAndSanitizesWindowsNames(t *testing.T) {
	root := t.TempDir()
	target := mustURL(t, "https://example.test")
	resource := model.Resource{
		URL:  "https://example.test/../../CON?.js?token=a",
		Type: model.ResourceTypeScript,
	}

	relative, err := SaveJS(root, target, resource, []byte("window.ok = true"))
	if err != nil {
		t.Fatal(err)
	}
	if filepath.IsAbs(relative) || strings.Contains(relative, "..") {
		t.Fatalf("unsafe relative path %q", relative)
	}
	absolute := filepath.Join(root, filepath.FromSlash(relative))
	cleanRoot, _ := filepath.Abs(root)
	cleanFile, _ := filepath.Abs(absolute)
	if !strings.HasPrefix(cleanFile, cleanRoot+string(filepath.Separator)) {
		t.Fatalf("saved file escaped root: %q", cleanFile)
	}
	if _, err := os.Stat(absolute); err != nil {
		t.Fatalf("saved file: %v", err)
	}
	if strings.EqualFold(strings.TrimSuffix(filepath.Base(absolute), ".js"), "CON") {
		t.Fatalf("reserved Windows name was not sanitized: %q", absolute)
	}
}

func TestSaveJSSeparatesQueryCollisionsAndDeduplicatesIdenticalWrite(t *testing.T) {
	root := t.TempDir()
	target := mustURL(t, "https://example.test")
	first := model.Resource{
		URL: "https://example.test/app.js?v=1", Type: model.ResourceTypeScript,
	}
	second := model.Resource{
		URL: "https://example.test/app.js?v=2", Type: model.ResourceTypeChunk,
	}

	firstPath, err := SaveJS(root, target, first, []byte("one"))
	if err != nil {
		t.Fatal(err)
	}
	again, err := SaveJS(root, target, first, []byte("one"))
	if err != nil {
		t.Fatal(err)
	}
	secondPath, err := SaveJS(root, target, second, []byte("two"))
	if err != nil {
		t.Fatal(err)
	}
	if firstPath != again {
		t.Fatalf("identical write paths differ: %q != %q", firstPath, again)
	}
	if firstPath == secondPath {
		t.Fatalf("query collision overwrote %q", firstPath)
	}
}

func TestSaveJSRejectsNonScriptResources(t *testing.T) {
	_, err := SaveJS(t.TempDir(), mustURL(t, "https://example.test"), model.Resource{
		URL: "https://example.test/api", Type: model.ResourceTypeAPI,
	}, []byte(`{"secret":"value"}`))
	if err == nil {
		t.Fatal("SaveJS() error = nil for API resource")
	}
}

func TestLoadJSReadsSavedScriptAndRejectsEscapePaths(t *testing.T) {
	root := t.TempDir()
	relative, err := SaveJS(root, mustURL(t, "https://example.test"), model.Resource{
		URL: "https://example.test/app.js", Type: model.ResourceTypeScript,
	}, []byte("window.ok = true"))
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadJS(root, relative)
	if err != nil {
		t.Fatal(err)
	}
	if string(loaded) != "window.ok = true" {
		t.Fatalf("LoadJS() = %q", loaded)
	}

	for _, escape := range []string{"../outside.js", "..\\outside.js", "C:\\abs.js", "/abs.js"} {
		if _, err := LoadJS(root, escape); err == nil {
			t.Fatalf("LoadJS(%q) error = nil", escape)
		}
	}
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}
