package jsowl

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func localTechnologies(result *Result) string {
	return strings.Join(result.Technologies, ",")
}

func TestAnalyzeLocationTechnologiesMergeAcrossFiles(t *testing.T) {
	root := t.TempDir()
	writeLocalScript(t, filepath.Join(root, "a.js"), `const lazy = import("./lazy.js");`)
	writeLocalScript(t, filepath.Join(root, "b.js"),
		`self.webpackChunkapp = self.webpackChunkapp || [];`)
	writeLocalScript(t, filepath.Join(root, "c.js"), `require.config({ paths: {} });`)

	config := DefaultConfig()
	config.Output.Directory = t.TempDir()
	result, err := AnalyzeLocation(context.Background(), config, root)
	if err != nil {
		t.Fatal(err)
	}
	if got := localTechnologies(result); got != "requirejs,spa,webpack" {
		t.Fatalf("technologies = %q", got)
	}
}

func TestAnalyzeLocationTechnologiesAreDeduplicated(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"a.js", "b.js", "c.js"} {
		writeLocalScript(t, filepath.Join(root, name),
			`self.webpackChunkapp = self.webpackChunkapp || [];`)
	}
	config := DefaultConfig()
	config.Output.Directory = t.TempDir()
	result, err := AnalyzeLocation(context.Background(), config, root)
	if err != nil {
		t.Fatal(err)
	}
	if got := localTechnologies(result); got != "webpack" {
		t.Fatalf("technologies = %q", got)
	}
}

func TestAnalyzeLocationTechnologiesNeedEvidence(t *testing.T) {
	root := t.TempDir()
	writeLocalScript(t, filepath.Join(root, "app.js"),
		`fetch("/users"); const value = { nested: true };`)
	config := DefaultConfig()
	config.Output.Directory = t.TempDir()
	result, err := AnalyzeLocation(context.Background(), config, root)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Technologies) != 0 {
		t.Fatalf("unevidenced technologies = %#v", result.Technologies)
	}
}

func TestAnalyzeLocationTechnologiesIncludeRecoveredSources(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "app.js")
	writeLocalScript(t, file, `fetch("/bundle");`+"\n//# sourceMappingURL=app.js.map")
	writeLocalSourceMap(t, filepath.Join(root, "app.js.map"),
		`{"version":3,"sources":["src/lazy.js"],`+
			`"sourcesContent":["const lazy = import(\"./lazy.js\");"]}`)

	config := DefaultConfig()
	config.Output.Directory = t.TempDir()
	result, err := AnalyzeLocation(context.Background(), config, file)
	if err != nil {
		t.Fatal(err)
	}
	if got := localTechnologies(result); got != "spa" {
		t.Fatalf("technologies = %q", got)
	}
}
