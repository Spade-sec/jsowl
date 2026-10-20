package jsowl

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/youmulijiang/jsowl/internal/collect"
	"github.com/youmulijiang/jsowl/internal/model"
)

func TestRepeatedScansKeepSeparateDirectoriesAndScripts(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/app.js" {
			w.Header().Set("Content-Type", "application/javascript")
			w.Write([]byte("window.example = 1;"))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<script src='/app.js'></script>"))
	}))
	defer server.Close()
	config := DefaultConfig()
	config.Mode = ModeDirect
	config.Output.Directory = t.TempDir()
	scanner, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	previous := ""
	for i := 0; i < 2; i++ {
		result, err := scanner.Scan(context.Background(), Target{URL: server.URL})
		if err != nil {
			t.Fatal(err)
		}
		if result.ReportDirectory == "" || result.ReportDirectory == previous {
			t.Fatalf("scan directory was reused: %s", result.ReportDirectory)
		}
		previous = result.ReportDirectory
		for _, resource := range result.Resources {
			if resource.LocalPath != "" {
				if _, err := os.Stat(filepath.Join(result.ReportDirectory, filepath.FromSlash(resource.LocalPath))); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	entries, err := os.ReadDir(config.Output.Directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("two scans created %d entries, want 2", len(entries))
	}
}

func TestAutoScanSharesDirectoryAcrossDirectAndBrowser(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<div id="app"></div><script src="/app.js"></script>`))
			return
		}
		w.Header().Set("Content-Type", "application/javascript")
		w.Write([]byte("window.example = 1;"))
	}))
	defer server.Close()
	config := DefaultConfig()
	config.Mode = ModeAuto
	config.Output.Directory = t.TempDir()
	scanner, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	scanner.browserFactory = func(model.BrowserConfig) (collect.BrowserCollector, error) {
		return &fakeBrowser{result: collect.BrowserResult{HTML: []byte("<html></html>"), Scripts: []string{server.URL + "/runtime.js"}}}, nil
	}
	result, err := scanner.Scan(context.Background(), Target{URL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if !result.BrowserStatus.Used {
		t.Fatal("browser phase was not exercised")
	}
	saved := 0
	for _, resource := range result.Resources {
		if resource.LocalPath != "" {
			saved++
			if _, err := os.Stat(filepath.Join(result.ReportDirectory, filepath.FromSlash(resource.LocalPath))); err != nil {
				t.Fatal(err)
			}
		}
	}
	if saved != 2 {
		t.Fatalf("saved %d scripts, want direct and browser scripts", saved)
	}
	entries, err := os.ReadDir(config.Output.Directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("one auto scan created %d directories", len(entries))
	}
}
