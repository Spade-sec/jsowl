package tools

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestSingleTargetSharesOneTemporaryOutputRoot(t *testing.T) {
	temporary := t.TempDir()
	t.Setenv("TMP", temporary)
	t.Setenv("TEMP", temporary)
	t.Setenv("TMPDIR", temporary)
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
	store := NewStore("")
	// Concurrent callers must all obtain the same root, without creating extras.
	roots := make(chan string, 16)
	var workers sync.WaitGroup
	for i := 0; i < 16; i++ {
		workers.Add(1)
		go func() { defer workers.Done(); roots <- store.reportRoot() }()
	}
	workers.Wait()
	close(roots)
	root := store.reportRoot()
	for got := range roots {
		if got != root {
			t.Fatalf("output roots differ: %q and %q", root, got)
		}
	}
	target := server.URL + "/app?q=1"
	output, err := store.Scan(context.Background(), ScanInput{URL: target, Mode: "direct", WriteReports: true})
	if err != nil {
		t.Fatal(err)
	}
	want := output.ReportDir
	if filepath.Dir(want) != root || !strings.HasPrefix(filepath.Base(want), "127.0.0.1_") {
		t.Fatalf("report directory = %q, expected an IP-named scan directory under %q", want, root)
	}
	for _, name := range []string{"report.json", "js"} {
		if _, err := os.Stat(filepath.Join(want, name)); err != nil {
			t.Fatalf("%s missing from target directory: %v", name, err)
		}
	}
	entries, err := os.ReadDir(temporary)
	if err != nil {
		t.Fatal(err)
	}
	var rootCount int
	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), "jsowl-tools-") {
			rootCount++
		}
	}
	if rootCount != 1 {
		t.Fatalf("one target created %d temporary output roots, want 1", rootCount)
	}
	targets, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 || targets[0].Name() != filepath.Base(want) {
		t.Fatalf("unexpected target directories: %v", targets)
	}
}
