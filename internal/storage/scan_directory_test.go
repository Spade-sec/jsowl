package storage

import (
	"context"
	"path/filepath"
	"regexp"
	"testing"
	"time"
)

func TestScanDirectoryUsesIPTimestampAndUniqueSuffix(t *testing.T) {
	root := t.TempDir()
	started := time.Date(2026, 10, 20, 10, 30, 25, 0, time.UTC)
	seen := make(map[string]bool)
	for i := 0; i < 32; i++ {
		path, err := ScanDirectory(context.Background(), root, "https://192.0.2.10:8443/app?q=1", started)
		if err != nil {
			t.Fatal(err)
		}
		if filepath.Dir(path) != root || !regexp.MustCompile(`^192\.0\.2\.10_20261020-183025_[0-9a-f]{16}$`).MatchString(filepath.Base(path)) {
			t.Fatalf("unexpected scan directory: %s", path)
		}
		if seen[path] {
			t.Fatalf("duplicate scan directory: %s", path)
		}
		seen[path] = true
	}
}

func TestScanDirectoryHandlesIPv6AndUnresolvedDomain(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, item := range []struct{ target, prefix string }{
		{"https://[2001:db8::1]/", "2001_db8__1_"},
		{"https://unresolvable.invalid/", "unresolved-unresolvable.invalid_"},
	} {
		path, err := ScanDirectory(ctx, t.TempDir(), item.target, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if !regexp.MustCompile(`^` + regexp.QuoteMeta(item.prefix) + `\d{8}-\d{6}_[0-9a-f]{16}$`).MatchString(filepath.Base(path)) {
			t.Fatalf("unexpected directory: %s", path)
		}
	}
}
