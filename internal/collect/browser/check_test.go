package browser

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-rod/rod/lib/launcher"
	"github.com/youmulijiang/jsowl/internal/model"
)

func TestCheckInstalledBrowser(t *testing.T) {
	bin, found := launcher.LookPath()
	if !found {
		t.Skip("local Chromium-compatible browser is not installed")
	}
	report := Check(context.Background(), model.BrowserConfig{
		Path: bin, Headless: true, NoSandbox: true, Timeout: 15 * time.Second,
	})
	if !report.Passed {
		t.Fatalf("Check() report = %#v", report)
	}
}

func TestCheckRecognizesTransientBrowserFailure(t *testing.T) {
	report := CheckReport{Checks: []CheckItem{{
		Name:    "cdp",
		Message: "read tcp: use of closed network connection",
	}}}
	if !hasTransientFailure(report) {
		t.Fatal("closed CDP connection should be treated as transient")
	}
	if hasTransientFailure(CheckReport{Checks: []CheckItem{{
		Name:    "javascript",
		Message: "unexpected JavaScript result",
	}}}) {
		t.Fatal("deterministic JavaScript failure must not be retried")
	}
}

func TestCheckReportsMissingConfiguredBrowserWithoutDownloading(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "definitely-missing-browser.exe")

	report := Check(context.Background(), model.BrowserConfig{Path: missing})

	if report.Passed {
		t.Fatal("Check() passed for a missing configured browser")
	}
	if report.Path != missing {
		t.Fatalf("Check() path = %q, want %q", report.Path, missing)
	}
	if len(report.Checks) != 1 {
		t.Fatalf("Check() returned %d checks, want 1", len(report.Checks))
	}
	if report.Checks[0].Name != "browser_path" || report.Checks[0].Passed {
		t.Fatalf("Check() first check = %#v, want failed browser_path", report.Checks[0])
	}
}
