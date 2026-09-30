package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/youmulijiang/jsowl"
)

// fakeLoginScanner wraps fakeScanner with the login capability and records
// the session lifecycle calls runScans makes.
type fakeLoginScanner struct {
	fakeScanner
	startedWith string
	currentURL  string
	closed      bool
}

func (f *fakeLoginScanner) StartLoginSession(
	_ context.Context, targetURL string, _ func(context.Context) error,
) error {
	f.startedWith = targetURL
	return nil
}

func (f *fakeLoginScanner) LoginSessionURL() (string, error) {
	return f.currentURL, nil
}

func (f *fakeLoginScanner) CloseLoginSession() {
	f.closed = true
}

func TestLoginFlagForcesHeadedBrowserModeAndSerialTargets(t *testing.T) {
	fake := &fakeLoginScanner{}
	var captured jsowl.Config
	deps := testDependencies()
	deps.stdin = strings.NewReader("\n")
	deps.newScanner = func(config jsowl.Config) (scanService, error) {
		captured = config
		return fake, nil
	}

	command := newRootCommand(deps)
	command.SetArgs([]string{"-u", "https://login.example", "--login"})
	if err := command.Execute(); err != nil {
		t.Fatalf("run with --login: %v", err)
	}
	if captured.Mode != jsowl.ModeBrowser {
		t.Fatalf("mode = %q, want browser", captured.Mode)
	}
	if captured.Browser.Headless {
		t.Fatal("headless must be forced off for --login")
	}
	if captured.Concurrency.Targets != 1 {
		t.Fatalf("target concurrency = %d, want 1", captured.Concurrency.Targets)
	}
	if fake.startedWith != "https://login.example" {
		t.Fatalf("login opened %q, want the first target", fake.startedWith)
	}
	if !fake.closed {
		t.Fatal("login session must be closed after the batch")
	}
}

func TestLoginWithoutTargetsAdoptsCurrentPage(t *testing.T) {
	fake := &fakeLoginScanner{currentURL: "https://app.example/dashboard"}
	deps := testDependencies()
	deps.stdin = strings.NewReader("\n")
	deps.newScanner = func(jsowl.Config) (scanService, error) {
		return fake, nil
	}

	command := newRootCommand(deps)
	command.SetArgs([]string{"--login"})
	if err := command.Execute(); err != nil {
		t.Fatalf("run --login without a target: %v", err)
	}
	if fake.startedWith != "" {
		t.Fatalf("login browser opened %q, want a blank tab", fake.startedWith)
	}
	if len(fake.targets) != 1 || fake.targets[0].URL != "https://app.example/dashboard" {
		t.Fatalf("scanned targets = %#v, want the adopted page", fake.targets)
	}
	if !fake.closed {
		t.Fatal("login session must be closed after the batch")
	}
}

func TestLoginWithoutTargetsOnBlankPageFails(t *testing.T) {
	fake := &fakeLoginScanner{currentURL: "about:blank"}
	deps := testDependencies()
	deps.stdin = strings.NewReader("\n")
	deps.newScanner = func(jsowl.Config) (scanService, error) {
		return fake, nil
	}

	command := newRootCommand(deps)
	command.SetArgs([]string{"--login"})
	err := command.Execute()
	if err == nil || !strings.Contains(err.Error(), "not an http(s) page") {
		t.Fatalf("expected blank-page error, got %v", err)
	}
}

func TestLoginWithoutScannerSupportFails(t *testing.T) {
	deps := testDependencies()
	deps.stdin = strings.NewReader("\n")
	deps.newScanner = func(config jsowl.Config) (scanService, error) {
		return &fakeScanner{}, nil
	}
	stderr := &bytes.Buffer{}
	deps.stderr = stderr

	command := newRootCommand(deps)
	command.SetArgs([]string{"-u", "https://login.example", "--login"})
	err := command.Execute()
	if err == nil || !strings.Contains(err.Error(), "--login is not supported") {
		t.Fatalf("expected unsupported error, got %v", err)
	}
}
