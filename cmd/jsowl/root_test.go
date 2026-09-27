package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/youmulijiang/jsowl"
)

type fakeScanner struct {
	targets []jsowl.Target
	result  *jsowl.Result
	sink    chan<- jsowl.ProbeEvent
	// beforeBatch, when set, runs after SetProbeSink and before the batch
	// channel is produced, letting tests emit probe events.
	beforeBatch func()
}

func (f *fakeScanner) SetProbeSink(sink chan<- jsowl.ProbeEvent) {
	f.sink = sink
}

func (f *fakeScanner) ScanBatch(
	_ context.Context,
	targets []jsowl.Target,
) <-chan jsowl.BatchItem {
	if f.beforeBatch != nil {
		f.beforeBatch()
	}
	f.targets = append([]jsowl.Target(nil), targets...)
	output := make(chan jsowl.BatchItem, len(targets))
	for _, target := range targets {
		result := f.result
		if result == nil {
			result = &jsowl.Result{Target: target.URL}
		}
		output <- jsowl.BatchItem{
			Target: target,
			Result: result,
		}
	}
	close(output)
	return output
}

func TestRootFlagsOverrideConfigAndMergeTargets(t *testing.T) {
	list := filepath.Join(t.TempDir(), "targets.txt")
	if err := os.WriteFile(
		list,
		[]byte("# comment\n\nhttps://list.example\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	fake := &fakeScanner{}
	var captured jsowl.Config
	deps := testDependencies()
	deps.newScanner = func(config jsowl.Config) (scanService, error) {
		captured = config
		return fake, nil
	}

	command := newRootCommand(deps)
	command.SetArgs([]string{
		"-u", "https://cli.example",
		"-l", list,
		"-m", "direct",
		"-t", "32",
		"-p", "socks5://127.0.0.1:1080",
		"--base-url", "https://static.example/assets/",
		"-o", t.TempDir(),
		"-H", "Authorization: Bearer abc",
		"-H", "X-Test: one:two",
		"--scope", "api.example.net,.static.example",
	})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	if captured.Mode != jsowl.ModeDirect {
		t.Fatalf("mode = %q", captured.Mode)
	}
	if captured.Concurrency.ResourcesPerTarget != 32 {
		t.Fatalf("threads = %d", captured.Concurrency.ResourcesPerTarget)
	}
	if captured.Request.Proxy != "socks5://127.0.0.1:1080" {
		t.Fatalf("proxy = %q", captured.Request.Proxy)
	}
	if captured.Request.Headers["Authorization"] != "Bearer abc" ||
		captured.Request.Headers["X-Test"] != "one:two" {
		t.Fatalf("headers = %#v", captured.Request.Headers)
	}
	restricted := captured.Scope.RestrictDomains
	if len(restricted) != 2 || restricted[0] != "api.example.net" ||
		restricted[1] != ".static.example" {
		t.Fatalf("restrict domains = %#v", restricted)
	}
	if len(fake.targets) != 2 {
		t.Fatalf("targets = %#v", fake.targets)
	}
	for _, target := range fake.targets {
		if target.BaseURL != "https://static.example/assets/" {
			t.Errorf("target BaseURL = %q", target.BaseURL)
		}
	}
	if len(command.Commands()) != 0 {
		t.Fatalf("root command unexpectedly has subcommands: %#v", command.Commands())
	}
}

func TestRootPrintsHTTPXStyleLineForEveryCollectedResource(t *testing.T) {
	var output bytes.Buffer
	deps := testDependencies()
	deps.stdout = &output
	deps.newScanner = func(jsowl.Config) (scanService, error) {
		return &fakeScanner{result: &jsowl.Result{
			Target: "https://example.test/",
			Resources: []jsowl.Resource{
				{
					URL:         "https://example.test/",
					Type:        jsowl.ResourceTypeDocument,
					StatusCode:  201,
					ContentType: "text/html; charset=utf-8",
					Size:        321,
					Depth:       0,
				},
				{
					URL:         "https://example.test/app.js",
					Type:        jsowl.ResourceTypeScript,
					StatusCode:  200,
					ContentType: "application/javascript",
					Size:        654,
					Depth:       1,
				},
			},
		}}, nil
	}
	command := newRootCommand(deps)
	command.SetArgs([]string{"-u", "https://example.test"})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	want := "" +
		"https://example.test/ [321] [201] [text/html; charset=utf-8]\n" +
		"https://example.test/app.js [654] [200] [application/javascript]\n"
	if output.String() != want {
		t.Fatalf("stdout = %q, want %q", output.String(), want)
	}
}

func TestRootSilentSuppressesSuccessfulResultLines(t *testing.T) {
	var output bytes.Buffer
	deps := testDependencies()
	deps.stdout = &output
	command := newRootCommand(deps)
	command.SetArgs([]string{"-u", "https://example.test", "--silent"})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	if output.Len() != 0 {
		t.Fatalf("silent stdout = %q", output.String())
	}
}

func TestRootPrintsProbeEventsAsTheyComplete(t *testing.T) {
	var output bytes.Buffer
	deps := testDependencies()
	deps.stdout = &output
	scanner := &fakeScanner{result: &jsowl.Result{Target: "https://example.test/"}}
	scanner.beforeBatch = func() {
		scanner.sink <- jsowl.ProbeEvent{
			Target: "https://example.test/", URL: "https://example.test/api/items",
			Method: "POST", StatusCode: 200, Evidence: "runtime",
		}
	}
	deps.newScanner = func(jsowl.Config) (scanService, error) {
		return scanner, nil
	}

	command := newRootCommand(deps)
	command.SetArgs([]string{"-u", "https://example.test"})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "[200] POST https://example.test/api/items [runtime]") {
		t.Fatalf("probe line missing from stdout: %q", output.String())
	}
}

func TestRootSilentSuppressesProbeEventLines(t *testing.T) {
	var output bytes.Buffer
	deps := testDependencies()
	deps.stdout = &output
	scanner := &fakeScanner{result: &jsowl.Result{Target: "https://example.test/"}}
	scanner.beforeBatch = func() {
		if scanner.sink != nil {
			scanner.sink <- jsowl.ProbeEvent{
				Target: "https://example.test/", URL: "https://example.test/api/items",
				StatusCode: 200, Evidence: "runtime",
			}
		}
	}
	deps.newScanner = func(jsowl.Config) (scanService, error) {
		return scanner, nil
	}

	command := newRootCommand(deps)
	command.SetArgs([]string{"-u", "https://example.test", "--silent"})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "api/items") {
		t.Fatalf("silent stdout leaked probe line: %q", output.String())
	}
}

func TestRootPrintsBrowserDegradationToStderr(t *testing.T) {
	var stdout, stderr bytes.Buffer
	deps := testDependencies()
	deps.stdout = &stdout
	deps.stderr = &stderr
	deps.newScanner = func(jsowl.Config) (scanService, error) {
		return &fakeScanner{result: &jsowl.Result{
			Target: "https://example.test/",
			BrowserStatus: jsowl.BrowserStatus{
				Attempted: true, Degraded: true,
				Reason: "collect browser page: context deadline exceeded",
			},
		}}, nil
	}
	command := newRootCommand(deps)
	command.SetArgs([]string{"-u", "https://example.test"})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr.String(), "browser degraded") {
		t.Fatalf("stderr missing degradation notice: %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), "context deadline exceeded") {
		t.Fatalf("stderr missing degradation reason: %q", stderr.String())
	}
}

func TestRootRejectsInvalidHeaderAndMissingTargets(t *testing.T) {
	for name, args := range map[string][]string{
		"header":  {"-u", "https://example.test", "-H", "broken"},
		"targets": nil,
	} {
		t.Run(name, func(t *testing.T) {
			command := newRootCommand(testDependencies())
			command.SetArgs(args)
			if err := command.Execute(); err == nil {
				t.Fatal("Execute() error = nil")
			}
		})
	}
}

func TestRootCheckRunsWithoutTargetsAndPropagatesFailure(t *testing.T) {
	deps := testDependencies()
	var called bool
	deps.check = func(context.Context, jsowl.BrowserConfig) jsowl.BrowserCheckReport {
		called = true
		return jsowl.BrowserCheckReport{
			Passed: false,
			Checks: []jsowl.BrowserCheck{{
				Name: "browser_path", Message: "browser missing",
			}},
		}
	}
	command := newRootCommand(deps)
	command.SetArgs([]string{"--check"})
	err := command.Execute()
	if !called {
		t.Fatal("browser check was not called")
	}
	if err == nil || !strings.Contains(err.Error(), "browser") {
		t.Fatalf("Execute() error = %v", err)
	}
}

func TestRootVersionRunsWithoutTargets(t *testing.T) {
	deps := testDependencies()
	var output bytes.Buffer
	deps.stdout = &output
	command := newRootCommand(deps)
	command.SetArgs([]string{"-v"})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), version) {
		t.Fatalf("version output = %q", output.String())
	}
}

func TestRootExplicitMissingConfigFails(t *testing.T) {
	deps := testDependencies()
	deps.loadConfig = jsowl.LoadConfig
	command := newRootCommand(deps)
	command.SetArgs([]string{
		"-c", filepath.Join(t.TempDir(), "missing.yml"),
		"-u", "https://example.test",
	})
	if err := command.Execute(); err == nil {
		t.Fatal("Execute() error = nil for explicit missing config")
	}
}

func TestParseHeader(t *testing.T) {
	name, value, err := parseHeader(" Authorization : Bearer a:b ")
	if err != nil {
		t.Fatal(err)
	}
	if name != "Authorization" || value != "Bearer a:b" {
		t.Fatalf("parseHeader() = %q, %q", name, value)
	}
	if _, _, err := parseHeader("Bad Header: value"); err == nil {
		t.Fatal("parseHeader() accepted invalid field name")
	}
}

func TestParseScopeDomains(t *testing.T) {
	got := parseScopeDomains([]string{
		"a.example.com,b.example.com",
		" c.example.com , ,d.example.com",
	})
	want := []string{"a.example.com", "b.example.com", "c.example.com", "d.example.com"}
	if len(got) != len(want) {
		t.Fatalf("parseScopeDomains() = %#v", got)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("parseScopeDomains() = %#v, want %#v", got, want)
		}
	}
}

func TestTargetReportDirectorySeparatesSameHostTargets(t *testing.T) {
	root := t.TempDir()
	first, err := targetReportDirectory(root, "https://example.test/app-a")
	if err != nil {
		t.Fatal(err)
	}
	second, err := targetReportDirectory(root, "https://example.test/app-b")
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatalf("report directories collide at %q", first)
	}
	base, err := targetReportDirectory(root, "https://example.test/")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(base) != "example.test" {
		t.Fatalf("root report directory = %q", base)
	}
}

func testDependencies() dependencies {
	return dependencies{
		stdout: &bytes.Buffer{},
		stderr: &bytes.Buffer{},
		defaultConfig: func() jsowl.Config {
			config := jsowl.DefaultConfig()
			config.Output.JSON = false
			config.Output.HTML = false
			return config
		},
		loadConfig: func(string) (jsowl.Config, error) {
			return jsowl.Config{}, errors.New("unexpected config load")
		},
		// Most tests exercise no user-level config at all: this stub
		// simulates an environment without a home directory, and the
		// user-config tests install their own fake home instead.
		userHomeDir: func() (string, error) {
			return "", errors.New("no user home in tests")
		},
		newScanner: func(jsowl.Config) (scanService, error) {
			return &fakeScanner{}, nil
		},
		writeJSON: func(string, *jsowl.Result) error { return nil },
		writeHTML: func(string, *jsowl.Result) error { return nil },
		check: func(context.Context, jsowl.BrowserConfig) jsowl.BrowserCheckReport {
			return jsowl.BrowserCheckReport{Passed: true}
		},
		ensureOutput: func(string) error { return nil },
	}
}
