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
}

func (f *fakeScanner) ScanBatch(
	_ context.Context,
	targets []jsowl.Target,
) <-chan jsowl.BatchItem {
	f.targets = append([]jsowl.Target(nil), targets...)
	output := make(chan jsowl.BatchItem, len(targets))
	for _, target := range targets {
		output <- jsowl.BatchItem{
			Target: target,
			Result: &jsowl.Result{Target: target.URL},
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
		"-o", t.TempDir(),
		"-H", "Authorization: Bearer abc",
		"-H", "X-Test: one:two",
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
	if captured.Request.Headers["Authorization"] != "Bearer abc" ||
		captured.Request.Headers["X-Test"] != "one:two" {
		t.Fatalf("headers = %#v", captured.Request.Headers)
	}
	if len(fake.targets) != 2 {
		t.Fatalf("targets = %#v", fake.targets)
	}
	if len(command.Commands()) != 0 {
		t.Fatalf("root command unexpectedly has subcommands: %#v", command.Commands())
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
