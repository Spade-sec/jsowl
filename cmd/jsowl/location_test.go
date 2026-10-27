package main

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/youmulijiang/jsowl"
)

func TestRootLocationRunsLocalAnalysis(t *testing.T) {
	var stdout bytes.Buffer
	reportDirectory := t.TempDir()
	analyzed := ""
	analyzedBase := ""
	jsonPath := ""
	deps := testDependencies()
	deps.stdout = &stdout
	deps.defaultConfig = func() jsowl.Config {
		config := jsowl.DefaultConfig()
		config.Output.JSON = true
		config.Output.HTML = false
		return config
	}
	deps.writeJSON = func(path string, _ *jsowl.Result) error {
		jsonPath = path
		return nil
	}
	deps.analyzeLocation = func(
		_ context.Context, _ jsowl.Config, location, baseURL string,
	) (*jsowl.Result, error) {
		analyzed = location
		analyzedBase = baseURL
		return &jsowl.Result{
			Target:          location,
			ReportDirectory: reportDirectory,
			Mode:            jsowl.ModeLocal,
		}, nil
	}

	command := newRootCommand(deps)
	command.SetArgs([]string{"--location", "assets/app.js"})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	if analyzed != "assets/app.js" {
		t.Fatalf("analyzed = %q", analyzed)
	}
	if analyzedBase != "" {
		t.Fatalf("base URL = %q", analyzedBase)
	}
	if jsonPath != filepath.Join(reportDirectory, "report.json") {
		t.Fatalf("json path = %q", jsonPath)
	}
	if !strings.Contains(stdout.String(), "[local] assets/app.js:") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestRootLocationRejectsTargetFlags(t *testing.T) {
	cases := [][]string{
		{"--location", "app.js", "-u", "https://example.test"},
		{"--location", "app.js", "-l", "targets.txt"},
		{"--location", "app.js", "--login"},
	}
	for _, args := range cases {
		command := newRootCommand(testDependencies())
		command.SetArgs(args)
		if err := command.Execute(); err == nil {
			t.Fatalf("%v was accepted", args)
		}
	}
}

func TestRootLocationAcceptsFullBaseURL(t *testing.T) {
	analyzed := ""
	base := ""
	deps := testDependencies()
	deps.analyzeLocation = func(
		_ context.Context, _ jsowl.Config, location, baseURL string,
	) (*jsowl.Result, error) {
		analyzed, base = location, baseURL
		return &jsowl.Result{
			Target: location, ReportDirectory: t.TempDir(), Mode: jsowl.ModeLocal,
		}, nil
	}
	command := newRootCommand(deps)
	command.SetArgs([]string{
		"--location", "app.js", "--base-url", "https://api.example.test/v1",
		"-s",
	})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	if analyzed != "app.js" || base != "https://api.example.test/v1" {
		t.Fatalf("analyzed = %q, base = %q", analyzed, base)
	}
}

func TestRootLocationRejectsPathOnlyBaseURL(t *testing.T) {
	command := newRootCommand(testDependencies())
	command.SetArgs([]string{"--location", "app.js", "--base-url", "/api"})
	err := command.Execute()
	if err == nil {
		t.Fatal("path-only --base-url was accepted without -u")
	}
	if !strings.Contains(err.Error(), "path-only prefix has no host without -u") {
		t.Fatalf("error = %v", err)
	}
}
