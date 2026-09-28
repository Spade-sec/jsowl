package jsowl

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestDefaultConfigProvidesBoundedScanDefaults(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Mode != ModeAuto {
		t.Fatalf("Mode = %q, want %q", cfg.Mode, ModeAuto)
	}
	if cfg.Browser.Wait != 3*time.Second {
		t.Fatalf("Browser.Wait = %s, want 3s", cfg.Browser.Wait)
	}
	if cfg.Browser.Idle != 800*time.Millisecond {
		t.Fatalf("Browser.Idle = %s, want 800ms", cfg.Browser.Idle)
	}
	if cfg.Concurrency.ResourcesPerTarget != 16 {
		t.Fatalf("ResourcesPerTarget = %d, want 16", cfg.Concurrency.ResourcesPerTarget)
	}
	if !cfg.Output.DownloadJS {
		t.Fatal("Output.DownloadJS = false, want true")
	}
	for _, suffix := range []string{
		".png", ".woff2", ".mp4", ".zip", ".css", ".svg",
	} {
		if !slices.Contains(cfg.Scope.SuffixBlacklist, suffix) {
			t.Errorf("default suffix blacklist does not contain %q", suffix)
		}
	}
	for _, suffix := range []string{".js", ".json"} {
		if slices.Contains(cfg.Scope.SuffixBlacklist, suffix) {
			t.Errorf("default suffix blacklist unexpectedly contains %q", suffix)
		}
	}
}

func TestLoadConfigMergesDefaultsAndRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yml")
	data := []byte("mode: direct\nbrowser:\n  wait: 5s\n")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != ModeDirect {
		t.Fatalf("Mode = %q, want %q", cfg.Mode, ModeDirect)
	}
	if cfg.Browser.Wait != 5*time.Second {
		t.Fatalf("Browser.Wait = %s, want 5s", cfg.Browser.Wait)
	}
	if cfg.Concurrency.ResourcesPerTarget != 16 {
		t.Fatalf("default ResourcesPerTarget lost: %d", cfg.Concurrency.ResourcesPerTarget)
	}

	badPath := filepath.Join(t.TempDir(), "bad.yml")
	if err := os.WriteFile(badPath, []byte("browser:\n  mystery: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = LoadConfig(badPath)
	if err == nil || !strings.Contains(err.Error(), "field mystery not found") {
		t.Fatalf("LoadConfig unknown field error = %v", err)
	}
}

func TestLoadConfigParsesBodySize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(path, []byte("limits:\n  max_body_size: 2MiB\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Limits.MaxBodySize != 2*1024*1024 {
		t.Fatalf("MaxBodySize = %d, want %d", cfg.Limits.MaxBodySize, 2*1024*1024)
	}
}

func TestLoadConfigLoadsRulesFromRelativeFile(t *testing.T) {
	directory := t.TempDir()
	rulesPath := filepath.Join(directory, "rules.yml")
	rules := []byte(`disabled:
  - url.generic
custom:
  - id: custom.fixture
    name: Fixture secret
    category: sensitive
    severity: high
    pattern: 'fixture_([a-z]+)'
    group: 1
    description: test fixture
    enabled: true
`)
	if err := os.WriteFile(rulesPath, rules, 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(directory, "config.yml")
	if err := os.WriteFile(configPath, []byte("rules_file: rules.yml\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RulesFile != "rules.yml" {
		t.Fatalf("RulesFile = %q, want rules.yml", cfg.RulesFile)
	}
	if !slices.Equal(cfg.Rules.Disabled, []string{"url.generic"}) {
		t.Fatalf("Rules.Disabled = %#v", cfg.Rules.Disabled)
	}
	if len(cfg.Rules.Custom) != 1 || cfg.Rules.Custom[0].ID != "custom.fixture" {
		t.Fatalf("Rules.Custom = %#v", cfg.Rules.Custom)
	}
}

func TestLoadConfigRejectsInlineRules(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(path, []byte("rules:\n  disabled: []\n  custom: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := LoadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "field rules not found") {
		t.Fatalf("LoadConfig inline rules error = %v", err)
	}
}

func TestExampleConfigurationLoadsAndCompiles(t *testing.T) {
	for _, path := range []string{
		filepath.Join("config", "config.yml"),
		filepath.Join("config", "config.example.yml"),
	} {
		t.Run(path, func(t *testing.T) {
			cfg, err := LoadConfig(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := New(cfg); err != nil {
				t.Fatalf("compile configuration: %v", err)
			}
		})
	}
}

func TestLoadConfigOntoLayersFilesOverBase(t *testing.T) {
	base := DefaultConfig()
	base.Request.Headers["X-Base"] = "base"

	path := filepath.Join(t.TempDir(), "config.yml")
	data := []byte(
		"mode: direct\nbrowser:\n  wait: 5s\n" +
			"request:\n  headers:\n    X-File: file\n",
	)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfigOnto(base, path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != ModeDirect {
		t.Fatalf("Mode = %q, want %q", cfg.Mode, ModeDirect)
	}
	if cfg.Browser.Wait != 5*time.Second {
		t.Fatalf("Browser.Wait = %s, want 5s", cfg.Browser.Wait)
	}
	if cfg.Concurrency.ResourcesPerTarget != 16 {
		t.Fatalf("default ResourcesPerTarget lost: %d", cfg.Concurrency.ResourcesPerTarget)
	}
	if cfg.Request.Headers["X-Base"] != "base" ||
		cfg.Request.Headers["X-File"] != "file" {
		t.Fatalf("Request.Headers = %#v, want merged base and file", cfg.Request.Headers)
	}
	// The base itself must stay untouched by the higher layer.
	if len(base.Request.Headers) != 1 {
		t.Fatalf("base headers mutated: %#v", base.Request.Headers)
	}
}

func TestLoadConfigOntoKeepsBaseUntouchedByCommentOnlyFile(t *testing.T) {
	base := DefaultConfig()
	base.Mode = ModeBrowser
	base.Browser.Wait = 9 * time.Second

	path := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(
		path, []byte("# comment only\n# mode: direct\n"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfigOnto(base, path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != ModeBrowser || cfg.Browser.Wait != 9*time.Second {
		t.Fatalf(
			"comment-only file altered base: mode=%q wait=%s",
			cfg.Mode, cfg.Browser.Wait,
		)
	}
}

func TestLoadConfigOntoRulesFollowTheFileThatSetsRulesFile(t *testing.T) {
	writeRules := func(directory, marker string) error {
		rules := []byte(
			"custom:\n" +
				"  - id: " + marker + "\n" +
				"    name: Fixture\n" +
				"    category: sensitive\n" +
				"    severity: high\n" +
				"    pattern: 'fixture_([a-z]+)'\n" +
				"    group: 1\n" +
				"    description: fixture\n" +
				"    enabled: true\n",
		)
		return os.WriteFile(filepath.Join(directory, "rules.yml"), rules, 0o600)
	}

	first := t.TempDir()
	if err := writeRules(first, "fixture.first"); err != nil {
		t.Fatal(err)
	}
	firstConfig := filepath.Join(first, "config.yml")
	if err := os.WriteFile(
		firstConfig, []byte("rules_file: rules.yml\n"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	base, err := LoadConfig(firstConfig)
	if err != nil {
		t.Fatal(err)
	}
	if len(base.Rules.Custom) != 1 || base.Rules.Custom[0].ID != "fixture.first" {
		t.Fatalf("base rules = %#v", base.Rules.Custom)
	}

	// A second file without rules_file keeps the inherited rules.
	second := t.TempDir()
	secondConfig := filepath.Join(second, "config.yml")
	if err := os.WriteFile(secondConfig, []byte("mode: direct\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	merged, err := LoadConfigOnto(base, secondConfig)
	if err != nil {
		t.Fatal(err)
	}
	if len(merged.Rules.Custom) != 1 || merged.Rules.Custom[0].ID != "fixture.first" {
		t.Fatalf("rules lost without rules_file: %#v", merged.Rules.Custom)
	}
	if merged.RulesFile != "rules.yml" {
		t.Fatalf("RulesFile = %q, want inherited rules.yml", merged.RulesFile)
	}

	// A file that sets rules_file reloads rules relative to its own directory.
	third := t.TempDir()
	if err := writeRules(third, "fixture.third"); err != nil {
		t.Fatal(err)
	}
	thirdConfig := filepath.Join(third, "config.yml")
	if err := os.WriteFile(
		thirdConfig, []byte("rules_file: rules.yml\n"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	replaced, err := LoadConfigOnto(base, thirdConfig)
	if err != nil {
		t.Fatal(err)
	}
	if len(replaced.Rules.Custom) != 1 ||
		replaced.Rules.Custom[0].ID != "fixture.third" {
		t.Fatalf("rules not reloaded from overriding file: %#v", replaced.Rules.Custom)
	}

	// An explicit empty rules_file clears inherited rules.
	clearedConfig := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(clearedConfig, []byte("rules_file: \"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cleared, err := LoadConfigOnto(base, clearedConfig)
	if err != nil {
		t.Fatal(err)
	}
	if cleared.RulesFile != "" || len(cleared.Rules.Custom) != 0 {
		t.Fatalf("empty rules_file did not clear rules: %#v", cleared.Rules)
	}
}

func TestConfigValidateRejectsUnsafeBounds(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{"mode", func(cfg *Config) { cfg.Mode = "invalid" }},
		{"request timeout", func(cfg *Config) { cfg.Request.Timeout = 0 }},
		{"browser wait", func(cfg *Config) { cfg.Browser.Wait = -time.Second }},
		{"target concurrency", func(cfg *Config) { cfg.Concurrency.Targets = 0 }},
		{"resource concurrency", func(cfg *Config) { cfg.Concurrency.ResourcesPerTarget = 0 }},
		{"max depth", func(cfg *Config) { cfg.Limits.MaxDepth = -1 }},
		{"max resources", func(cfg *Config) { cfg.Limits.MaxResources = -1 }},
		{"max body size", func(cfg *Config) { cfg.Limits.MaxBodySize = -1 }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := DefaultConfig()
			test.mutate(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("Validate() error = nil")
			}
		})
	}
}

func TestConfigValidateRejectsMalformedProxyAndAllowlist(t *testing.T) {
	for name, mutate := range map[string]func(*Config){
		"proxy scheme": func(config *Config) {
			config.Request.Proxy = "file:///tmp/proxy"
		},
		"proxy host": func(config *Config) {
			config.Request.Proxy = "http://"
		},
		"allowlist wildcard": func(config *Config) {
			config.Scope.AllowDomains = []string{"*.example.test"}
		},
		"allowlist label": func(config *Config) {
			config.Scope.AllowDomains = []string{"bad label.example"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			config := DefaultConfig()
			mutate(&config)
			if err := config.Validate(); err == nil {
				t.Fatal("Validate() error = nil")
			}
		})
	}
}
