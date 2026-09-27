package main

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/youmulijiang/jsowl"
)

func TestEnsureUserConfigFileCreatesTemplateOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), userConfigDirName, userConfigFileName)

	created, err := ensureUserConfigFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Fatal("first ensureUserConfigFile() created = false")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "用户级配置文件") {
		t.Fatalf("template header missing: %q", string(data))
	}
	// A fully commented template must stay inert when loaded.
	defaults := jsowl.DefaultConfig()
	loaded, err := jsowl.LoadConfigOnto(defaults, path)
	if err != nil {
		t.Fatalf("load generated template: %v", err)
	}
	if !reflect.DeepEqual(loaded, jsowl.DefaultConfig()) {
		t.Fatalf("generated template changed defaults: %#v", loaded)
	}

	created, err = ensureUserConfigFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if created {
		t.Fatal("second ensureUserConfigFile() created = true")
	}
}

func TestLoadConfigurationCreatesUserConfigOnFirstRun(t *testing.T) {
	home := t.TempDir()
	var stderr bytes.Buffer
	deps := testDependencies()
	deps.stderr = &stderr
	deps.userHomeDir = func() (string, error) { return home, nil }

	deps = completeDependencies(deps)
	config, err := loadConfiguration(deps, "")
	if err != nil {
		t.Fatal(err)
	}
	userPath := userConfigPath(home)
	if _, err := os.Stat(userPath); err != nil {
		t.Fatalf("user config not created: %v", err)
	}
	if !strings.Contains(stderr.String(), userPath) {
		t.Fatalf("creation notice missing from stderr: %q", stderr.String())
	}
	// The fresh template must not alter the defaults — except Rules, which
	// is now intentionally seeded from ~/.jsowl/rules.yaml.
	defaults := deps.defaultConfig()
	config.Rules = defaults.Rules
	if !reflect.DeepEqual(config, defaults) {
		t.Fatalf("fresh user config changed defaults: %#v", config)
	}

	stderr.Reset()
	if _, err := loadConfiguration(deps, ""); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr.String(), "user config: "+userPath) {
		t.Fatalf("location hint missing from stderr: %q", stderr.String())
	}
	if strings.Contains(stderr.String(), "created user config") {
		t.Fatalf("creation notice repeated: %q", stderr.String())
	}
}

func TestLoadConfigurationLayersUserAndProjectConfig(t *testing.T) {
	home := t.TempDir()
	userPath := userConfigPath(home)
	if err := os.MkdirAll(filepath.Dir(userPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(userPath, []byte(
		"mode: direct\nrequest:\n  timeout: 7s\n  headers:\n    X-Global: user\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	project := t.TempDir()
	if err := os.WriteFile(filepath.Join(project, "config.yml"), []byte(
		"mode: browser\nrequest:\n  headers:\n    X-Local: project\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	t.Chdir(project)

	deps := testDependencies()
	deps.defaultConfig = jsowl.DefaultConfig
	deps.userHomeDir = func() (string, error) { return home, nil }
	deps = completeDependencies(deps)

	config, err := loadConfiguration(deps, "")
	if err != nil {
		t.Fatal(err)
	}
	if config.Mode != jsowl.ModeBrowser {
		t.Fatalf("Mode = %q, want project layer to win with %q", config.Mode, jsowl.ModeBrowser)
	}
	if config.Request.Timeout != 7*time.Second {
		t.Fatalf("Request.Timeout = %s, want user layer value 7s", config.Request.Timeout)
	}
	if config.Request.Headers["X-Global"] != "user" ||
		config.Request.Headers["X-Local"] != "project" {
		t.Fatalf("Request.Headers = %#v, want merged layers", config.Request.Headers)
	}
}

func TestLoadConfigurationInvalidUserConfigFails(t *testing.T) {
	home := t.TempDir()
	userPath := userConfigPath(home)
	if err := os.MkdirAll(filepath.Dir(userPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(userPath, []byte("browser:\n  mystery: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	deps := completeDependencies(testDependencies())
	deps.userHomeDir = func() (string, error) { return home, nil }
	if _, err := loadConfiguration(deps, ""); err == nil {
		t.Fatal("loadConfiguration() error = nil for invalid user config")
	}
}

func TestLoadConfigurationSeedsUserRulesOnce(t *testing.T) {
	home := t.TempDir()
	deps := testDependencies()
	deps.userHomeDir = func() (string, error) { return home, nil }
	deps = completeDependencies(deps)

	config, err := loadConfiguration(deps, "")
	if err != nil {
		t.Fatal(err)
	}
	rulesPath := userRulesPath(home)
	data, err := os.ReadFile(rulesPath)
	if err != nil {
		t.Fatalf("user rules not seeded: %v", err)
	}
	if !strings.Contains(string(data), "id: secret.jwt") {
		t.Fatalf("seed file missing builtin rules: %s", data[:200])
	}
	if len(config.Rules.Custom) == 0 {
		t.Fatalf("config should load the seeded rules: %#v", config.Rules)
	}

	// Edits survive: a second run must not overwrite the file.
	if err := os.WriteFile(rulesPath,
		[]byte("custom:\n  - id: secret.jwt\n    name: edited\n    category: sensitive\n    severity: high\n    pattern: 'x'\n    group: 0\n    enabled: false\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	config, err = loadConfiguration(deps, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(config.Rules.Custom) != 1 || config.Rules.Custom[0].Name != "edited" {
		t.Fatalf("user edits were clobbered: %#v", config.Rules.Custom)
	}
}

func TestLoadConfigurationExplicitRulesFileWins(t *testing.T) {
	home := t.TempDir()
	project := t.TempDir()
	if err := os.WriteFile(filepath.Join(project, "config.yml"),
		[]byte("rules_file: ./my-rules.yml"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "my-rules.yml"),
		[]byte("custom:\n  - id: custom.only\n    name: only\n    category: sensitive\n    severity: low\n    pattern: 'y'\n    group: 0\n    enabled: true\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	t.Chdir(project)

	deps := testDependencies()
	deps.userHomeDir = func() (string, error) { return home, nil }
	deps = completeDependencies(deps)

	config, err := loadConfiguration(deps, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(config.Rules.Custom) != 1 || config.Rules.Custom[0].ID != "custom.only" {
		t.Fatalf("explicit rules_file must win: %#v", config.Rules.Custom)
	}
	if _, err := os.Stat(userRulesPath(home)); !os.IsNotExist(err) {
		t.Fatalf("rules.yaml should not be seeded when rules_file is set: %v", err)
	}
}
