package jsowl

import (
	"os"
	"path/filepath"
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
	if cfg.Output.DownloadJS {
		t.Fatal("Output.DownloadJS = true, want false")
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
		{"max resources", func(cfg *Config) { cfg.Limits.MaxResources = 0 }},
		{"max body size", func(cfg *Config) { cfg.Limits.MaxBodySize = 0 }},
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
