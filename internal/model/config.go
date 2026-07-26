package model

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// DefaultConfig returns the canonical internal defaults used by the library and CLI.
func DefaultConfig() Config {
	return Config{
		Mode: ModeAuto,
		Request: RequestConfig{
			Timeout:       15 * time.Second,
			TargetTimeout: 5 * time.Minute,
			Retry:         1,
			Headers:       make(map[string]string),
			Cookies:       make(map[string]string),
		},
		Browser: BrowserConfig{
			Wait:     3 * time.Second,
			Idle:     800 * time.Millisecond,
			Timeout:  45 * time.Second,
			Headless: true,
		},
		Concurrency: ConcurrencyConfig{
			Targets:            4,
			ResourcesPerTarget: 16,
		},
		Limits: LimitsConfig{
			MaxDepth:     5,
			MaxResources: 2000,
			MaxBodySize:  10 * 1024 * 1024,
		},
		Scope: ScopeConfig{
			FetchExternalScripts: true,
		},
		Output: OutputConfig{
			Directory:   "./jsowl-report",
			JSON:        true,
			HTML:        true,
			JSDirectory: "js",
		},
	}
}

// LoadConfig decodes a strict YAML configuration while preserving unspecified defaults.
func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}

	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	if err := normalizeBodySize(&document); err != nil {
		return Config{}, err
	}
	var normalized bytes.Buffer
	if err := yaml.NewEncoder(&normalized).Encode(&document); err != nil {
		return Config{}, fmt.Errorf("normalize config: %w", err)
	}

	cfg := DefaultConfig()
	decoder := yaml.NewDecoder(&normalized)
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate rejects configuration values that could disable scan safety bounds.
func (c Config) Validate() error {
	if c.Mode != ModeAuto && c.Mode != ModeDirect && c.Mode != ModeBrowser {
		return fmt.Errorf("invalid mode %q", c.Mode)
	}
	if c.Request.Timeout <= 0 || c.Request.TargetTimeout <= 0 {
		return errors.New("request timeouts must be positive")
	}
	if c.Browser.Wait < 0 || c.Browser.Idle < 0 || c.Browser.Timeout <= 0 {
		return errors.New("browser durations are invalid")
	}
	if c.Concurrency.Targets <= 0 || c.Concurrency.ResourcesPerTarget <= 0 {
		return errors.New("concurrency values must be positive")
	}
	if c.Limits.MaxDepth < 0 || c.Limits.MaxResources <= 0 || c.Limits.MaxBodySize <= 0 {
		return errors.New("resource limits are invalid")
	}
	if err := validateProxy(c.Request.Proxy); err != nil {
		return err
	}
	for _, domain := range c.Scope.AllowDomains {
		if err := validateAllowDomain(domain); err != nil {
			return err
		}
	}
	return nil
}

func validateProxy(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	proxyURL, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid request proxy: %w", err)
	}
	switch strings.ToLower(proxyURL.Scheme) {
	case "http", "https", "socks5":
	default:
		return fmt.Errorf("invalid request proxy scheme %q", proxyURL.Scheme)
	}
	if proxyURL.Hostname() == "" {
		return errors.New("request proxy host is empty")
	}
	return nil
}

func validateAllowDomain(raw string) error {
	domain := strings.ToLower(strings.TrimSpace(raw))
	domain = strings.TrimSuffix(domain, ".")
	if strings.HasPrefix(domain, ".") {
		domain = strings.TrimPrefix(domain, ".")
	}
	if domain == "" || len(domain) > 253 {
		return fmt.Errorf("invalid allowlist domain %q", raw)
	}
	if net.ParseIP(domain) != nil {
		return nil
	}
	for _, label := range strings.Split(domain, ".") {
		if label == "" || len(label) > 63 ||
			label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("invalid allowlist domain %q", raw)
		}
		for _, character := range label {
			if character >= 'a' && character <= 'z' ||
				character >= '0' && character <= '9' ||
				character == '-' {
				continue
			}
			return fmt.Errorf("invalid allowlist domain %q", raw)
		}
	}
	return nil
}

func normalizeBodySize(document *yaml.Node) error {
	if document.Kind != yaml.DocumentNode || len(document.Content) != 1 {
		return nil
	}
	root := document.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value != "limits" {
			continue
		}
		limits := root.Content[i+1]
		if limits.Kind != yaml.MappingNode {
			return nil
		}
		for j := 0; j+1 < len(limits.Content); j += 2 {
			if limits.Content[j].Value != "max_body_size" {
				continue
			}
			value := limits.Content[j+1]
			if value.Tag != "!!str" {
				return nil
			}
			size, err := parseByteSize(value.Value)
			if err != nil {
				return fmt.Errorf("limits.max_body_size: %w", err)
			}
			value.Tag = "!!int"
			value.Value = strconv.FormatInt(size, 10)
			return nil
		}
	}
	return nil
}

func parseByteSize(value string) (int64, error) {
	trimmed := strings.TrimSpace(value)
	for _, unit := range []struct {
		suffix string
		bytes  int64
	}{
		{"GiB", 1024 * 1024 * 1024},
		{"MiB", 1024 * 1024},
		{"KiB", 1024},
		{"B", 1},
	} {
		if strings.HasSuffix(trimmed, unit.suffix) {
			number := strings.TrimSpace(strings.TrimSuffix(trimmed, unit.suffix))
			n, err := strconv.ParseInt(number, 10, 64)
			if err != nil {
				return 0, err
			}
			return n * unit.bytes, nil
		}
	}
	return strconv.ParseInt(trimmed, 10, 64)
}
