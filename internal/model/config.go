package model

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/youmulijiang/jsowl/internal/aiclient"
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
			IdleMax:  5 * time.Second,
			Timeout:  45 * time.Second,
			Headless: true,
			// 0 means no route cap: every route the crawl deadline allows
			// is rendered.
			MaxRoutes:    0,
			CrawlTimeout: 60 * time.Second,
			// Route crawling is on by default: static extraction lists the
			// routes, but only rendering each view observes the API calls
			// the view itself fires.
			CrawlRoutes: true,

			AutoForm:        false,
			TriggerEvents:   false,
			MaxInteractions: 20,
		},
		Concurrency: ConcurrencyConfig{
			Targets:            4,
			ResourcesPerTarget: 16,
		},
		Limits: LimitsConfig{
			MaxDepth: 5,
			// 0 means no resource cap: every reachable script and chunk is
			// fetched and analyzed.
			MaxResources: 0,
			// 0 means no body cap: responses are downloaded in full, so
			// truncated bundles never break AST chunk extraction.
			MaxBodySize: 0,
		},
		Scope: ScopeConfig{
			FetchExternalScripts: true,
			ProbeSourceMaps:      true,
			SkipLibraryBundles:   true,
			SourceMapBlacklist: []string{
				// Library and vendor bundles: their maps are huge and their
				// sources never describe the target application.
				"chunk-vendors", "chunk-libs", "vendors~", "/vendor", "node_modules",
				"/polyfills", "/runtime.", "/libs/", "axios", "lodash", "jquery",
				"moment", "echarts", "element-ui", "elementui", "antd", "highlight.js",
				"/umd/", "core-js", "regenerator-runtime", "zone.js", "bootstrap",
			},
			SuffixBlacklist: []string{
				".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico",
				".bmp", ".tif", ".tiff",
				".woff", ".woff2", ".ttf", ".otf", ".eot",
				".mp3", ".wav", ".ogg", ".flac",
				".mp4", ".webm", ".avi", ".mov", ".mkv",
				".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz",
				".pdf", ".wasm", ".exe", ".dll", ".dmg", ".iso", ".css",
			},
		},
		// AI defaults mirror what the runtime falls back to (aiclient and
		// NewAIThird), so the user-level config template can preset them.
		AI: AIConfig{
			Format:      aiclient.FormatOpenAIChat,
			MaxRequests: 20,
		},
		Output: OutputConfig{
			Directory:       "./jsowl-report",
			JSON:            true,
			HTML:            true,
			DownloadJS:      true,
			JSDirectory:     "js",
			RequestTemplate: true,
		},
	}
}

// LoadConfig decodes a strict YAML configuration while preserving unspecified defaults.
func LoadConfig(path string) (Config, error) {
	return LoadConfigOnto(DefaultConfig(), path)
}

// LoadConfigOnto decodes the strict YAML file at path on top of base. Fields
// the file leaves unspecified keep their base values, so layered files merge:
// a user-level file can carry global values while a project file overrides
// individual fields. rules_file is honored only when this file sets it, and
// resolves relative to the file's directory.
func LoadConfigOnto(base Config, path string) (Config, error) {
	// Clone the maps so a higher layer never mutates the base it decodes over.
	base.Request.Headers = maps.Clone(base.Request.Headers)
	base.Request.Cookies = maps.Clone(base.Request.Cookies)

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

	cfg := base
	decoder := yaml.NewDecoder(&normalized)
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	if documentSetsKey(&document, "rules_file") {
		if strings.TrimSpace(cfg.RulesFile) == "" {
			// An explicit empty rules_file clears rules inherited from
			// lower configuration layers.
			cfg.RulesFile = ""
			cfg.Rules = RulesConfig{}
		} else {
			rulesPath := cfg.RulesFile
			if !filepath.IsAbs(rulesPath) {
				rulesPath = filepath.Join(filepath.Dir(path), rulesPath)
			}
			rules, err := loadRulesFile(rulesPath)
			if err != nil {
				return Config{}, err
			}
			cfg.Rules = rules
		}
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// documentSetsKey reports whether the document's root mapping contains the
// key, so inherited values are only replaced by files that actually set one.
func documentSetsKey(document *yaml.Node, key string) bool {
	if document.Kind != yaml.DocumentNode || len(document.Content) != 1 {
		return false
	}
	root := document.Content[0]
	if root.Kind != yaml.MappingNode {
		return false
	}
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == key {
			return true
		}
	}
	return false
}

// LoadRulesFile reads a rule file in either supported schema (JsOwl custom
// or HaE native), resolving include chains relative to the file.
func LoadRulesFile(path string) (RulesConfig, error) {
	return loadRulesFile(path)
}

// ParseRules decodes a rule document held in memory, auto-detecting the
// schema (JsOwl custom or HaE native) exactly as LoadRulesFile does. name is
// used only for error messages; include chains are not resolved here because
// there is no file to resolve them against.
func ParseRules(name string, data []byte) (RulesConfig, error) {
	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil {
		return RulesConfig{}, fmt.Errorf("parse rules %q: %w", name, err)
	}
	if isHaERulesDocument(&document) {
		rules, err := parseHaERules(&document)
		if err != nil {
			return RulesConfig{}, fmt.Errorf("decode rules %q: %w", name, err)
		}
		return rules, nil
	}
	var rules RulesConfig
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&rules); err != nil {
		return RulesConfig{}, fmt.Errorf("decode rules %q: %w", name, err)
	}
	return rules, nil
}

// loadRulesFile strictly decodes the rule-specific YAML document and folds in
// any included rule files (resolved relative to this file, cycle-safe).
func loadRulesFile(path string) (RulesConfig, error) {
	return loadRulesFileVisited(path, map[string]struct{}{})
}

func loadRulesFileVisited(path string, visited map[string]struct{}) (RulesConfig, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		absolute = path
	}
	if _, seen := visited[absolute]; seen {
		return RulesConfig{}, fmt.Errorf("rules include cycle at %q", path)
	}
	visited[absolute] = struct{}{}

	data, err := os.ReadFile(path)
	if err != nil {
		return RulesConfig{}, fmt.Errorf("read rules file %q: %w", path, err)
	}
	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil {
		return RulesConfig{}, fmt.Errorf("parse rules file %q: %w", path, err)
	}
	var rules RulesConfig
	if isHaERulesDocument(&document) {
		// HaE-native files (rules:/group:/rule:) decode leniently: they come
		// from an external ecosystem and must load without edits.
		rules, err = parseHaERules(&document)
		if err != nil {
			return RulesConfig{}, fmt.Errorf("decode rules file %q: %w", path, err)
		}
	} else {
		decoder := yaml.NewDecoder(bytes.NewReader(data))
		decoder.KnownFields(true)
		if err := decoder.Decode(&rules); err != nil {
			return RulesConfig{}, fmt.Errorf("decode rules file %q: %w", path, err)
		}
	}

	merged := rules
	for _, include := range rules.Include {
		includePath := include
		if !filepath.IsAbs(includePath) {
			includePath = filepath.Join(filepath.Dir(path), includePath)
		}
		included, err := loadRulesFileVisited(includePath, visited)
		if err != nil {
			return RulesConfig{}, err
		}
		merged.Disabled = append(merged.Disabled, included.Disabled...)
		merged.Custom = append(merged.Custom, included.Custom...)
	}
	return merged, nil
}

// Validate rejects configuration values that could disable scan safety bounds.
func (c Config) Validate() error {
	if c.Mode != ModeAuto && c.Mode != ModeDirect && c.Mode != ModeBrowser {
		return fmt.Errorf("invalid mode %q", c.Mode)
	}
	if c.Request.Timeout <= 0 || c.Request.TargetTimeout <= 0 {
		return errors.New("request timeouts must be positive")
	}
	if c.Browser.Wait < 0 || c.Browser.Idle < 0 ||
		c.Browser.IdleMax < 0 || c.Browser.Timeout <= 0 {
		return errors.New("browser durations are invalid")
	}
	if c.Browser.MaxInteractions < 0 {
		return errors.New("browser.max_interactions must not be negative")
	}
	if c.Browser.MaxRoutes < 0 || c.Browser.CrawlTimeout < 0 {
		return errors.New("browser crawl bounds are invalid")
	}
	if c.Concurrency.Targets <= 0 || c.Concurrency.ResourcesPerTarget <= 0 {
		return errors.New("concurrency values must be positive")
	}
	if c.AI.Enabled {
		if strings.TrimSpace(c.AI.APIKey) == "" {
			return errors.New("启用 -ai 需要先在配置文件的 ai.api_key 中设置模型 API Key")
		}
		if strings.TrimSpace(c.AI.BaseURL) == "" {
			return errors.New("启用 -ai 需要设置 ai.base_url（AI 上游接口地址）")
		}
		// Unknown format values fall back to the OpenAI default at client
		// build time; validation only rejects clearly unsupported input so
		// a typo does not silently scan against the wrong protocol.
		format := strings.ToLower(strings.TrimSpace(c.AI.Format))
		switch format {
		case "", aiclient.FormatOpenAIChat, aiclient.FormatOpenAIResponses,
			aiclient.FormatAnthropic, "anthropic", aiclient.FormatGemini, "gemini":
		default:
			return fmt.Errorf(
				"ai.format 不支持 %q（可选 openai-chat / openai-responses / anthropic-messages / gemini-native）", format)
		}
		if c.AI.MaxRequests < 0 {
			return errors.New("ai.max_requests must not be negative")
		}
	}
	// MaxResources accepts 0 for "no cap"; MaxBodySize accepts 0 for
	// "download in full"; negative values are rejected.
	if c.Limits.MaxDepth < 0 || c.Limits.MaxResources < 0 || c.Limits.MaxBodySize < 0 {
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
	for _, domain := range c.Scope.RestrictDomains {
		if err := validateAllowDomain(domain); err != nil {
			return err
		}
	}
	for _, suffix := range c.Scope.SuffixBlacklist {
		if err := validateSuffix(suffix); err != nil {
			return err
		}
	}
	return nil
}

func validateSuffix(raw string) error {
	suffix := strings.TrimSpace(raw)
	suffix = strings.TrimPrefix(suffix, ".")
	if suffix == "" || strings.ContainsAny(suffix, `/\?#`) {
		return fmt.Errorf("invalid suffix blacklist entry %q", raw)
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
