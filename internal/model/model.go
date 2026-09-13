package model

import (
	"net/http"
	"time"
)

type Mode string

const (
	ModeAuto    Mode = "auto"
	ModeDirect  Mode = "direct"
	ModeBrowser Mode = "browser"
)

type RuleCategory string

const (
	RuleCategoryURL       RuleCategory = "url"
	RuleCategorySensitive RuleCategory = "sensitive"
)

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Endpoint evidence ranks how strongly an API path is confirmed.
const (
	EvidenceRuntime = "runtime"  // observed as a live browser request via CDP
	EvidenceFullURL = "full-url" // absolute URL recovered by AST analysis
	EvidenceStatic  = "static"   // relative path from AST or regex matching
)

type ResourceType string

const (
	ResourceTypeDocument ResourceType = "document"
	ResourceTypeScript   ResourceType = "script"
	ResourceTypeChunk    ResourceType = "chunk"
	ResourceTypeAPI      ResourceType = "api"
	ResourceTypeRoute    ResourceType = "route"
	ResourceTypeAsset    ResourceType = "asset"
	ResourceTypeExternal ResourceType = "external"
)

type RequestConfig struct {
	Timeout       time.Duration     `yaml:"timeout" json:"timeout"`
	TargetTimeout time.Duration     `yaml:"target_timeout" json:"target_timeout"`
	Retry         int               `yaml:"retry" json:"retry"`
	Proxy         string            `yaml:"proxy" json:"proxy"`
	UserAgent     string            `yaml:"user_agent" json:"user_agent"`
	Headers       map[string]string `yaml:"headers" json:"headers"`
	Cookies       map[string]string `yaml:"cookies" json:"cookies"`
}

type BrowserConfig struct {
	Path             string        `yaml:"path" json:"path"`
	Wait             time.Duration `yaml:"wait" json:"wait"`
	Idle             time.Duration `yaml:"idle" json:"idle"`
	Timeout          time.Duration `yaml:"timeout" json:"timeout"`
	Headless         bool          `yaml:"headless" json:"headless"`
	NoSandbox        bool          `yaml:"no_sandbox" json:"no_sandbox"`
	CollectorScript  string        `yaml:"collector_script" json:"collector_script"`
	DisableInjection bool          `yaml:"disable_injection" json:"disable_injection"`
}

type ConcurrencyConfig struct {
	Targets            int `yaml:"targets" json:"targets"`
	ResourcesPerTarget int `yaml:"resources_per_target" json:"resources_per_target"`
}

type LimitsConfig struct {
	MaxDepth     int   `yaml:"max_depth" json:"max_depth"`
	MaxResources int   `yaml:"max_resources" json:"max_resources"`
	MaxBodySize  int64 `yaml:"max_body_size" json:"max_body_size"`
}

type ScopeConfig struct {
	AllowDomains           []string `yaml:"allow_domains" json:"allow_domains"`
	SuffixBlacklist        []string `yaml:"suffix_blacklist" json:"suffix_blacklist"`
	FetchExternalScripts   bool     `yaml:"fetch_external_scripts" json:"fetch_external_scripts"`
	ProbeExternalEndpoints bool     `yaml:"probe_external_endpoints" json:"probe_external_endpoints"`
}

type OutputConfig struct {
	Directory   string `yaml:"directory" json:"directory"`
	JSON        bool   `yaml:"json" json:"json"`
	HTML        bool   `yaml:"html" json:"html"`
	DownloadJS  bool   `yaml:"download_js" json:"download_js"`
	JSDirectory string `yaml:"js_directory" json:"js_directory"`
}

type RulesConfig struct {
	Disabled []string `yaml:"disabled" json:"disabled"`
	Custom   []Rule   `yaml:"custom" json:"custom"`
}

// Config contains every library and CLI scan setting.
type Config struct {
	Mode        Mode              `yaml:"mode" json:"mode"`
	Request     RequestConfig     `yaml:"request" json:"request"`
	Browser     BrowserConfig     `yaml:"browser" json:"browser"`
	Concurrency ConcurrencyConfig `yaml:"concurrency" json:"concurrency"`
	Limits      LimitsConfig      `yaml:"limits" json:"limits"`
	Scope       ScopeConfig       `yaml:"scope" json:"scope"`
	Output      OutputConfig      `yaml:"output" json:"output"`
	RulesFile   string            `yaml:"rules_file" json:"rules_file,omitempty"`
	Rules       RulesConfig       `yaml:"-" json:"rules"`
}

// Target describes one isolated scan target and its request state.
type Target struct {
	URL     string         `json:"url"`
	BaseURL string         `json:"base_url,omitempty"`
	Headers http.Header    `json:"headers,omitempty"`
	Cookies []*http.Cookie `json:"-"`
}

// Rule defines one compiled URL or sensitive-information extraction pattern.
type Rule struct {
	ID          string       `yaml:"id" json:"id"`
	Name        string       `yaml:"name" json:"name"`
	Category    RuleCategory `yaml:"category" json:"category"`
	Severity    Severity     `yaml:"severity" json:"severity"`
	Pattern     string       `yaml:"pattern" json:"pattern"`
	Group       int          `yaml:"group" json:"group"`
	Description string       `yaml:"description" json:"description"`
	Enabled     bool         `yaml:"enabled" json:"enabled"`
}

type BrowserStatus struct {
	Attempted bool   `json:"attempted"`
	Used      bool   `json:"used"`
	Degraded  bool   `json:"degraded"`
	Reason    string `json:"reason,omitempty"`
}

type Resource struct {
	URL         string       `json:"url"`
	Type        ResourceType `json:"type"`
	SourceURL   string       `json:"source_url,omitempty"`
	LocalPath   string       `json:"local_path,omitempty"`
	StatusCode  int          `json:"status_code,omitempty"`
	ContentType string       `json:"content_type,omitempty"`
	Size        int64        `json:"size,omitempty"`
	Depth       int          `json:"depth"`
}

type Endpoint struct {
	Raw        string `json:"raw"`
	URL        string `json:"url"`
	SourceURL  string `json:"source_url"`
	Authorized bool   `json:"authorized"`
	StatusCode int    `json:"status_code,omitempty"`
	Method     string `json:"method,omitempty"`
	Evidence   string `json:"evidence,omitempty"`
	Line       int    `json:"line,omitempty"`
	Column     int    `json:"column,omitempty"`
	// ContextLines carries up to three surrounding source lines so reports
	// can show the call without re-downloading the bundle.
	ContextLines []ContextLine `json:"context_lines,omitempty"`
}

// ContextLine is one line of surrounding source code for a finding.
type ContextLine struct {
	LineNumber int    `json:"line_number"`
	Content    string `json:"content"`
	MatchStart int    `json:"match_start"`
	MatchEnd   int    `json:"match_end"`
}

// Finding records one rule match and its source location.
type Finding struct {
	RuleID       string        `json:"rule_id"`
	RuleName     string        `json:"rule_name"`
	Category     RuleCategory  `json:"category"`
	Severity     Severity      `json:"severity"`
	Value        string        `json:"value"`
	SourceURL    string        `json:"source_url"`
	Line         int           `json:"line"`
	Column       int           `json:"column"`
	ContextLines []ContextLine `json:"context_lines"`
}

// Issue records a non-fatal resource error or diagnostic event.
type Issue struct {
	Code      string `json:"code"`
	Stage     string `json:"stage"`
	URL       string `json:"url,omitempty"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

type Statistics struct {
	Resources int `json:"resources"`
	Scripts   int `json:"scripts"`
	Chunks    int `json:"chunks"`
	Endpoints int `json:"endpoints"`
	Findings  int `json:"findings"`
}

// Result is the deterministic, serializable output of one target scan.
type Result struct {
	Target        string        `json:"target"`
	StartedAt     time.Time     `json:"started_at"`
	FinishedAt    time.Time     `json:"finished_at"`
	Mode          Mode          `json:"mode"`
	UserAgent     string        `json:"user_agent"`
	BrowserStatus BrowserStatus `json:"browser_status"`
	Resources     []Resource    `json:"resources"`
	Endpoints     []Endpoint    `json:"endpoints"`
	Findings      []Finding     `json:"findings"`
	Technologies  []string      `json:"technologies"`
	Statistics    Statistics    `json:"statistics"`
	Issues        []Issue       `json:"issues"`
}

type BatchItem struct {
	Target Target
	Result *Result
	Err    error
}
