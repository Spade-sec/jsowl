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
	ResourceTypeDocument  ResourceType = "document"
	ResourceTypeScript    ResourceType = "script"
	ResourceTypeChunk     ResourceType = "chunk"
	ResourceTypeAPI       ResourceType = "api"
	ResourceTypeRoute     ResourceType = "route"
	ResourceTypeSourceMap ResourceType = "sourcemap"
	ResourceTypeAsset     ResourceType = "asset"
	ResourceTypeExternal  ResourceType = "external"
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
	Path string        `yaml:"path" json:"path"`
	Wait time.Duration `yaml:"wait" json:"wait"`
	Idle time.Duration `yaml:"idle" json:"idle"`
	// IdleMax caps the WaitRequestIdle phase: polling SPAs never keep the
	// network quiet for `idle`, so without a cap the browser stage always
	// runs to Timeout and the injection results are lost. When IdleMax
	// elapses, waiting is abandoned and the snapshot proceeds with what has
	// been collected so far. 0 disables the cap.
	IdleMax          time.Duration `yaml:"idle_max" json:"idle_max"`
	Timeout          time.Duration `yaml:"timeout" json:"timeout"`
	Headless         bool          `yaml:"headless" json:"headless"`
	NoSandbox        bool          `yaml:"no_sandbox" json:"no_sandbox"`
	CollectorScript  string        `yaml:"collector_script" json:"collector_script"`
	DisableInjection bool          `yaml:"disable_injection" json:"disable_injection"`
	// CrawlRoutes renders each discovered framework route so the endpoints a
	// view loads are observed too. Front-end route guards are frequently not
	// authorization, so navigating straight to a view often renders it and
	// fires its API calls. Off by default: it multiplies the requests a scan
	// sends and can trigger the target's own write paths.
	CrawlRoutes bool `yaml:"crawl_routes" json:"crawl_routes"`
	// MaxRoutes bounds how many route views one scan renders.
	MaxRoutes int `yaml:"max_routes" json:"max_routes"`
	// CrawlTimeout bounds the total time spent rendering route views.
	CrawlTimeout time.Duration `yaml:"crawl_timeout" json:"crawl_timeout"`
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
	AllowDomains []string `yaml:"allow_domains" json:"allow_domains"`
	// RestrictDomains, when non-empty, limits crawling to the root origin
	// plus these domains: scripts outside the list are not fetched and
	// endpoints outside it are neither probed nor marked authorized.
	RestrictDomains        []string `yaml:"restrict_domains" json:"restrict_domains"`
	SuffixBlacklist        []string `yaml:"suffix_blacklist" json:"suffix_blacklist"`
	FetchExternalScripts   bool     `yaml:"fetch_external_scripts" json:"fetch_external_scripts"`
	ProbeExternalEndpoints bool     `yaml:"probe_external_endpoints" json:"probe_external_endpoints"`
	// ProbeRoutes optionally GETs framework routes and compares their body
	// against the index page to tell server-backed routes from SPA fallbacks.
	ProbeRoutes bool `yaml:"probe_routes" json:"probe_routes"`
	// ProbeSourceMaps fetches JavaScript source maps and feeds the sources
	// they embed back into the analyzer, which recovers the unminified
	// originals. On by default: a leaked map usually restores the whole app.
	ProbeSourceMaps bool `yaml:"probe_source_maps" json:"probe_source_maps"`
	// SourceMapBlacklist skips maps whose URL path contains one of these
	// fragments, so known library bundles are not downloaded.
	SourceMapBlacklist []string `yaml:"source_map_blacklist" json:"source_map_blacklist"`
	// SkipLibraryBundles skips the regex and AST pass over scripts whose
	// license banner identifies a third-party library, so analysis stays on
	// the code that actually describes the target.
	SkipLibraryBundles bool `yaml:"skip_library_bundles" json:"skip_library_bundles"`
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
	ID       string       `yaml:"id" json:"id"`
	Name     string       `yaml:"name" json:"name"`
	Category RuleCategory `yaml:"category" json:"category"`
	Severity Severity     `yaml:"severity" json:"severity"`
	Pattern  string       `yaml:"pattern" json:"pattern"`
	Group    int          `yaml:"group" json:"group"`
	// MethodGroup optionally captures the HTTP verb from the same match.
	MethodGroup int    `yaml:"method_group,omitempty" json:"method_group,omitempty"`
	Description string `yaml:"description" json:"description"`
	Enabled     bool   `yaml:"enabled" json:"enabled"`
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
	// Source records how the endpoint was found: cdp, ast, or regex.
	Source string `json:"source,omitempty"`
	// Type separates backend APIs from framework routes: api or route.
	Type string `json:"type,omitempty"`
	// Probe records the optional route probe outcome: server (distinct body
	// from the index), static (identical), or error.
	Probe  string `json:"probe,omitempty"`
	Line   int    `json:"line,omitempty"`
	Column int    `json:"column,omitempty"`
	// ContextLines carries up to three surrounding source lines so reports
	// can show the call without re-downloading the bundle.
	ContextLines []ContextLine `json:"context_lines,omitempty"`
	// BodyParams lists request-body field names for write methods.
	BodyParams []string `json:"body_params,omitempty"`
	// Vendor marks a result that came from a third-party library bundle
	// (identified by its license banner) instead of application code.
	Vendor bool `json:"vendor,omitempty"`
	// ResponseParams lists JSON field names observed in the probe response,
	// so fields that only the server exposes can be fuzzed too. Only names
	// are kept; response bodies are never persisted.
	ResponseParams []string `json:"response_params,omitempty"`
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
	// Vendor marks a match found in a third-party library bundle.
	Vendor       bool          `json:"vendor,omitempty"`
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

// ProbeEvent is emitted the moment one API probe completes, so hosts can
// stream results to a terminal without waiting for the scan to finish.
type ProbeEvent struct {
	Target     string `json:"target"`
	URL        string `json:"url"`
	Method     string `json:"method,omitempty"`
	StatusCode int    `json:"status_code,omitempty"`
	Evidence   string `json:"evidence,omitempty"`
}
