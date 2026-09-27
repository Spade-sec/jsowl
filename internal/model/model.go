package model

import (
	"fmt"
	"net/http"
	"time"

	"go.yaml.in/yaml/v3"
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

// Request-parameter evidence ranks how strongly a param value or content
// type was recovered. Values follow the same recall-first policy as API
// discovery: even a placeholder name is reported, just with lower evidence.
const (
	EvidenceLiteral     = "literal"     // written as a constant in the source
	EvidenceConstant    = "constant"    // resolved through an identifier binding
	EvidencePlaceholder = "placeholder" // dynamic expression, name kept as {name}
	EvidenceInferred    = "inferred"    // deduced from the payload shape
)

// Param is one request parameter key with the best value the AST could
// recover. Values are always present in some form so the report can seed
// fuzzing; the Evidence field says how trustworthy each value is.
type Param struct {
	Key      string `json:"key"`
	Value    string `json:"value,omitempty"`
	Evidence string `json:"evidence,omitempty"`
	// Taint describes where a runtime-only value flows in from. It is
	// advisory metadata: the value column stays the source symbol.
	Taint *Taint `json:"taint,omitempty"`
}

// Taint is the local backward-taint annotation attached to placeholder
// parameters: the value of such a parameter is a runtime object, and this
// says where that object originates.
type Taint struct {
	// Kind classifies the origin: upstream (a prior API response), storage
	// (localStorage/sessionStorage), route (client router params), or
	// unknown.
	Kind string `json:"kind"`
	// Symbol is the source-level expression the value flows through
	// (e.g. "res.data").
	Symbol string `json:"symbol,omitempty"`
	// Upstream is the URL of the API whose response feeds this parameter
	// (Kind=upstream); UpstreamField is the response member read.
	Upstream      string `json:"upstream,omitempty"`
	UpstreamField string `json:"upstream_field,omitempty"`
	// Hops counts backward-binding steps taken (1 = bound directly in the
	// same function).
	Hops int `json:"hops,omitempty"`
}

// Taint kinds.
const (
	TaintUpstream = "upstream"
	TaintStorage  = "storage"
	TaintRoute    = "route"
	TaintUnknown  = "unknown"
)

// RequestSpec is the normalized shape of one request call site, merged from
// every client library into the same vocabulary.
type RequestSpec struct {
	// BaseURL is the axios-instance base the path would be joined with, when
	// one was recovered; BaseURLKind carries the same evidence vocabulary.
	BaseURL     string `json:"base_url,omitempty"`
	BaseURLKind string `json:"base_url_kind,omitempty"`
	ContentType string `json:"content_type,omitempty"`
	// ContentTypeEvidence marks how the content type was obtained: literal
	// (headers object), inferred (JSON.stringify / FormData), or empty when
	// unknown.
	ContentTypeEvidence string  `json:"content_type_evidence,omitempty"`
	Query               []Param `json:"query,omitempty"`
	Body                []Param `json:"body,omitempty"`
}

// ParamKeys flattens both parameter lists into the deduplicated key set the
// legacy BodyParams field carried.
func (s *RequestSpec) ParamKeys() []string {
	if s == nil {
		return nil
	}
	seen := make(map[string]struct{}, len(s.Body)+len(s.Query))
	keys := make([]string, 0, len(s.Body)+len(s.Query))
	for _, param := range append(append([]Param{}, s.Query...), s.Body...) {
		if param.Key == "" {
			continue
		}
		if _, duplicate := seen[param.Key]; duplicate {
			continue
		}
		seen[param.Key] = struct{}{}
		keys = append(keys, param.Key)
	}
	return keys
}

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
	// MaxRoutes bounds how many route views one scan renders. 0 means no
	// cap: crawling is then bounded by crawl_timeout and view signatures
	// alone.
	MaxRoutes int `yaml:"max_routes" json:"max_routes"`
	// CrawlTimeout bounds the total time spent rendering route views.
	CrawlTimeout time.Duration `yaml:"crawl_timeout" json:"crawl_timeout"`
	// AutoForm fills and submits the page's forms at runtime (katana-style,
	// adapted from projectdiscovery/katana, MIT) so the requests a form
	// submit fires are observed by CDP and their parameters recorded.
	// Off by default: submission can trigger the target's write paths.
	AutoForm bool `yaml:"auto_form" json:"auto_form"`
	// TriggerEvents clicks buttons and elements carrying inline handlers so
	// SPA interactions fire their hidden API calls. Off by default for the
	// same reason.
	TriggerEvents bool `yaml:"trigger_events" json:"trigger_events"`
	// MaxInteractions bounds form submits plus event clicks per page render.
	// 0 applies the default of 20.
	MaxInteractions int `yaml:"max_interactions" json:"max_interactions"`
	// Aggressive stops skipping disabled and invisible controls during
	// runtime interactions: they are filled and clicked too, via direct DOM
	// writes when normal interaction is impossible. Wider attack surface,
	// noisier; server-side validation becomes the only guard.
	Aggressive bool `yaml:"aggressive" json:"aggressive"`
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
	// RequestTemplate reconstructs an HTTP request packet per API endpoint
	// into the API report (values literal where the source had them,
	// {{fuzz:...}} placeholders elsewhere).
	RequestTemplate bool `yaml:"request_template" json:"request_template"`
}

type RulesConfig struct {
	// Include loads extra rule files (HaE-adapted sets, team rules); paths are
	// resolved relative to the including file and merged before compilation.
	Include  []string `yaml:"include" json:"include"`
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
	// AI configures the optional AI-assist layer (-ai): an OpenAI-compatible
	// chat endpoint plus budget bounds. Credentials never serialize into
	// scan results — results reference AI verdicts, not the key.
	AI AIConfig `yaml:"ai" json:"ai"`
}

// AIConfig points at an OpenAI-compatible chat completions endpoint. Any
// provider exposing that protocol works (GLM, one-api proxies, vLLM, ...).
type AIConfig struct {
	// Enabled is flipped by the -ai CLI flag; scans run the AI enrichers
	// only when set.
	Enabled bool `yaml:"enabled" json:"enabled"`
	// APIKey authenticates as a Bearer token.
	APIKey string `yaml:"api_key" json:"-"`
	// BaseURL is the provider root, e.g. https://open.bigmodel.cn/api/paas/v4.
	BaseURL string `yaml:"base_url" json:"-"`
	// Path is the chat completions route appended to BaseURL
	// (default /chat/completions).
	Path string `yaml:"path" json:"-"`
	// Model is the model id requested in the payload.
	Model string `yaml:"model" json:"model"`
	// MaxRequests caps AI calls per scan (default 20) so a large target
	// cannot run away with the budget.
	MaxRequests int `yaml:"max_requests" json:"max_requests"`
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
	// Engine is accepted for HaE-file compatibility (nfa/dfa/java) but no
	// longer selects a backend: every rule compiles with regexp2.
	Engine string `yaml:"engine,omitempty" json:"engine,omitempty"`
	// SRegex optionally re-runs against the extracted value: a miss discards
	// the finding (false-positive filter), a hit keeps it — and when SGroup
	// names a capture group of SRegex, that group replaces the value.
	SRegex string `yaml:"s_regex,omitempty" json:"s_regex,omitempty"`
	SGroup int    `yaml:"s_group,omitempty" json:"s_group,omitempty"`
	// Format renders the final value HaE-style: {0} is the whole match,
	// {N} the Nth capture group; empty means the extracted text itself.
	Format string `yaml:"format,omitempty" json:"format,omitempty"`
	// IgnoreCase compiles the pattern case-insensitively; HaE rules derive
	// it from an absent or false `sensitive` field.
	IgnoreCase bool `yaml:"ignore_case,omitempty" json:"ignore_case,omitempty"`
}

// ruleYAMLFields is the whitelist of keys a rule mapping may carry; the
// custom unmarshaler rejects anything else to keep rule files strict.
var ruleYAMLFields = map[string]struct{}{
	"id": {}, "name": {}, "category": {}, "severity": {}, "pattern": {},
	"group": {}, "method_group": {}, "description": {}, "enabled": {},
	"engine": {}, "s_regex": {}, "s_group": {}, "format": {}, "ignore_case": {},
}

// UnmarshalYAML decodes one rule mapping and defaults Enabled to true when
// the key is absent, mirroring HaE's loaded field: rules are on unless
// explicitly disabled, so HaE rule sets can be pasted in without edits.
func (r *Rule) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.MappingNode {
		return fmt.Errorf("rule must be a mapping, got kind %v", value.Kind)
	}
	for i := 0; i+1 < len(value.Content); i += 2 {
		key := value.Content[i].Value
		if _, known := ruleYAMLFields[key]; !known {
			return fmt.Errorf("field %s not found", key)
		}
	}
	var raw struct {
		ID          string       `yaml:"id"`
		Name        string       `yaml:"name"`
		Category    RuleCategory `yaml:"category"`
		Severity    Severity     `yaml:"severity"`
		Pattern     string       `yaml:"pattern"`
		Group       int          `yaml:"group"`
		MethodGroup int          `yaml:"method_group"`
		Description string       `yaml:"description"`
		Enabled     *bool        `yaml:"enabled"`
		Engine      string       `yaml:"engine"`
		SRegex      string       `yaml:"s_regex"`
		SGroup      int          `yaml:"s_group"`
		Format      string       `yaml:"format"`
		IgnoreCase  bool         `yaml:"ignore_case"`
	}
	if err := value.Decode(&raw); err != nil {
		return err
	}
	r.ID = raw.ID
	r.Name = raw.Name
	r.Category = raw.Category
	r.Severity = raw.Severity
	r.Pattern = raw.Pattern
	r.Group = raw.Group
	r.MethodGroup = raw.MethodGroup
	r.Description = raw.Description
	r.Enabled = raw.Enabled == nil || *raw.Enabled
	r.Engine = raw.Engine
	r.SRegex = raw.SRegex
	r.SGroup = raw.SGroup
	r.Format = raw.Format
	r.IgnoreCase = raw.IgnoreCase
	return nil
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
	// Spec is the normalized request shape (content type, query and body
	// parameters with per-value evidence) recovered from the AST call site.
	Spec *RequestSpec `json:"spec,omitempty"`
	// Vendor marks a result that came from a third-party library bundle
	// (identified by its license banner) instead of application code.
	Vendor bool `json:"vendor,omitempty"`
	// ResponseParams lists JSON field names observed in the probe response,
	// so fields that only the server exposes can be fuzzed too. Only names
	// are kept; response bodies are never persisted.
	ResponseParams []string `json:"response_params,omitempty"`
	// Template is the reconstructed HTTP request packet for this endpoint:
	// method, URL, headers and a body serialized from Spec, with values kept
	// literal where the source had them and {{fuzz:...}} placeholders where
	// they must be invented. Built by analyze.BuildTemplate.
	Template *RequestTemplate `json:"template,omitempty"`
}

// RequestTemplate is the reconstructed HTTP request packet for one endpoint.
// Placeholder syntax embedded in URL/Headers/Body:
//   - {{fuzz:name}}        — value must be invented for testing
//   - {{fuzz:body:{sym}}}  — the whole body is a runtime object (source symbol sym)
//   - {{cookie:NAME}}      — session cookie the client library is expected to send
type RequestTemplate struct {
	Method  string      `json:"method"`
	URL     string      `json:"url"`
	Headers []HeaderTpl `json:"headers,omitempty"`
	Body    string      `json:"body,omitempty"`
	// Notes carry caveats that would break the packet if ignored (e.g. the
	// site likely hashes passwords before sending).
	Notes []string `json:"notes,omitempty"`
	// AI is the optional AI review of this packet (parameter completeness
	// and authenticity); present only when -ai is enabled and the model
	// responded for this endpoint.
	AI *AIReview `json:"ai,omitempty"`
}

// AIReview is the AI layer's verdict on one reconstructed request packet.
type AIReview struct {
	// Completeness classifies the parameter set: complete, missing-fields,
	// or uncertain.
	Completeness string `json:"completeness,omitempty"`
	// Assessment is a short human-readable authenticity judgement.
	Assessment string `json:"assessment,omitempty"`
	// SuggestedParams lists field names the AI believes the call probably
	// needs but the static layer could not recover — advisory, never merged
	// into the body itself.
	SuggestedParams []string `json:"suggested_params,omitempty"`
}

// HeaderTpl is one reconstructed header line; Evidence distinguishes headers
// read verbatim from the call site (literal) from ones inferred from the
// payload shape (inferred) or expected client-library behavior (placeholder).
type HeaderTpl struct {
	Key      string `json:"key"`
	Value    string `json:"value"`
	Evidence string `json:"evidence,omitempty"`
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
	// AI is the optional AI assessment of how exploitable/valuable this
	// sensitive finding is; present only when -ai is enabled.
	AI *AIAssessment `json:"ai,omitempty"`
}

// AIAssessment is the AI layer's value rating for one finding.
type AIAssessment struct {
	// Rating: high / medium / low / invalid.
	Rating string `json:"rating"`
	// Reason justifies the rating in one sentence.
	Reason string `json:"reason,omitempty"`
	// Suggestion names the next test the finding enables (e.g. try the key
	// against the admin API).
	Suggestion string `json:"suggestion,omitempty"`
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
