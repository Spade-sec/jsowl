# JsOwl Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build JsOwl as a reusable Go library and compact CLI that collects HTML, JavaScript, SPA runtime resources and chunks, extracts URLs and sensitive information, safely GETs authorized endpoints, and emits JSON/HTML reports.

**Architecture:** A public `jsowl.Scanner` owns per-target scan state and delegates HTTP/browser collection to adapters. Every collected response enters one bounded discovery/analyzer queue shared by direct, browser and auto modes; reporters consume the same deterministic `Result` model.

**Tech Stack:** Go 1.25 module, `github.com/enetx/surf` v1.0.173, `github.com/go-rod/rod` v0.116.2, Cobra v1.10.2, goquery v1.10.3, xxhash/v2 v2.3.0, `golang.org/x/sync` v0.16.0, and `go.yaml.in/yaml/v3` v3.0.4.

## Global Constraints

- Keep module path `github.com/youmulijiang/jsowl` and `go 1.25.0`.
- CLI has no subcommands; supported flags are `-u/-l/-c/-o/-m/-H/-t/-v`, `--check`, and help.
- CLI explicit values override YAML; YAML overrides `DefaultConfig()`.
- Browser configuration is YAML-only. Never download Chrome/Chromium automatically.
- `auto` runs surf first and uses Rod only for SPA/dynamic shortfall; browser failure in auto is a recorded degradation.
- Browser defaults are `wait: 3s`, `idle: 800ms`, and `timeout: 45s`.
- Only GET authorized endpoints. Never issue POST, PUT, PATCH, DELETE, form submissions, or guessed request bodies.
- Fetch cross-origin scripts referenced by the target; do not GET cross-origin endpoints unless allowlisted.
- If no User-Agent is configured, choose one random desktop UA per target and reuse it for surf, Rod, scripts, chunks and API GETs.
- JSON and HTML preserve full sensitive values and must warn that reports contain sensitive data.
- `output.download_js` defaults to false; API bodies are never persisted.
- Every queue is bounded by target timeout, maximum depth, maximum resources, body size and worker counts.
- Internal packages import `internal/model`, never the root `jsowl` package, preventing import cycles; root public types are aliases.
- Use TDD for every task and run focused tests before the full suite.

## File Map

| Path | Responsibility |
|---|---|
| `config.go` | Public configuration, defaults, strict YAML loading and CLI override helpers |
| `target.go` | Public target and batch item types |
| `result.go` | Public deterministic scan result and error models |
| `rules.go` | Public custom-rule types |
| `scanner.go` | Public constructor, single scan and batch scan orchestration |
| `internal/model/model.go` | Canonical internal configuration/result types exposed through root aliases |
| `internal/ua/ua.go` | Random per-target desktop User-Agent selection |
| `internal/scope/scope.go` | URL normalization, same-origin and allowlist decisions |
| `internal/analyze/engine.go` | Compiled URL/sensitive rule execution |
| `internal/analyze/builtin.go` | RE2-compatible built-in rules |
| `internal/discover/html.go` | HTML resources and SPA signal extraction |
| `internal/discover/javascript.go` | Generic JS/API/path extraction |
| `internal/discover/webpack.go` | Webpack runtime and chunk URL extraction |
| `internal/discover/requirejs.go` | RequireJS configuration and module URL extraction |
| `internal/collect/types.go` | Collector-neutral document and response types |
| `internal/collect/direct/client.go` | surf-backed GET client |
| `internal/collect/browser/browser.go` | Rod collection and browser checker |
| `internal/collect/browser/assets/collect_resource_urls.js` | Embedded enhanced page collector |
| `internal/scheduler/queue.go` | Bounded concurrent per-target resource queue |
| `internal/pipeline/pipeline.go` | Direct/browser documents through discovery, analysis and probing |
| `internal/report/json.go` | Atomic JSON report |
| `internal/report/html.go` | Embedded self-contained HTML report |
| `internal/report/assets/report.html` | HTML template and inline styling/script |
| `internal/storage/js.go` | Optional safe JavaScript persistence |
| `cmd/jsowl/main.go` | Process entry point |
| `cmd/jsowl/root.go` | No-subcommand Cobra command and validation |
| `config.example.yml` | Documented default configuration |
| `README.md` | Library and CLI usage |

---

### Task 1: Public Models, Defaults, YAML, and User-Agent

**Files:**
- Modify: `go.mod`
- Modify: `go.sum`
- Create: `.gitignore`
- Create: `config.go`
- Create: `config_test.go`
- Create: `target.go`
- Create: `result.go`
- Create: `rules.go`
- Create: `internal/model/model.go`
- Create: `internal/model/config.go`
- Create: `internal/ua/ua.go`
- Create: `internal/ua/ua_test.go`
- Create: `config.example.yml`

**Interfaces:**
- Produces: `DefaultConfig() Config`, `LoadConfig(path string) (Config, error)`, `Config.Validate() error`.
- Produces: canonical `internal/model` types plus root aliases `Target`, `Result`, `Issue`, `Resource`, `Endpoint`, `Finding`, `Rule`, and `BatchItem`.
- Produces: `ua.ForTarget(configured string, headers http.Header, random io.Reader) (string, error)`.

- [ ] **Step 1: Add dependencies and write failing default/config tests**

```go
func TestDefaultConfig(t *testing.T) {
    cfg := DefaultConfig()
    if cfg.Mode != ModeAuto { t.Fatalf("mode=%q", cfg.Mode) }
    if cfg.Browser.Wait != 3*time.Second { t.Fatalf("wait=%s", cfg.Browser.Wait) }
    if cfg.Browser.Idle != 800*time.Millisecond { t.Fatalf("idle=%s", cfg.Browser.Idle) }
    if cfg.Concurrency.ResourcesPerTarget != 16 {
        t.Fatalf("resources_per_target=%d", cfg.Concurrency.ResourcesPerTarget)
    }
    if cfg.Output.DownloadJS { t.Fatal("download_js must default false") }
}

func TestLoadConfigRejectsUnknownField(t *testing.T) {
    path := writeTemp(t, "browser:\n  mystery: true\n")
    _, err := LoadConfig(path)
    if err == nil || !strings.Contains(err.Error(), "field mystery not found") {
        t.Fatalf("err=%v", err)
    }
}
```

Use standard `testing` assertions instead of adding an assertion library; the snippet expresses the required values.

- [ ] **Step 2: Run tests to verify missing public API**

Run: `go test ./...`

Expected: FAIL because `DefaultConfig`, `LoadConfig`, and model types do not exist.

- [ ] **Step 3: Implement exact public configuration and result types**

```go
type Mode string

const (
    ModeAuto    Mode = "auto"
    ModeDirect  Mode = "direct"
    ModeBrowser Mode = "browser"
)

// internal/model/config.go
type Config struct {
    Mode        Mode              `yaml:"mode" json:"mode"`
    Request     RequestConfig     `yaml:"request" json:"request"`
    Browser     BrowserConfig     `yaml:"browser" json:"browser"`
    Concurrency ConcurrencyConfig `yaml:"concurrency" json:"concurrency"`
    Limits      LimitsConfig      `yaml:"limits" json:"limits"`
    Scope       ScopeConfig       `yaml:"scope" json:"scope"`
    Output      OutputConfig      `yaml:"output" json:"output"`
    Rules       RulesConfig       `yaml:"rules" json:"rules"`
}

type Target struct {
    URL     string
    Headers http.Header
    Cookies []*http.Cookie
}

type BatchItem struct {
    Target Target
    Result *Result
    Err    error
}

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

type BrowserStatus struct {
    Attempted bool   `json:"attempted"`
    Used      bool   `json:"used"`
    Degraded  bool   `json:"degraded"`
    Reason    string `json:"reason,omitempty"`
}

// Root package aliases keep the public API at github.com/youmulijiang/jsowl.
type Config = model.Config
type Target = model.Target
type Result = model.Result
type Rule = model.Rule
```

Decode YAML inside `internal/model` with `yaml.Decoder.KnownFields(true)`, start from defaults, and validate positive durations, body size, worker counts, modes and allowlist host syntax. Root functions wrap the internal implementation. Add `.superpowers/` and generated report directories to `.gitignore`.

- [ ] **Step 4: Implement and test per-target UA selection**

```go
func ForTarget(configured string, headers http.Header, random io.Reader) (string, error) {
    if v := headers.Get("User-Agent"); v != "" {
        return v, nil
    }
    if configured != "" {
        return configured, nil
    }
    var b [2]byte
    if _, err := io.ReadFull(random, b[:]); err != nil {
        return "", err
    }
    return desktop[int(binary.LittleEndian.Uint16(b[:]))%len(desktop)], nil
}
```

Test header precedence, configured precedence, deterministic injected randomness, and non-empty desktop pool.

- [ ] **Step 5: Verify and commit**

Run: `gofmt -w config.go config_test.go target.go result.go rules.go internal/ua/*.go`

Run: `go test ./...`

Expected: PASS.

```bash
git add go.mod go.sum .gitignore config.go config_test.go target.go result.go rules.go internal/model internal/ua config.example.yml
git commit -m "feat: add public configuration and result models"
```

---

### Task 2: URL Normalization and Authorization Scope

**Files:**
- Create: `internal/scope/scope.go`
- Create: `internal/scope/scope_test.go`

**Interfaces:**
- Consumes: `model.ScopeConfig` from Task 1.
- Produces: `scope.New(root *url.URL, cfg model.ScopeConfig) (*Scope, error)`.
- Produces: `(*Scope).Resolve(raw string, base *url.URL) (*url.URL, error)`.
- Produces: `(*Scope).CanFetchScript(*url.URL) bool` and `(*Scope).CanProbe(*url.URL) bool`.
- Produces: `scope.Canonical(*url.URL) string`.

- [ ] **Step 1: Write table-driven failing tests**

```go
func TestScopeDecisions(t *testing.T) {
    root := mustURL("https://app.example.com/start")
    s, _ := New(root, model.ScopeConfig{
        FetchExternalScripts: true,
        AllowDomains:         []string{"api.example.net"},
    })
    cases := []struct {
        raw, base string
        script, probe bool
    }{
        {"/api/users#top", root.String(), true, true},
        {"//cdn.example.net/app.js", root.String(), true, false},
        {"https://api.example.net/v1", root.String(), true, true},
    }
    // Resolve and assert both decisions.
}
```

Also test default ports, host case, dot segments, fragments, unsupported schemes, userinfo rejection and allowlist exact/subdomain behavior.

- [ ] **Step 2: Run focused test**

Run: `go test ./internal/scope -run TestScope -v`

Expected: FAIL because package/functions are absent.

- [ ] **Step 3: Implement canonicalization and scope**

```go
func Canonical(u *url.URL) string {
    c := *u
    c.Fragment = ""
    c.Host = strings.ToLower(c.Host)
    c.Path = path.Clean("/" + strings.TrimPrefix(c.EscapedPath(), "/"))
    if (c.Scheme == "https" && c.Port() == "443") ||
       (c.Scheme == "http" && c.Port() == "80") {
        c.Host = c.Hostname()
    }
    return c.String()
}
```

Resolve only HTTP(S), reject credentials, and define same-origin as equal normalized scheme, hostname and effective port. Allowlist entries match the exact host or its subdomains only when written as `.example.com`.

- [ ] **Step 4: Run tests**

Run: `go test ./internal/scope -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/scope
git commit -m "feat: add URL scope and normalization"
```

---

### Task 3: RE2 Rule Engine and Built-In Rules

**Files:**
- Create: `internal/analyze/engine.go`
- Create: `internal/analyze/engine_test.go`
- Create: `internal/analyze/builtin.go`
- Create: `internal/analyze/builtin_test.go`
- Create: `internal/analyze/testdata/cases.json`

**Interfaces:**
- Consumes: `model.Rule`, `model.Finding`, `model.RulesConfig`.
- Produces: `analyze.New(custom []model.Rule, disabled []string) (*Engine, error)`.
- Produces: `analyze.ResourceRef{URL string, Type model.ResourceType}`.
- Produces: `analyze.Candidate{Raw string, RuleID string, Offset int}`.
- Produces: `(*Engine).Analyze(source ResourceRef, body []byte) ([]model.Finding, []analyze.Candidate)`.
- Produces: `analyze.BuiltinRules() []model.Rule`.

- [ ] **Step 1: Write failing compile, location, and dedupe tests**

```go
func TestAnalyzeReportsLocationAndCapture(t *testing.T) {
    e, err := New([]model.Rule{{
        ID: "test.api", Name: "API", Category: model.RuleCategoryURL,
        Severity: model.SeverityInfo,
        Pattern: `fetch\(["']([^"']+)["']`, Group: 1, Enabled: true,
    }}, nil)
    if err != nil { t.Fatal(err) }
    findings, candidates := e.Analyze(ref("https://e.test/app.js"),
        []byte("x\nfetch('/api/users')"))
    if got := candidates[0].Raw; got != "/api/users" { t.Fatal(got) }
    if findings[0].Line != 2 { t.Fatalf("line=%d", findings[0].Line) }
}
```

Add a test that duplicate `(rule ID, source URL, value)` matches collapse to one result and invalid custom RE2 produces a named error.

- [ ] **Step 2: Run focused test**

Run: `go test ./internal/analyze -v`

Expected: FAIL because analyzer is absent.

- [ ] **Step 3: Implement compiled engine**

```go
type compiledRule struct {
    rule model.Rule
    re   *regexp.Regexp
}

type Engine struct {
    rules []compiledRule
}

type ResourceRef struct {
    URL  string
    Type model.ResourceType
}

type Candidate struct {
    Raw    string
    RuleID string
    Offset int
}

func (e *Engine) Analyze(source ResourceRef, body []byte) ([]model.Finding, []Candidate) {
    // Iterate FindAllSubmatchIndex, select Rule.Group, compute 1-based
    // line/column, capture bounded context, and stable-dedupe.
}
```

Keep context to 160 bytes on each side, without splitting invalid UTF-8. Sort by source URL, byte offset and rule ID.

- [ ] **Step 4: Port and validate built-in rules**

Create explicit rules for API calls, Vue routes, URL attributes/assignments, quoted URLs, API prefixes, static JS assets, Webpack/RequireJS signals, JWT, AWS/Alibaba/Huawei keys, GitHub tokens, Google OAuth, passwords/secrets, private-key blocks, JDBC strings and Chinese mobile numbers. Convert every pattern to Go RE2 syntax.

`cases.json` must provide at least one positive and one negative sample per built-in rule:

```json
[
  {"rule":"secret.jwt","positive":"'eyJhbGciOiJIUzI1NiJ9.abcdefghijk.abcdefghijk'","negative":"'not.a.jwt'"},
  {"rule":"url.api-prefix","positive":"'/api/v1/users'","negative":"'api without slash'"}
]
```

Run: `go test ./internal/analyze -v`

Expected: PASS and every built-in rule represented in the fixture.

- [ ] **Step 5: Commit**

```bash
git add internal/analyze
git commit -m "feat: add RE2 extraction rule engine"
```

---

### Task 4: HTML and Generic JavaScript Discovery

**Files:**
- Create: `internal/discover/types.go`
- Create: `internal/discover/html.go`
- Create: `internal/discover/html_test.go`
- Create: `internal/discover/javascript.go`
- Create: `internal/discover/javascript_test.go`
- Create: `internal/discover/testdata/spa.html`

**Interfaces:**
- Produces: `discover.Kind` constants `KindScript`, `KindChunk`, `KindEndpoint`, `KindRoute`, and `KindAsset`.
- Produces: `discover.Candidate{Raw string, Kind Kind, SourceURL string, Depth int}`.
- Produces: `discover.SPAEvidence{RootNode, DynamicImport, HistoryRouting, LargeBundle bool}`.
- Produces: `discover.FromHTML(base *url.URL, body []byte) HTMLResult`.
- Produces: `discover.FromJavaScript(source *url.URL, body []byte, engine *analyze.Engine) JSResult`.
- Produces: `HTMLResult.SPA SPAEvidence`.

- [ ] **Step 1: Write failing HTML extraction and SPA evidence tests**

```go
func TestFromHTMLFindsScriptsAndSPA(t *testing.T) {
    got := FromHTML(mustURL("https://e.test/app/"), []byte(`
      <div id="app"></div>
      <script type="module" src="/assets/main.js"></script>
      <link rel="modulepreload" href="//cdn.test/vendor.js">`))
    assertCandidate(t, got.Candidates, "https://e.test/assets/main.js", KindScript)
    assertCandidate(t, got.Candidates, "https://cdn.test/vendor.js", KindScript)
    if !got.SPA.RootNode { t.Fatal("missing SPA root evidence") }
}
```

Test base tags, inline scripts, preload/modulepreload, malformed HTML and duplicate resources.

- [ ] **Step 2: Run focused tests**

Run: `go test ./internal/discover -run 'TestFrom(HTML|JavaScript)' -v`

Expected: FAIL because discoverers do not exist.

- [ ] **Step 3: Implement HTML extraction with goquery**

Parse `base[href]`, `script[src]`, inline scripts, `link[rel=preload|modulepreload]`, `src`, `href`, `action` and meta refresh. Return inline script bodies separately with synthetic source fragments, but canonicalization later removes fragments for network requests.

- [ ] **Step 4: Implement JavaScript discovery**

```go
func FromJavaScript(source *url.URL, body []byte, engine *analyze.Engine) JSResult {
    findings, extracted := engine.Analyze(ResourceRef{
        URL: source.String(), Type: model.ResourceTypeScript,
    }, body)
    return JSResult{
        Findings:   findings,
        Candidates: convertCandidates(source, extracted),
        Signals:    detectSignals(body),
    }
}
```

Signals include `webpackChunk`, dynamic import, `requirejs.config`, history API and dynamic script creation.

Run: `go test ./internal/discover -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/discover
git commit -m "feat: discover resources from HTML and JavaScript"
```

---

### Task 5: Webpack and RequireJS Chunk Resolution

**Files:**
- Create: `internal/discover/webpack.go`
- Create: `internal/discover/webpack_test.go`
- Create: `internal/discover/requirejs.go`
- Create: `internal/discover/requirejs_test.go`
- Create: `internal/discover/testdata/webpack3.js`
- Create: `internal/discover/testdata/webpack5.js`
- Create: `internal/discover/testdata/requirejs.js`

**Interfaces:**
- Consumes: `discover.Candidate`.
- Produces: `discover.FromWebpack(source *url.URL, body []byte, limit int) []Candidate`.
- Produces: `discover.FromRequireJS(source *url.URL, body []byte, limit int) []Candidate`.

- [ ] **Step 1: Write failing fixture tests**

```go
func TestWebpack5ChunkMap(t *testing.T) {
    body := readFixture(t, "webpack5.js")
    got := FromWebpack(mustURL("https://e.test/assets/runtime.js"), body, 100)
    assertCandidate(t, got, "https://e.test/static/js/users.a1b2.js", KindChunk)
}

func TestRequireJSBaseURLAndPaths(t *testing.T) {
    body := readFixture(t, "requirejs.js")
    got := FromRequireJS(mustURL("https://e.test/js/main.js"), body, 100)
    assertCandidate(t, got, "https://e.test/assets/lib/jquery.min.js", KindChunk)
}
```

- [ ] **Step 2: Run focused tests**

Run: `go test ./internal/discover -run 'Test(Webpack|RequireJS)' -v`

Expected: FAIL because resolvers are absent.

- [ ] **Step 3: Implement bounded Webpack extraction**

Extract public path assignments, `.p+"..."`, runtime filename functions, object maps of ID-to-name/hash, `.js` suffixes and dynamic import IDs. Only parse object literals smaller than 2 MiB and cap generated candidates by `maxResources` supplied to the resolver.

```go
func FromWebpack(source *url.URL, body []byte, limit int) []Candidate {
    publicPath := extractPublicPath(source, body)
    maps := extractChunkMaps(body)
    return renderChunkCandidates(source, publicPath, maps, limit)
}
```

- [ ] **Step 4: Implement RequireJS extraction and run tests**

Parse quoted `baseUrl`, `paths` object string values and quoted arrays passed to `define`/`require`. Apply path aliases, preserve absolute URLs, and append `.js` only when no extension exists.

```go
func FromRequireJS(source *url.URL, body []byte, limit int) []Candidate {
    cfg := extractRequireConfig(body)
    modules := extractRequireModules(body)
    return resolveRequireModules(source, cfg, modules, limit)
}
```

Run: `go test ./internal/discover -v`

Expected: PASS for Webpack 3/5, nested source-relative paths and RequireJS fixtures.

- [ ] **Step 5: Commit**

```bash
git add internal/discover
git commit -m "feat: resolve webpack and requirejs chunks"
```

---

### Task 6: surf-Backed Bounded GET Collector

**Files:**
- Create: `internal/collect/types.go`
- Create: `internal/collect/direct/client.go`
- Create: `internal/collect/direct/client_test.go`

**Interfaces:**
- Produces: `collect.Response{URL, StatusCode, Header, Body, Truncated, Duration}`.
- Produces: `collect.Getter` interface with `Get(context.Context, *url.URL, http.Header) (collect.Response, error)`.
- Produces: `direct.New(model.RequestConfig, http.CookieJar) (*Client, error)`.

- [ ] **Step 1: Write failing `httptest` tests**

```go
func TestClientUsesGETHeadersCookiesAndBodyLimit(t *testing.T) {
    // Server asserts r.Method == GET, custom header, UA and cookie.
    // Server writes 32 bytes; client limit is 16.
    got, err := client.Get(ctx, mustURL(server.URL+"/api"), headers)
    if err != nil { t.Fatal(err) }
    if !got.Truncated || len(got.Body) != 16 { t.Fatalf("%+v", got) }
}
```

Add redirect-to-disallowed callback testing, timeout, gzip decoding, retry-on-transport-error only, and context cancellation.

- [ ] **Step 2: Run focused test**

Run: `go test ./internal/collect/direct -v`

Expected: FAIL because direct client is absent.

- [ ] **Step 3: Build surf session and expose bounded standard GET**

```go
surfClient := surf.NewClient().
    Builder().
    Session().
    Build().
    Unwrap()
std := surfClient.Std()
std.Timeout = cfg.Timeout
```

Configure proxy through surf’s builder when present. Build `http.RequestWithContext(ctx, http.MethodGet, u.String(), nil)`, clone headers, read through `io.LimitReader(resp.Body, maxBodySize+1)`, set `Truncated`, and always close the body. Retry only eligible transport failures and never retry after context cancellation.

- [ ] **Step 4: Verify behavior**

Run: `go test ./internal/collect/direct -v`

Run: `go test -race ./internal/collect/direct`

Expected: PASS; test server observes GET only.

- [ ] **Step 5: Commit**

```bash
git add internal/collect
git commit -m "feat: add bounded surf GET collector"
```

---

### Task 7: Bounded Resource Queue and Direct Pipeline

**Files:**
- Create: `internal/scheduler/queue.go`
- Create: `internal/scheduler/queue_test.go`
- Create: `internal/pipeline/pipeline.go`
- Create: `internal/pipeline/pipeline_test.go`
- Create: `scanner.go`
- Create: `scanner_test.go`

**Interfaces:**
- Consumes: `collect.Getter`, `scope.Scope`, `analyze.Engine`, discoverers.
- Produces: `scheduler.New(maxItems, maxDepth, workers int) *Queue`.
- Produces: `pipeline.New(Options) *Pipeline`, `(*Pipeline).Run(ctx context.Context, target model.Target) (*model.Result, error)`.
- Produces: `jsowl.New(Config) (*Scanner, error)` and `(*Scanner).Scan(context.Context, Target) (*Result, error)`.

- [ ] **Step 1: Write failing queue tests**

```go
func TestQueueDedupesAndHonorsDepthAndLimit(t *testing.T) {
    q := New(2, 2, 1)
    if !q.Add(Item{URL:"https://e.test/a.js", Depth:1}) { t.Fatal("first add") }
    if q.Add(Item{URL:"https://e.test/a.js", Depth:1}) { t.Fatal("duplicate added") }
    if !q.Add(Item{URL:"https://e.test/b.js", Depth:2}) { t.Fatal("second add") }
    if q.Add(Item{URL:"https://e.test/c.js", Depth:1}) { t.Fatal("limit ignored") }
    if q.Add(Item{URL:"https://e.test/deep.js", Depth:3}) { t.Fatal("depth ignored") }
}
```

Add cancellation, deterministic completion and no-send-after-close tests under race detection.

- [ ] **Step 2: Write failing direct end-to-end pipeline test**

Create an `httptest.Server` whose HTML references `runtime.js`, whose runtime references `users.hash.js`, and whose chunk contains `fetch('/api/users')` plus a JWT. Assert each URL is requested once, API uses GET, and result includes resource, endpoint and finding.

Run: `go test ./internal/scheduler ./internal/pipeline ./... -run TestDirectPipeline -v`

Expected: FAIL because scheduler/pipeline/scanner are absent.

- [ ] **Step 3: Implement scheduler and pipeline work item flow**

```go
type Item struct {
    URL       *url.URL
    Kind      model.ResourceType
    SourceURL string
    Depth     int
}

type Options struct {
    Getter   collect.Getter
    Scope    *scope.Scope
    Analyzer *analyze.Engine
    Config   model.Config
}
```

For each response: record metadata, optionally retain JS bytes for storage, select analyzer by content type/kind, resolve candidates, enforce scope, enqueue scripts/chunks/endpoints, and append resource errors as `Issue`. A failed entry document is a task error; later resource failures are non-fatal.

- [ ] **Step 4: Implement public scanner and verify**

`New` validates config and compiles rules. `Scan` normalizes the target, selects one UA, merges headers, creates a target timeout, a fresh cookie jar/scope/queue, runs direct pipeline, finalizes statistics and stable-sorts all slices.

Run: `go test -race ./...`

Expected: PASS including direct end-to-end test.

- [ ] **Step 5: Commit**

```bash
git add scanner.go scanner_test.go internal/scheduler internal/pipeline
git commit -m "feat: add bounded direct scan pipeline"
```

---

### Task 8: Rod Collector, Injected Resource Script, and Browser Check

**Files:**
- Create: `internal/collect/browser/assets/collect_resource_urls.js`
- Create: `internal/collect/browser/browser.go`
- Create: `internal/collect/browser/browser_test.go`
- Create: `internal/collect/browser/check.go`
- Create: `internal/collect/browser/check_test.go`
- Create: `internal/collect/browser/testdata/dynamic.html`

**Interfaces:**
- Produces: `browser.New(model.BrowserConfig) (*Collector, error)`.
- Produces: `(*Collector).Collect(ctx context.Context, target *url.URL, headers http.Header) (collect.BrowserResult, error)`.
- Produces: `browser.Check(ctx context.Context, BrowserConfig) CheckResult`.
- Produces embedded collector API `window.__jsowlCollector.snapshot()`.

- [ ] **Step 1: Write failing injected collector contract test**

Use Rod integration only when `launcher.LookPath()` finds a local browser; otherwise call `t.Skip`. Serve a page that waits 100 ms, runs fetch, XHR and dynamically assigns `script.src`. Assert snapshot includes all relative URLs resolved against document URL.

```go
func TestCollectorCapturesDelayedResources(t *testing.T) {
    bin, found := launcher.LookPath()
    if !found { t.Skip("Chrome/Chromium not installed") }
    // Collect with Wait=200ms and assert /fetch, /xhr, /late.js.
}
```

- [ ] **Step 2: Implement enhanced embedded JavaScript**

```javascript
(() => {
  if (window.__jsowlCollector) return;
  const urls = new Set();
  const add = value => {
    try {
      const raw = value instanceof Request ? value.url : String(value || "");
      if (raw) urls.add(new URL(raw, document.baseURI).href);
    } catch (_) {}
  };
  const originalFetch = window.fetch;
  window.fetch = function(input) { add(input); return originalFetch.apply(this, arguments); };
  const originalOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(method, url) {
    add(url); return originalOpen.apply(this, arguments);
  };
  new MutationObserver(records => records.forEach(record =>
    record.addedNodes.forEach(node => {
      if (node && node.querySelectorAll) {
        if (node.src || node.href) add(node.src || node.href);
        node.querySelectorAll("[src],[href]").forEach(el => add(el.src || el.href));
      }
    })
  )).observe(document, {subtree:true, childList:true});
  window.__jsowlCollector = {
    snapshot() {
      document.querySelectorAll("[src],[href]").forEach(el => add(el.src || el.href));
      performance.getEntriesByType("resource").forEach(entry => add(entry.name));
      return Array.from(urls);
    }
  };
})();
```

The Go collector loads an external configured script or the embedded script and calls `EvalOnNewDocument` before navigation.

- [ ] **Step 3: Implement Rod lifecycle and waiting**

Launch with configured binary and headless setting, never `launcher.NewBrowser()`. Connect through Rod, set target UA/headers, register CDP network response events, navigate, wait for load, wait for request idle for `Browser.Idle`, then wait exactly `Browser.Wait` unless context expires. Snapshot DOM and collector URLs, merge with CDP URLs, and close page/browser in defers.

Avoid `Must*` APIs in library code; return typed stage errors.

- [ ] **Step 4: Implement browser checker and tests**

`Check` validates configured/discovered binary, version, launch, CDP, blank page, injection and snapshot. It returns ordered checks with name, success and error. It does not access an external URL and does not download a browser.

Run: `go test ./internal/collect/browser -v`

Expected: PASS or integration tests SKIP only when no local browser exists.

- [ ] **Step 5: Commit**

```bash
git add internal/collect/browser
git commit -m "feat: collect SPA resources with Rod"
```

---

### Task 9: Auto Mode, Browser Merge, and Batch Scanning

**Files:**
- Modify: `scanner.go`
- Modify: `scanner_test.go`
- Modify: `internal/pipeline/pipeline.go`
- Modify: `internal/pipeline/pipeline_test.go`

**Interfaces:**
- Consumes: browser collector from Task 8.
- Produces: `(*Scanner).ScanBatch(context.Context, []Target) <-chan BatchItem`.
- Produces: deterministic `BrowserStatus{Attempted, Used, Degraded, Reason}`.

- [ ] **Step 1: Write failing mode-selection tests with fake browser**

```go
func TestAutoUsesBrowserForSPAAndDegradesCleanly(t *testing.T) {
    fake := &fakeBrowser{err: errors.New("chrome missing")}
    scanner := newTestScanner(t, Config{Mode: ModeAuto}, withBrowser(fake))
    result, err := scanner.Scan(ctx, spaTarget)
    if err != nil { t.Fatal(err) }
    if !result.BrowserStatus.Degraded { t.Fatal("expected degradation") }
    if len(result.Resources) == 0 { t.Fatal("surf result was lost") }
}
```

Test direct never calls browser, browser mode returns browser failure as task error, and successful browser results merge without duplicates.

- [ ] **Step 2: Write failing bounded batch test**

Use an atomic counter fake pipeline and assert maximum simultaneous targets equals `Concurrency.Targets`; cancel the context and assert the output channel closes.

- [ ] **Step 3: Implement SPA decision and browser merge**

```go
func needsBrowser(e discover.SPAEvidence, result *model.Result) bool {
    return e.RootNode || e.DynamicImport || e.HistoryRouting ||
        (e.LargeBundle && len(result.Endpoints) == 0)
}
```

Feed browser DOM and discovered script/network URLs back into the same target pipeline and shared canonical URL dedupe set.

- [ ] **Step 4: Implement batch workers and verify**

Create exactly `min(targets, cfg.Concurrency.Targets)` workers, send one `BatchItem` per input target, preserve each target’s isolation, and close output after workers finish.

Run: `go test -race ./...`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add scanner.go scanner_test.go internal/pipeline
git commit -m "feat: add auto browser fallback and batch scans"
```

---

### Task 10: Optional JS Storage and JSON/HTML Reports

**Files:**
- Create: `internal/storage/js.go`
- Create: `internal/storage/js_test.go`
- Create: `internal/report/json.go`
- Create: `internal/report/json_test.go`
- Create: `internal/report/html.go`
- Create: `internal/report/html_test.go`
- Create: `internal/report/assets/report.html`
- Modify: `internal/pipeline/pipeline.go`
- Modify: `result.go`

**Interfaces:**
- Produces: `storage.SaveJS(root string, target *url.URL, resource model.Resource, body []byte) (relative string, error)`.
- Produces: `report.WriteJSON(path string, result *model.Result) error`.
- Produces: `report.WriteHTML(path string, result *model.Result) error`.

- [ ] **Step 1: Write failing storage safety tests**

Test Windows-invalid characters, query collisions, identical content dedupe, JS-only enforcement, size limit, disabled mode and containment under `<output>/<host>/js`.

```go
func TestSaveJSStaysUnderTargetDirectory(t *testing.T) {
    rel, err := SaveJS(t.TempDir(), mustURL("https://e.test"),
        resource("https://e.test/../../CON?.js?x=1"), []byte("x"))
    if err != nil { t.Fatal(err) }
    if filepath.IsAbs(rel) || strings.Contains(rel, "..") { t.Fatal(rel) }
}
```

- [ ] **Step 2: Write failing report tests**

Assert JSON round-trips the public result. Assert HTML contains the target, full test secret, API status, degradation reason and Chinese sensitive-data warning, but not the complete stored response body.

- [ ] **Step 3: Implement atomic storage and JSON**

Write to a sibling temporary file, `Sync`, close, then rename. Derive stable filenames from sanitized path plus an 8-character xxhash of canonical URL when collision is possible. Store only script/chunk bodies when enabled.

- [ ] **Step 4: Implement self-contained HTML**

Embed one template containing inline CSS and vanilla JS filters. Escape all target-controlled content with `html/template`; never use `template.HTML` for findings. Include summary cards, resource/endpoint/finding tables, severity/category filters, issues and sensitive-data warning.

Run: `go test ./internal/storage ./internal/report ./internal/pipeline -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add result.go internal/storage internal/report internal/pipeline
git commit -m "feat: write JS artifacts and security reports"
```

---

### Task 11: Compact No-Subcommand CLI and `--check`

**Files:**
- Create: `cmd/jsowl/main.go`
- Create: `cmd/jsowl/root.go`
- Create: `cmd/jsowl/root_test.go`
- Modify: `config.go`

**Interfaces:**
- Produces: `newRootCommand(deps dependencies) *cobra.Command`.
- Produces: `parseHeader(string) (name, value string, err error)`.
- Consumes: public scanner, reporters and browser checker.

- [ ] **Step 1: Write failing CLI parsing tests**

```go
func TestRootFlagsOverrideConfig(t *testing.T) {
    cmd := newRootCommand(fakeDeps())
    cmd.SetArgs([]string{
        "-u", "https://e.test", "-m", "direct", "-t", "32",
        "-H", "Authorization: Bearer abc",
    })
    if err := cmd.Execute(); err != nil { t.Fatal(err) }
    got := fakeDeps().captured
    assertEqual(t, got.Mode, jsowl.ModeDirect)
    assertEqual(t, got.Concurrency.ResourcesPerTarget, 32)
    assertEqual(t, got.Header.Get("Authorization"), "Bearer abc")
}
```

Test repeatable URLs, list files with blank/comment lines, `-u` plus `-l`, invalid header, `--check`, `-v`, missing targets, explicit missing config, and automatic optional `./config.yml`.

- [ ] **Step 2: Run focused test**

Run: `go test ./cmd/jsowl -v`

Expected: FAIL because command files are absent.

- [ ] **Step 3: Implement root-only Cobra command**

Set `Args: cobra.NoArgs`, do not add child commands, and bind:

```go
flags.StringArrayVarP(&opts.urls, "url", "u", nil, "target URL (repeatable)")
flags.StringVarP(&opts.list, "list", "l", "", "file containing target URLs")
flags.StringVarP(&opts.config, "config", "c", "", "YAML configuration file")
flags.StringVarP(&opts.output, "output", "o", "", "report output directory")
flags.StringVarP(&opts.mode, "mode", "m", "", "auto, direct, or browser")
flags.StringArrayVarP(&opts.headers, "header", "H", nil, "request header Name: value")
flags.IntVarP(&opts.threads, "threads", "t", 0, "per-target resource concurrency")
flags.BoolVarP(&opts.version, "version", "v", false, "print version")
flags.BoolVar(&opts.check, "check", false, "check config, rules, and browser")
```

Apply only changed CLI values over loaded YAML. `-H` merges case-insensitively and CLI values replace YAML values.

- [ ] **Step 4: Implement execution and verify**

Create output directories, stream batch completion summaries, write one JSON/HTML pair per target, return non-zero when any target has a task error, and keep partial reports for successful targets. `--check` runs without target input and returns non-zero when a required check fails.

Run: `go test ./cmd/jsowl -v`

Run: `go run ./cmd/jsowl -h`

Expected: tests PASS and help lists flags directly with no commands section.

- [ ] **Step 5: Commit**

```bash
git add cmd/jsowl config.go
git commit -m "feat: add compact JsOwl CLI"
```

---

### Task 12: End-to-End Fixtures, Documentation, Race Tests, and Benchmarks

**Files:**
- Create: `testdata/site/index.html`
- Create: `testdata/site/runtime.js`
- Create: `testdata/site/chunk-users.js`
- Create: `e2e_test.go`
- Create: `benchmark_test.go`
- Create: `README.md`
- Create: `examples/library/main.go`
- Modify: `config.example.yml`

**Interfaces:**
- Verifies all public interfaces and completion criteria.
- Produces documented stable library and CLI examples.

- [ ] **Step 1: Add failing end-to-end acceptance test**

Build an `httptest.Server` with entry HTML, runtime, nested chunk and JSON API. The API returns another path and a test credential. Run public `Scanner.Scan` in direct mode and assert:

```go
if got := result.Statistics.Chunks; got != 1 { t.Fatalf("chunks=%d", got) }
assertEndpoint(t, result, "/api/users", http.StatusOK)
assertFinding(t, result, "secret.jwt")
assertStableSorted(t, result)
```

Also run the CLI binary against the fixture in a subprocess and verify report filenames and exit code.

- [ ] **Step 2: Add benchmarks**

```go
func BenchmarkAnalyzeLargeBundle(b *testing.B) {
    body := bytes.Repeat([]byte(`fetch("/api/users");const token="x";`), 10000)
    engine := mustEngine(b)
    b.ReportAllocs()
    for i := 0; i < b.N; i++ {
        engine.Analyze(ref("https://e.test/app.js"), body)
    }
}
```

Add URL canonicalization/dedupe and 100-target fake batch benchmarks.

- [ ] **Step 3: Write README and library example**

Document:

- Authorized-use notice.
- Install/build commands.
- Root-only CLI examples for every flag.
- YAML schema and defaults.
- direct/browser/auto behavior.
- Chrome is never auto-downloaded.
- Browser wait defaults to 3 seconds.
- Cross-origin script/API scope.
- Full-sensitive-value report warning.
- `download_js`.
- Public single and batch Go examples.

The example must compile with `go test ./examples/library`.

- [ ] **Step 4: Run complete verification**

Run: `gofmt -w .`

Run: `go mod tidy`

Run: `go test ./...`

Run: `go test -race ./...`

Run: `go vet ./...`

Run: `go test -run '^$' -bench 'Benchmark(AnalyzeLargeBundle|Canonical|Batch)' -benchmem ./...`

Expected: all commands exit 0; Rod integration may report SKIP only when no local browser is installed.

- [ ] **Step 5: Commit**

```bash
git add README.md config.example.yml testdata e2e_test.go benchmark_test.go examples go.mod go.sum
git commit -m "test: verify JsOwl end-to-end workflow"
```

---

## Final Verification

- [ ] Run `git status --short` and verify only intentionally untracked local files remain.
- [ ] Run `go test ./...`, `go test -race ./...`, and `go vet ./...` once more from repository root.
- [ ] Run `go run ./cmd/jsowl --check -c config.example.yml`; browser absence is reported clearly without a download attempt.
- [ ] Run a direct fixture scan and inspect both JSON and HTML reports.
- [ ] Compare every requirement in `docs/superpowers/specs/2026-07-26-jsowl-design.md` with Tasks 1–12.

## Spec Coverage Map

| Design sections | Implemented by |
|---|---|
| 1–3 goals, architecture, modes | Tasks 1, 7, 9 |
| 4 Rod waiting and injected collection | Task 8 |
| 5 HTML/JS/chunk discovery | Tasks 3–5, 7 |
| 6 scope and API GET | Tasks 2, 6, 7 |
| 7 rules | Task 3 |
| 8 public Go API | Tasks 1, 7, 9 |
| 9 CLI | Task 11 |
| 10 YAML configuration | Tasks 1, 11 |
| 11 random per-target UA | Tasks 1, 7, 8 |
| 12 JS download | Task 10 |
| 13 browser/config/rule check | Tasks 8, 11 |
| 14 reports | Task 10 |
| 15 errors and degradation | Tasks 6–9 |
| 16 package structure | Tasks 1–12 |
| 17 dependencies | Task 1 |
| 18 performance bounds | Tasks 6, 7, 9, 12 |
| 19 tests | Every task, consolidated in Task 12 |
| 20 completion criteria | Task 12 and Final Verification |
