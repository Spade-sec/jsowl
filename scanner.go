package jsowl

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/youmulijiang/jsowl/internal/analyze"
	"github.com/youmulijiang/jsowl/internal/aiclient"
	"github.com/youmulijiang/jsowl/internal/collect"
	"github.com/youmulijiang/jsowl/internal/collect/browser"
	"github.com/youmulijiang/jsowl/internal/collect/direct"
	"github.com/youmulijiang/jsowl/internal/discover"
	"github.com/youmulijiang/jsowl/internal/model"
	"github.com/youmulijiang/jsowl/internal/pipeline"
	"github.com/youmulijiang/jsowl/internal/ua"
)

// Scanner owns immutable scan configuration and a compiled extraction engine.
type Scanner struct {
	config         model.Config
	analyzer       *analyze.Engine
	browserFactory func(model.BrowserConfig) (collect.BrowserCollector, error)
	probeSink      chan<- model.ProbeEvent
}

// SetProbeSink registers a channel that receives one event per completed API
// probe while scans run. Events are sent non-blockingly; a slow consumer
// drops events, and the final report always contains every probe result.
// Pass nil to detach the sink.
func (s *Scanner) SetProbeSink(sink chan<- ProbeEvent) {
	s.probeSink = sink
}

// New validates configuration and constructs a reusable Scanner.
func New(config Config) (*Scanner, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	ownedConfig := cloneConfig(config)
	engine, err := analyze.New(
		ownedConfig.Rules.Custom,
		ownedConfig.Rules.Disabled,
	)
	if err != nil {
		return nil, err
	}
	return &Scanner{
		config: ownedConfig, analyzer: engine, browserFactory: func(
			config model.BrowserConfig,
		) (collect.BrowserCollector, error) {
			return browser.New(config, ownedConfig.Request)
		},
	}, nil
}

func cloneConfig(config model.Config) model.Config {
	cloned := config
	cloned.Request.Headers = make(
		map[string]string, len(config.Request.Headers),
	)
	for name, value := range config.Request.Headers {
		cloned.Request.Headers[name] = value
	}
	cloned.Request.Cookies = make(
		map[string]string, len(config.Request.Cookies),
	)
	for name, value := range config.Request.Cookies {
		cloned.Request.Cookies[name] = value
	}
	cloned.Scope.AllowDomains = append(
		[]string(nil), config.Scope.AllowDomains...,
	)
	cloned.Scope.RestrictDomains = append(
		[]string(nil), config.Scope.RestrictDomains...,
	)
	cloned.Scope.SuffixBlacklist = append(
		[]string(nil), config.Scope.SuffixBlacklist...,
	)
	cloned.Rules.Disabled = append(
		[]string(nil), config.Rules.Disabled...,
	)
	cloned.Rules.Custom = append([]model.Rule(nil), config.Rules.Custom...)
	return cloned
}

// Scan executes an isolated scan for one target and returns partial diagnostics on failure.
func (s *Scanner) Scan(ctx context.Context, target Target) (*Result, error) {
	root, err := url.Parse(target.URL)
	if err != nil {
		return nil, fmt.Errorf("parse target URL: %w", err)
	}

	headers := make(http.Header)
	for name, value := range s.config.Request.Headers {
		headers.Set(name, value)
	}
	for name, values := range target.Headers {
		headers.Del(name)
		for _, value := range values {
			headers.Add(name, value)
		}
	}
	userAgent, err := ua.ForTarget(s.config.Request.UserAgent, headers, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("select User-Agent: %w", err)
	}
	headers.Set("User-Agent", userAgent)

	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("create cookie jar: %w", err)
	}
	cookies := make([]*http.Cookie, 0, len(s.config.Request.Cookies)+len(target.Cookies))
	for name, value := range s.config.Request.Cookies {
		cookies = append(cookies, &http.Cookie{Name: name, Value: value})
	}
	cookies = append(cookies, target.Cookies...)
	jar.SetCookies(root, cookies)

	client, err := direct.New(
		s.config.Request,
		s.config.Limits.MaxBodySize,
		jar,
	)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	targetContext, cancel := context.WithTimeout(ctx, s.config.Request.TargetTimeout)
	defer cancel()
	started := time.Now()
	resourcePipeline := pipeline.New(pipeline.Options{
		Getter: client, Analyzer: s.analyzer, Config: s.config,
		ProbeEvents: s.probeSink,
	})
	// AI assist layer (-ai): the three enrichers share one client and one
	// request budget. Without -ai they stay nil and the pipeline no-ops.
	if s.config.AI.Enabled {
		aiClient := aiclient.New(
			s.config.AI.BaseURL, s.config.AI.APIKey, s.config.AI.Model, s.config.AI.Format,
		)
		templateAI, taintAI, findingAI := analyze.NewAIThird(aiClient, s.config.AI.MaxRequests)
		resourcePipeline.SetEnrichers(templateAI, taintAI, findingAI)
	}
	var result *model.Result
	switch s.config.Mode {
	case ModeDirect:
		result, _, err = resourcePipeline.RunDetailed(
			targetContext, target, headers, nil, nil, nil,
		)
	case ModeBrowser:
		result, err = s.scanWithBrowser(
			targetContext, root, target, headers, jar, resourcePipeline, nil,
		)
	case ModeAuto:
		var evidence discover.SPAEvidence
		result, evidence, err = resourcePipeline.RunDetailed(
			targetContext, target, headers, nil, nil, nil,
		)
		if err == nil && needsBrowser(evidence, result) {
			var browserResult *model.Result
			browserResult, err = s.scanWithBrowser(
				targetContext, root, target, headers, jar, resourcePipeline,
				collectedURLs(result),
			)
			if err != nil {
				if contextErr := targetContext.Err(); contextErr != nil {
					err = contextErr
				} else {
					result.BrowserStatus = model.BrowserStatus{
						Attempted: true,
						Degraded:  true,
						Reason:    err.Error(),
					}
					err = nil
				}
			} else {
				result = mergeResults(result, browserResult)
				result.BrowserStatus = model.BrowserStatus{
					Attempted: true, Used: true,
				}
			}
		}
	}
	if result != nil {
		normalizeHashRoutes(result)
		// The browser pass merges endpoints after the pipeline already
		// finalized its counts; refresh them so the report header matches
		// the rows it renders.
		pipeline.Finalize(result)
		result.StartedAt = started
		result.FinishedAt = time.Now()
		result.UserAgent = userAgent
	}
	return result, err
}

// normalizeHashRoutes rewrites framework routes into their hash-router form
// once any route proves the app keeps its routes after "#". Vue 2 routers
// default to hash mode, so the router table alone ("/404") cannot tell; the
// runtime observation can. Runs after merging so the direct pass, which
// precedes the browser pass, is covered too.
func normalizeHashRoutes(result *model.Result) {
	hashMode := false
	for _, endpoint := range result.Endpoints {
		if endpoint.Type == "route" && strings.Contains(endpoint.URL, "#") {
			hashMode = true
			break
		}
	}
	if !hashMode {
		return
	}
	seen := make(map[string]struct{}, len(result.Endpoints))
	kept := result.Endpoints[:0]
	for _, endpoint := range result.Endpoints {
		if endpoint.Type == "route" && !strings.Contains(endpoint.URL, "#") {
			if parsed, err := url.Parse(endpoint.URL); err == nil &&
				parsed.Host != "" {
				rewritten := hashRouteURL(parsed)
				endpoint.URL = rewritten
				endpoint.Raw = rewritten
			}
		}
		if _, duplicate := seen[endpoint.URL]; duplicate {
			continue
		}
		seen[endpoint.URL] = struct{}{}
		kept = append(kept, endpoint)
	}
	result.Endpoints = kept
}

// hashRouteURL renders a path in hash-router form: a hash-mode SPA serves one
// document and keeps the route after "#", so "/login" is really "/#/login".
func hashRouteURL(resolved *url.URL) string {
	base := *resolved
	fragment := base.Path
	if base.RawQuery != "" {
		fragment += "?" + base.RawQuery
	}
	base.Path = "/"
	base.RawPath = ""
	base.RawQuery = ""
	base.Fragment = ""
	base.RawFragment = ""
	return base.String() + "#" + fragment
}

// ScanBatch scans targets with a fixed worker count and closes the returned
// channel after all started work completes or the context is cancelled.
func (s *Scanner) ScanBatch(
	ctx context.Context,
	targets []Target,
) <-chan BatchItem {
	output := make(chan BatchItem)
	go func() {
		defer close(output)
		if len(targets) == 0 {
			return
		}
		workers := min(len(targets), s.config.Concurrency.Targets)
		jobs := make(chan Target)
		var wait sync.WaitGroup
		wait.Add(workers)
		for range workers {
			go func() {
				defer wait.Done()
				for target := range jobs {
					result, err := s.Scan(ctx, target)
					select {
					case output <- BatchItem{Target: target, Result: result, Err: err}:
					case <-ctx.Done():
						return
					}
				}
			}()
		}
		for _, target := range targets {
			select {
			case jobs <- target:
			case <-ctx.Done():
				close(jobs)
				wait.Wait()
				return
			}
		}
		close(jobs)
		wait.Wait()
	}()
	return output
}

func (s *Scanner) scanWithBrowser(
	ctx context.Context,
	root *url.URL,
	target model.Target,
	headers http.Header,
	jar http.CookieJar,
	resourcePipeline *pipeline.Pipeline,
	previouslySeen []string,
) (*model.Result, error) {
	collector, err := s.browserFactory(s.config.Browser)
	if err != nil {
		return nil, fmt.Errorf("create browser collector: %w", err)
	}
	browserHeaders := headers.Clone()
	if cookieHeader := serializeCookies(jar.Cookies(root)); cookieHeader != "" {
		browserHeaders.Set("Cookie", cookieHeader)
	}
	rendered, err := collector.Collect(ctx, root, browserHeaders)
	if err != nil {
		return nil, fmt.Errorf("collect browser page: %w", err)
	}
	jar.SetCookies(root, rendered.Cookies)
	entry := collect.Response{
		URL: root.String(), StatusCode: http.StatusOK,
		Header: http.Header{"Content-Type": {"text/html; charset=utf-8"}},
		Body:   rendered.HTML,
	}
	seeds := browserSeeds(root, rendered)
	result, _, err := resourcePipeline.RunDetailed(
		ctx, target, headers, &entry, seeds, previouslySeen,
	)
	if result != nil {
		result.BrowserStatus = model.BrowserStatus{Attempted: true, Used: true}
	}
	return result, err
}

func serializeCookies(cookies []*http.Cookie) string {
	parts := make([]string, 0, len(cookies))
	for _, cookie := range cookies {
		if cookie == nil || cookie.Name == "" {
			continue
		}
		parts = append(parts, cookie.Name+"="+cookie.Value)
	}
	return strings.Join(parts, "; ")
}

func collectedURLs(result *model.Result) []string {
	urls := make([]string, 0, len(result.Resources))
	for _, resource := range result.Resources {
		urls = append(urls, resource.URL)
	}
	return urls
}

func needsBrowser(evidence discover.SPAEvidence, result *model.Result) bool {
	return evidence.RootNode || evidence.DynamicImport ||
		evidence.HistoryRouting || evidence.DynamicScript ||
		(evidence.LargeBundle && len(result.Endpoints) == 0)
}

func browserSeeds(root *url.URL, rendered collect.BrowserResult) []pipeline.Seed {
	seen := make(map[string]pipeline.Seed)
	addSeed := func(raw string, kind model.ResourceType, record collect.NetworkRecord) {
		if _, exists := seen[raw]; !exists {
			seed := pipeline.Seed{
				URL: raw, Kind: kind,
				Evidence:     model.EvidenceRuntime,
				Method:       record.Method,
				InitiatorURL: record.InitiatorURL,
				Line:         record.Line,
				Column:       record.Column,
				Source:       "cdp",
			}
			if kind == model.ResourceTypeAPI {
				seed.Spec = collect.ParseRequestPayload(
					record.Method, record.URL, record.PostData, record.ContentType)
			}
			seen[raw] = seed
		}
	}
	for _, record := range rendered.Network {
		kind := model.ResourceType("")
		switch strings.ToLower(record.ResourceType) {
		case "script":
			kind = model.ResourceTypeScript
		case "xhr", "fetch", "beacon", "ping", "eventsource", "websocket", "preflight":
			// Every request the page actually issued is an interface worth
			// recording, not just XHR and fetch.
			kind = model.ResourceTypeAPI
		}
		if kind == "" && strings.Contains(
			strings.ToLower(record.ContentType), "javascript",
		) {
			kind = model.ResourceTypeScript
		}
		if kind != "" {
			addSeed(record.URL, kind, record)
		}
	}
	// Scripts the injected collector classified explicitly keep their script
	// kind even when the URL carries no .js extension.
	for _, raw := range rendered.Scripts {
		addSeed(raw, model.ResourceTypeScript, collect.NetworkRecord{})
	}
	for _, raw := range rendered.URLs {
		parsed, err := url.Parse(raw)
		if err == nil && isJavaScriptExtension(parsed.Path) {
			addSeed(raw, model.ResourceTypeScript, collect.NetworkRecord{})
		}
	}
	for _, route := range rendered.Routes {
		if route.Path == "" {
			continue
		}
		reference, err := url.Parse(route.Path)
		if err != nil {
			continue
		}
		resolved := reference
		if !resolved.IsAbs() {
			// ResolveReference keeps an embedded query intact; JoinPath
			// would percent-encode it ("?a=b" → "%3Fa=b").
			resolved = root.ResolveReference(reference)
		}
		path := resolved.String()
		if _, exists := seen[path]; exists {
			continue
		}
		seen[path] = pipeline.Seed{
			URL: path, Kind: model.ResourceTypeRoute,
			Evidence: model.EvidenceRuntime, Source: "cdp-runtime",
			InitiatorURL: "vue:" + route.Name + ":" + route.Source,
		}
	}
	seeds := make([]pipeline.Seed, 0, len(seen))
	for _, seed := range seen {
		seeds = append(seeds, seed)
	}
	sort.Slice(seeds, func(i, j int) bool { return seeds[i].URL < seeds[j].URL })
	return seeds
}

func isJavaScriptExtension(value string) bool {
	switch strings.ToLower(path.Ext(value)) {
	case ".js", ".mjs", ".jsx", ".ts", ".tsx":
		return true
	default:
		return false
	}
}

func mergeResults(primary, secondary *model.Result) *model.Result {
	resourceSeen := make(map[string]struct{}, len(primary.Resources))
	for _, resource := range primary.Resources {
		resourceSeen[resource.URL] = struct{}{}
	}
	for _, resource := range secondary.Resources {
		if _, duplicate := resourceSeen[resource.URL]; duplicate {
			continue
		}
		resourceSeen[resource.URL] = struct{}{}
		primary.Resources = append(primary.Resources, resource)
	}

	endpointIndex := make(map[string]int, len(primary.Endpoints))
	for index, endpoint := range primary.Endpoints {
		endpointIndex[endpoint.URL] = index
	}
	for _, endpoint := range secondary.Endpoints {
		if index, duplicate := endpointIndex[endpoint.URL]; duplicate {
			if endpoint.StatusCode != 0 {
				primary.Endpoints[index].StatusCode = endpoint.StatusCode
			}
			// Runtime observation outranks static extraction.
			if endpoint.Evidence == model.EvidenceRuntime &&
				primary.Endpoints[index].Evidence != model.EvidenceRuntime {
				primary.Endpoints[index].Evidence = endpoint.Evidence
				primary.Endpoints[index].Method = endpoint.Method
				primary.Endpoints[index].SourceURL = endpoint.SourceURL
				primary.Endpoints[index].Line = endpoint.Line
				primary.Endpoints[index].Column = endpoint.Column
			}
			continue
		}
		endpointIndex[endpoint.URL] = len(primary.Endpoints)
		primary.Endpoints = append(primary.Endpoints, endpoint)
	}

	findingSeen := make(map[string]struct{}, len(primary.Findings))
	for _, finding := range primary.Findings {
		findingSeen[findingKey(finding)] = struct{}{}
	}
	for _, finding := range secondary.Findings {
		key := findingKey(finding)
		if _, duplicate := findingSeen[key]; duplicate {
			continue
		}
		findingSeen[key] = struct{}{}
		primary.Findings = append(primary.Findings, finding)
	}
	technologySeen := make(map[string]struct{}, len(primary.Technologies))
	for _, technology := range primary.Technologies {
		technologySeen[technology] = struct{}{}
	}
	for _, technology := range secondary.Technologies {
		if _, duplicate := technologySeen[technology]; duplicate {
			continue
		}
		technologySeen[technology] = struct{}{}
		primary.Technologies = append(primary.Technologies, technology)
	}
	sort.Strings(primary.Technologies)
	primary.Issues = append(primary.Issues, secondary.Issues...)
	sort.Slice(primary.Resources, func(i, j int) bool {
		return primary.Resources[i].URL < primary.Resources[j].URL
	})
	sort.Slice(primary.Endpoints, func(i, j int) bool {
		return primary.Endpoints[i].URL < primary.Endpoints[j].URL
	})
	sort.Slice(primary.Findings, func(i, j int) bool {
		if primary.Findings[i].SourceURL != primary.Findings[j].SourceURL {
			return primary.Findings[i].SourceURL < primary.Findings[j].SourceURL
		}
		return primary.Findings[i].RuleID < primary.Findings[j].RuleID
	})
	recalculateStatistics(primary)
	return primary
}

func findingKey(finding model.Finding) string {
	return finding.RuleID + "\x00" + finding.SourceURL + "\x00" + finding.Value
}

func recalculateStatistics(result *model.Result) {
	result.Statistics = model.Statistics{
		Resources: len(result.Resources),
		Endpoints: len(result.Endpoints),
		Findings:  len(result.Findings),
	}
	for _, resource := range result.Resources {
		switch resource.Type {
		case model.ResourceTypeScript:
			result.Statistics.Scripts++
		case model.ResourceTypeChunk:
			result.Statistics.Chunks++
		}
	}
}
