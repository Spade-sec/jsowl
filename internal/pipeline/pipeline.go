package pipeline

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/youmulijiang/jsowl/internal/analyze"
	"github.com/youmulijiang/jsowl/internal/collect"
	"github.com/youmulijiang/jsowl/internal/discover"
	"github.com/youmulijiang/jsowl/internal/model"
	"github.com/youmulijiang/jsowl/internal/scheduler"
	"github.com/youmulijiang/jsowl/internal/scope"
	"github.com/youmulijiang/jsowl/internal/storage"
)

// Options supplies the immutable dependencies for one target pipeline.
type Options struct {
	Getter   collect.Getter
	Analyzer *analyze.Engine
	Config   model.Config
	// ProbeEvents, when non-nil, receives one event per completed API probe.
	// The pipeline never blocks on it; consumers must keep up or drop events.
	ProbeEvents chan<- model.ProbeEvent
}

// Pipeline recursively collects and analyzes one target within configured bounds.
type Pipeline struct {
	options Options
}

// Seed describes one browser-observed URL to feed into the shared pipeline.
type Seed struct {
	URL  string
	Kind model.ResourceType
	// Evidence, Method and initiator position come from runtime observation
	// (CDP) and mark the resulting endpoint as confirmed.
	Evidence     string
	Method       string
	InitiatorURL string
	Line         int
	Column       int
	// Source records the extractor: cdp for runtime seeds.
	Source string
	// Spec carries runtime-observed query/body parameters from the request
	// payload CDP captured for this seed.
	Spec *model.RequestSpec
}

type outcome struct {
	item       scheduler.Item
	response   collect.Response
	err        error
	findings   []model.Finding
	candidates []discover.Candidate
	spa        discover.SPAEvidence
	// vendor marks the body as a third-party library bundle.
	vendor bool
}

// runState carries the mutable state shared by the collection drains and the
// deferred JavaScript analysis phase.
type runState struct {
	result         *model.Result
	queue          *scheduler.Queue
	endpointIndex  map[string]int
	findingSeen    map[string]struct{}
	spa            *discover.SPAEvidence
	pending        []deferredJS
	deferJS        bool
	targetScope    *scope.Scope
	root           *url.URL
	resolutionBase *url.URL
	probeEvents    chan<- model.ProbeEvent
}

// emitProbe publishes one completed API probe without ever blocking the scan:
// when no consumer is attached or the consumer is slower than the producers,
// the event is dropped. Probes are recorded in the final report regardless.
func (state *runState) emitProbe(event model.ProbeEvent) {
	if state.probeEvents == nil {
		return
	}
	select {
	case state.probeEvents <- event:
	default:
	}
}

// deferredJS is one downloaded script or chunk waiting for the regex and AST
// analysis pass that runs after collection completes. Fetch-first mode
// persists the body to disk first and analyzes from the saved file; when the
// save is skipped or fails (truncated body, storage error) the in-memory
// body is carried as a fallback so no resource is ever dropped.
type deferredJS struct {
	source *url.URL
	path   string
	body   []byte
	depth  int
	vendor bool
}

// New constructs a direct resource pipeline.
func New(options Options) *Pipeline {
	return &Pipeline{options: options}
}

// Run collects the entry document and all authorized resources discovered from it.
func (p *Pipeline) Run(
	ctx context.Context,
	target model.Target,
	headers http.Header,
) (*model.Result, error) {
	result, _, err := p.RunDetailed(ctx, target, headers, nil, nil, nil)
	return result, err
}

// maxDiscoveryCandidates bounds one webpack/RequireJS discovery pass when no
// resource cap is configured; those extractors need a positive limit.
const maxDiscoveryCandidates = 200000

// candidateLimit is the per-pass discovery ceiling. A zero resource cap means
// "no limit", so discovery gets a large ceiling instead of returning nothing.
func (p *Pipeline) candidateLimit() int {
	if limit := p.options.Config.Limits.MaxResources; limit > 0 {
		return limit
	}
	return maxDiscoveryCandidates
}

// sourceMapAllowed reports whether a map URL may be fetched: the feature must
// be enabled and the path must not match the library blacklist.
func (p *Pipeline) sourceMapAllowed(candidate *url.URL) bool {
	if !p.options.Config.Scope.ProbeSourceMaps || candidate == nil {
		return false
	}
	path := strings.ToLower(candidate.Path)
	for _, fragment := range p.options.Config.Scope.SourceMapBlacklist {
		fragment = strings.ToLower(strings.TrimSpace(fragment))
		if fragment != "" && strings.Contains(path, fragment) {
			return false
		}
	}
	return true
}

// markVendor labels everything extracted from one body between the two marks
// as vendor code, so the report can separate library noise from application
// results when skip_library_bundles is disabled.
func markVendor(result *outcome, vendor bool, candidatesFrom, findingsFrom int) {
	if !vendor {
		return
	}
	for index := candidatesFrom; index < len(result.candidates); index++ {
		result.candidates[index].Vendor = true
	}
	for index := findingsFrom; index < len(result.findings); index++ {
		result.findings[index].Vendor = true
	}
}

// absorbSourceMap queues the map a bundle points at through sourceMappingURL,
// or analyzes an inline map immediately since it needs no extra request.
func (p *Pipeline) absorbSourceMap(
	result *outcome,
	source *url.URL,
	base *url.URL,
	body []byte,
) {
	if !p.options.Config.Scope.ProbeSourceMaps {
		return
	}
	content, reference, ok := discover.SourceMapReference(body)
	if !ok {
		return
	}
	if len(content) > 0 {
		absorbRecoveredSources(result, base, content, p.options.Analyzer, p.options.Config.Scope.SkipLibraryBundles)
		return
	}
	if reference == "" {
		return
	}
	parsed, err := url.Parse(reference)
	if err != nil {
		return
	}
	resolved := base.ResolveReference(parsed)
	if !p.sourceMapAllowed(resolved) {
		return
	}
	result.candidates = append(result.candidates, discover.Candidate{
		Raw: resolved.String(), Kind: discover.KindSourceMap,
		SourceURL: source.String(), Source: "sourcemap",
	})
}

// absorbRecoveredSources runs the extractors over every original embedded in a
// map, so recovered sources contribute paths, parameters and findings that the
// minified bundle hid. This mirrors shuji's sources recovery.
func absorbRecoveredSources(
	result *outcome,
	origin *url.URL,
	body []byte,
	engine *analyze.Engine,
	skipLibraries bool,
) {
	for _, file := range discover.ParseSourceMap(body) {
		source := origin
		if fileURL, err := url.Parse(file.Name); err == nil {
			source = origin.ResolveReference(fileURL)
		}
		content := []byte(file.Content)
		isVendor := discover.IsThirdPartyBundle(content)
		if skipLibraries && isVendor {
			// The recovered original is a library file; skip it the same way
			// a bundled library script is skipped.
			continue
		}
		candidatesFrom, findingsFrom := len(result.candidates), len(result.findings)
		textResult := discover.FromJavaScript(source, content, engine)
		result.findings = append(result.findings, textResult.Findings...)
		result.candidates = append(result.candidates, textResult.Candidates...)
		result.candidates = append(
			result.candidates, discover.APIFromAST(source, content)...,
		)
		markVendor(result, isVendor, candidatesFrom, findingsFrom)
	}
}

// RunDetailed runs the shared pipeline with optional browser-rendered entry
// content and runtime URL seeds, returning aggregate SPA evidence.
func (p *Pipeline) RunDetailed(
	ctx context.Context,
	target model.Target,
	headers http.Header,
	entry *collect.Response,
	seeds []Seed,
	previouslySeen []string,
) (*model.Result, discover.SPAEvidence, error) {
	root, err := url.Parse(target.URL)
	if err != nil {
		return nil, discover.SPAEvidence{}, fmt.Errorf("parse target URL: %w", err)
	}
	targetScope, err := scope.New(root, p.options.Config.Scope)
	if err != nil {
		return nil, discover.SPAEvidence{}, err
	}
	resolutionBase := root
	if strings.TrimSpace(target.BaseURL) != "" {
		parsedBase, parseErr := url.Parse(target.BaseURL)
		if parseErr != nil || !parsedBase.IsAbs() || parsedBase.Host == "" {
			return nil, discover.SPAEvidence{}, fmt.Errorf(
				"invalid base URL %q", target.BaseURL,
			)
		}
		resolutionBase, err = targetScope.Resolve(target.BaseURL, root)
		if err != nil {
			return nil, discover.SPAEvidence{}, fmt.Errorf("base URL: %w", err)
		}
	}

	result := &model.Result{
		Target:    scope.Canonical(root),
		Mode:      p.options.Config.Mode,
		Resources: make([]model.Resource, 0),
		Endpoints: make([]model.Endpoint, 0),
		Findings:  make([]model.Finding, 0),
		Issues:    make([]model.Issue, 0),
	}
	queue := scheduler.New(
		p.options.Config.Limits.MaxResources,
		p.options.Config.Limits.MaxDepth,
	)
	endpointIndex := make(map[string]int)
	queue.Add(scheduler.Item{
		URL: scope.Canonical(root), Kind: model.ResourceTypeDocument,
	})
	queue.MarkSeen(previouslySeen)
	// A runtime route that carries a fragment proves the app is a hash-mode
	// router; static routes are then reported in the same "/#/x" form.
	var spa discover.SPAEvidence
	for _, seed := range seeds {
		seedURL, parseErr := url.Parse(seed.URL)
		if parseErr != nil {
			continue
		}
		if targetScope.IsSuffixBlocked(seedURL) {
			continue
		}
		allowed := seed.Kind == model.ResourceTypeScript &&
			targetScope.CanFetchScript(seedURL)
		if seed.Kind == model.ResourceTypeAPI {
			allowed = targetScope.CanProbe(seedURL)
		}
		if seed.Kind == model.ResourceTypeRoute {
			// Runtime-observed framework routes are recorded but never probed.
			// Hash-router routes keep their fragment ("#/admin"); stripping it
			// would collapse every hash route into the index URL.
			if seedURL.Fragment != "" {
				spa.HashRouting = true
			}
			canonical := routeCanonical(seedURL)
			if _, exists := endpointIndex[canonical]; !exists {
				endpointIndex[canonical] = len(result.Endpoints)
				result.Endpoints = append(result.Endpoints, model.Endpoint{
					Raw: seed.URL, URL: canonical,
					SourceURL:  seed.InitiatorURL,
					Authorized: false,
					Type:       "route",
					Evidence:   model.EvidenceRuntime,
					Source:     seed.Source,
				})
			}
			continue
		}
		if seed.Kind == model.ResourceTypeAPI {
			// Runtime-observed endpoints are reported regardless of probe
			// authorization; only the active GET probe is gated.
			canonical := scope.Canonical(seedURL)
			if _, exists := endpointIndex[canonical]; !exists {
				endpointIndex[canonical] = len(result.Endpoints)
				result.Endpoints = append(result.Endpoints, model.Endpoint{
					Raw: canonical, URL: canonical,
					SourceURL:  seed.InitiatorURL,
					Authorized: targetScope.CanProbe(seedURL),
					Method:     seed.Method,
					Evidence:   seed.Evidence,
					Line:       seed.Line,
					Column:     seed.Column,
					Source:     seed.Source,
					Spec:       seed.Spec,
					Type:       "api",
				})
			}
		}
		if !allowed {
			continue
		}
		queue.Add(scheduler.Item{
			URL:       scope.Canonical(seedURL),
			Kind:      seed.Kind,
			SourceURL: scope.Canonical(root),
			Depth:     1,
		})
		if seed.Kind == model.ResourceTypeAPI {
			canonical := scope.Canonical(seedURL)
			if index, exists := endpointIndex[canonical]; exists {
				result.Endpoints[index].Authorized = true
			} else {
				endpointIndex[canonical] = len(result.Endpoints)
				result.Endpoints = append(result.Endpoints, model.Endpoint{
					Raw: canonical, URL: canonical,
					SourceURL: scope.Canonical(root), Authorized: true,
					Evidence: seed.Evidence,
					Type:     "api",
				})
			}
		}
	}

	state := &runState{
		result:         result,
		queue:          queue,
		endpointIndex:  endpointIndex,
		findingSeen:    make(map[string]struct{}),
		spa:            &spa,
		deferJS:        p.options.Config.Output.DownloadJS,
		targetScope:    targetScope,
		root:           root,
		resolutionBase: resolutionBase,
		probeEvents:    p.options.ProbeEvents,
	}
	if err := p.drain(ctx, state, headers, entry); err != nil {
		return result, spa, err
	}
	// Fetch-first mode: every script and chunk has been downloaded (and saved)
	// before the regex engine and AST extractor run over the saved files.
	// Endpoint candidates discovered here may enqueue fresh API probes, so the
	// queue is drained again until nothing new is pending.
	for len(state.pending) > 0 {
		if err := ctx.Err(); err != nil {
			return result, spa, err
		}
		batch := state.pending
		state.pending = nil
		for _, analysis := range p.computeBatch(batch) {
			p.mergeDeferred(state, analysis)
		}
		if err := p.drain(ctx, state, headers, entry); err != nil {
			return result, spa, err
		}
	}

	if p.options.Config.Scope.ProbeRoutes {
		p.probeRoutes(ctx, result, headers, root)
	}
	if p.options.Config.Output.RequestTemplate {
		templates := make([]*model.RequestTemplate, len(result.Endpoints))
		endpoints := make([]*model.Endpoint, len(result.Endpoints))
		for i := range result.Endpoints {
			result.Endpoints[i].Template = analyze.BuildTemplate(&result.Endpoints[i])
			templates[i] = result.Endpoints[i].Template
			endpoints[i] = &result.Endpoints[i]
		}
		// Optional AI enrichment point: the default enricher is a no-op and
		// returns the deterministic templates unchanged.
		refined := analyze.DefaultEnricher{}.Enrich(templates, endpoints)
		for i := range result.Endpoints {
			if refined != nil && i < len(refined) && refined[i] != nil {
				result.Endpoints[i].Template = refined[i]
			}
		}
	}
	if spa.RootNode || spa.DynamicImport || spa.HistoryRouting || spa.DynamicScript {
		result.Technologies = append(result.Technologies, "spa")
	}
	if spa.Webpack {
		result.Technologies = append(result.Technologies, "webpack")
	}
	if spa.RequireJS {
		result.Technologies = append(result.Technologies, "requirejs")
	}
	sort.Strings(result.Technologies)
	finalize(result)
	return result, spa, nil
}

// drain collects and processes queued resources until the queue is empty.
// In fetch-first mode (DownloadJS enabled) scripts and chunks are saved and
// queued for the deferred analysis phase instead of being analyzed inline.
func (p *Pipeline) drain(
	ctx context.Context,
	state *runState,
	headers http.Header,
	entry *collect.Response,
) error {
	for state.queue.Len() > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		batch := state.queue.Take(p.options.Config.Concurrency.ResourcesPerTarget)
		outcomes := p.collectBatch(
			ctx, batch, headers, entry, state.root, state.resolutionBase,
			state.deferJS,
		)
		for _, collected := range outcomes {
			if err := p.processOutcome(state, collected); err != nil {
				if contextErr := ctx.Err(); contextErr != nil {
					return contextErr
				}
				if collected.item.Depth == 0 {
					return err
				}
				state.result.Issues = append(state.result.Issues, model.Issue{
					Code:      "resource_get_failed",
					Stage:     "collect",
					URL:       collected.item.URL,
					Message:   err.Error(),
					Retryable: true,
				})
			}
		}
	}
	return nil
}

// processOutcome records one collected response and expands its candidates;
// a non-nil error marks a collection failure (already logged when nil-safe).
func (p *Pipeline) processOutcome(state *runState, collected outcome) error {
	result := state.result
	if collected.err != nil {
		return collected.err
	}
	mergeSPAEvidence(state.spa, collected.spa)

	resource := model.Resource{
		URL:         collected.response.URL,
		Type:        collected.item.Kind,
		SourceURL:   collected.item.SourceURL,
		StatusCode:  collected.response.StatusCode,
		ContentType: collected.response.Header.Get("Content-Type"),
		Size:        int64(len(collected.response.Body)),
		Depth:       collected.item.Depth,
	}
	if collected.response.Truncated {
		result.Issues = append(result.Issues, model.Issue{
			Code: "body_truncated", Stage: "collect", URL: resource.URL,
			Message: "response exceeded max_body_size",
		})
	}
	isJS := resource.Type == model.ResourceTypeScript ||
		resource.Type == model.ResourceTypeChunk
	if state.deferJS && isJS {
		if source, parseErr := url.Parse(collected.response.URL); parseErr == nil {
			deferred := deferredJS{source: source, depth: collected.item.Depth, vendor: collected.vendor}
			switch {
			case collected.response.Truncated:
				// Truncated bodies are never persisted; analyze from memory.
				result.Issues = append(result.Issues, model.Issue{
					Code: "js_not_saved", Stage: "storage", URL: resource.URL,
					Message: "truncated JavaScript body was not persisted",
				})
				deferred.body = collected.response.Body
			default:
				localPath, saveErr := storage.SaveJSIn(
					p.options.Config.Output.Directory,
					state.root,
					p.options.Config.Output.JSDirectory,
					resource,
					collected.response.Body,
				)
				if saveErr != nil {
					// Saving failed; analyze from memory so endpoints are not lost.
					deferred.body = collected.response.Body
					result.Issues = append(result.Issues, model.Issue{
						Code: "js_save_failed", Stage: "storage", URL: resource.URL,
						Message: saveErr.Error(),
					})
				} else {
					resource.LocalPath = localPath
					deferred.path = localPath
				}
			}
			state.pending = append(state.pending, deferred)
		}
	}
	result.Resources = append(result.Resources, resource)
	if collected.item.Kind == model.ResourceTypeAPI {
		if index, exists := state.endpointIndex[collected.item.URL]; exists {
			result.Endpoints[index].StatusCode = collected.response.StatusCode
			if len(result.Endpoints[index].ResponseParams) == 0 &&
				strings.Contains(
					strings.ToLower(collected.response.Header.Get("Content-Type")),
					"json",
				) {
				// Keep only the field names, never the body itself.
				result.Endpoints[index].ResponseParams =
					discover.JSONFieldNames(collected.response.Body)
			}
			state.emitProbe(model.ProbeEvent{
				Target:     scope.Canonical(state.root),
				URL:        result.Endpoints[index].URL,
				Method:     result.Endpoints[index].Method,
				StatusCode: collected.response.StatusCode,
				Evidence:   result.Endpoints[index].Evidence,
			})
		}
	}

	for _, finding := range collected.findings {
		key := finding.RuleID + "\x00" + finding.SourceURL + "\x00" + finding.Value
		if _, duplicate := state.findingSeen[key]; duplicate {
			continue
		}
		state.findingSeen[key] = struct{}{}
		result.Findings = append(result.Findings, finding)
	}

	p.processCandidates(
		state, collected.response.URL, collected.candidates, collected.item.Depth,
	)
	return nil
}

// processCandidates resolves discovery candidates against their source,
// deduplicates endpoints and enqueues follow-up resources and API probes.
func (p *Pipeline) processCandidates(
	state *runState,
	sourceURL string,
	candidates []discover.Candidate,
	depth int,
) {
	result := state.result
	base, parseErr := url.Parse(sourceURL)
	if parseErr != nil {
		return
	}
	for _, candidate := range candidates {
		candidateBase := base
		if state.resolutionBase != state.root && isRelativeReference(candidate.Raw) {
			candidateBase = state.resolutionBase
		}
		resolved, resolveErr := state.targetScope.Resolve(
			candidate.Raw, candidateBase,
		)
		if resolveErr != nil {
			continue
		}
		if state.targetScope.IsSuffixBlocked(resolved) {
			continue
		}
		canonical := scope.Canonical(resolved)
		nextDepth := depth + 1
		switch candidate.Kind {
		case discover.KindScript:
			if state.targetScope.CanFetchScript(resolved) {
				state.queue.Add(scheduler.Item{
					URL: canonical, Kind: model.ResourceTypeScript,
					SourceURL: sourceURL, Depth: nextDepth,
				})
			}
		case discover.KindChunk:
			if state.targetScope.CanFetchScript(resolved) {
				state.queue.Add(scheduler.Item{
					URL: canonical, Kind: model.ResourceTypeChunk,
					SourceURL: sourceURL, Depth: nextDepth,
				})
			}
		case discover.KindSourceMap:
			// A leaked map usually restores the whole app, so it is fetched
			// like a script; library maps are skipped via the blacklist.
			if p.sourceMapAllowed(resolved) &&
				state.targetScope.CanFetchScript(resolved) {
				state.queue.Add(scheduler.Item{
					URL: canonical, Kind: model.ResourceTypeSourceMap,
					SourceURL: sourceURL, Depth: nextDepth,
				})
			}
		case discover.KindEndpoint:
			if discover.IsNoiseEndpoint(candidate.Raw) {
				// A value consisting of slashes only ("//", "///") is a
				// regex artifact over comment markers, not an endpoint.
				continue
			}
			if discover.IsStaticAssetPath(resolved.Path) {
				// A quoted "/a/b.png" or "/bundle.js" is a resource
				// reference, not an API endpoint.
				continue
			}
			authorized := state.targetScope.CanProbe(resolved)
			if index, exists := state.endpointIndex[canonical]; exists {
				enrichEndpoint(
					&result.Endpoints[index], candidate,
					candidateEvidence(candidate, resolved),
				)
			} else {
				state.endpointIndex[canonical] = len(result.Endpoints)
				result.Endpoints = append(result.Endpoints, model.Endpoint{
					Raw: candidate.Raw, URL: canonical,
					SourceURL: sourceURL, Authorized: authorized,
					Method:       candidate.Method,
					Evidence:     candidateEvidence(candidate, resolved),
					Line:         candidate.Line,
					Column:       candidate.Column,
					ContextLines: candidate.ContextLines,
					Vendor:       candidate.Vendor,
					BodyParams:   candidate.BodyParams,
					Spec:         candidate.Spec,
					Source:       candidate.Source,
					Type:         "api",
				})
			}
			if authorized {
				state.queue.Add(scheduler.Item{
					URL: canonical, Kind: model.ResourceTypeAPI,
					SourceURL: sourceURL, Depth: nextDepth,
				})
			}
		case discover.KindRoute:
			if state.spa.HashRouting && resolved.Fragment == "" &&
				isRelativeReference(candidate.Raw) {
				// A hash-mode SPA serves one document and keeps the route
				// after "#": report "/#/admin", not a bogus "/admin".
				canonical = asHashRoute(resolved)
			}
			if index, exists := state.endpointIndex[canonical]; exists {
				enrichEndpoint(&result.Endpoints[index], candidate, "")
			} else {
				state.endpointIndex[canonical] = len(result.Endpoints)
				result.Endpoints = append(result.Endpoints, model.Endpoint{
					Raw: candidate.Raw, URL: canonical,
					SourceURL:    sourceURL,
					Authorized:   state.targetScope.CanProbe(resolved),
					Type:         routeType(candidate),
					Source:       candidate.Source,
					Line:         candidate.Line,
					Column:       candidate.Column,
					ContextLines: candidate.ContextLines,
				})
			}
		}
	}
}

// enrichEndpoint fills fields an earlier, coarser candidate left empty on an
// existing endpoint. Fetch-first mode sees regex candidates before AST
// candidates, so the richer AST data (body parameters, context lines, method)
// has to be merged instead of winning the initial dedup.
func enrichEndpoint(
	endpoint *model.Endpoint,
	candidate discover.Candidate,
	evidence string,
) {
	if !candidate.Vendor {
		// Application code references this endpoint too, so it is not
		// vendor-only and must not be filtered as library noise.
		endpoint.Vendor = false
	}
	if len(endpoint.BodyParams) == 0 && len(candidate.BodyParams) > 0 {
		endpoint.BodyParams = candidate.BodyParams
	}
	endpoint.Spec = mergeSpec(endpoint.Spec, candidate.Spec)
	if endpoint.Spec != nil {
		// The spec's union of keys is the recall-first superset of the
		// per-candidate lists; keep the legacy field consistent with it.
		if keys := endpoint.Spec.ParamKeys(); len(keys) > len(endpoint.BodyParams) {
			endpoint.BodyParams = keys
		}
	}
	if len(endpoint.ContextLines) == 0 && len(candidate.ContextLines) > 0 {
		endpoint.ContextLines = candidate.ContextLines
	}
	if endpoint.Method == "" && candidate.Method != "" {
		endpoint.Method = candidate.Method
	}
	if endpoint.Line == 0 && candidate.Line != 0 {
		endpoint.Line = candidate.Line
	}
	if endpoint.Column == 0 && candidate.Column != 0 {
		endpoint.Column = candidate.Column
	}
	if evidenceRank(evidence) > evidenceRank(endpoint.Evidence) {
		endpoint.Evidence = evidence
	}
}

// mergeSpec unions two request specs by parameter key, recall-first: a key
// seen at either call site is kept, the higher-evidence value wins, and an
// explicit content type outranks an inferred one. Either side may be nil.
func mergeSpec(base, extra *model.RequestSpec) *model.RequestSpec {
	if extra == nil {
		return base
	}
	if base == nil {
		return extra
	}
	if base.ContentType == "" && extra.ContentType != "" {
		base.ContentType, base.ContentTypeEvidence =
			extra.ContentType, extra.ContentTypeEvidence
	}
	if base.BaseURL == "" && extra.BaseURL != "" {
		base.BaseURL, base.BaseURLKind = extra.BaseURL, extra.BaseURLKind
	}
	base.Query = mergeParams(base.Query, extra.Query)
	base.Body = mergeParams(base.Body, extra.Body)
	return base
}

var specEvidenceRank = map[string]int{
	model.EvidenceRuntime:     4,
	model.EvidenceLiteral:     3,
	model.EvidenceConstant:    2,
	model.EvidenceInferred:    1,
	model.EvidencePlaceholder: 0,
}

func paramRank(param model.Param) int {
	if rank, ok := specEvidenceRank[param.Evidence]; ok {
		return rank
	}
	return 0
}

func mergeParams(base, extra []model.Param) []model.Param {
	if len(extra) == 0 {
		return base
	}
	index := make(map[string]int, len(base)+len(extra))
	for i, param := range base {
		index[param.Key] = i
	}
	for _, param := range extra {
		if param.Key == "" {
			continue
		}
		if i, exists := index[param.Key]; exists {
			if paramRank(param) > paramRank(base[i]) {
				base[i] = param
			}
			continue
		}
		index[param.Key] = len(base)
		base = append(base, param)
	}
	return base
}

func evidenceRank(evidence string) int {
	switch evidence {
	case model.EvidenceRuntime:
		return 3
	case model.EvidenceFullURL:
		return 2
	case model.EvidenceStatic:
		return 1
	default:
		return 0
	}
}

// deferredAnalysis is the analysis output for one deferred JavaScript item,
// kept positionally aligned with its batch so merging stays deterministic.
type deferredAnalysis struct {
	vendor     bool
	item       deferredJS
	findings   []model.Finding
	candidates []discover.Candidate
	spa        discover.SPAEvidence
	readErr    error
}

// computeBatch loads and analyzes deferred JavaScript bodies in parallel.
// Items with a saved file are read from disk (dropping the in-memory copy
// after the save); items with a fallback body are analyzed from memory.
// The caller merges results sequentially so endpoint ordering stays stable.
func (p *Pipeline) computeBatch(batch []deferredJS) []deferredAnalysis {
	analyses := make([]deferredAnalysis, len(batch))
	var wait sync.WaitGroup
	wait.Add(len(batch))
	for index := range batch {
		item := batch[index]
		go func() {
			defer wait.Done()
			analysis := deferredAnalysis{item: item, vendor: item.vendor}
			body := item.body
			if item.path != "" {
				loaded, readErr := storage.LoadJS(
					p.options.Config.Output.Directory, item.path,
				)
				if readErr != nil {
					analysis.readErr = readErr
					analyses[index] = analysis
					return
				}
				body = loaded
			}
			if body == nil {
				analysis.readErr = errors.New("no saved file or in-memory body to analyze")
				analyses[index] = analysis
				return
			}
			jsResult := discover.FromJavaScript(item.source, body, p.options.Analyzer)
			analysis.findings = jsResult.Findings
			analysis.spa = jsResult.SPA
			analysis.candidates = discover.APIFromAST(item.source, body)
			analyses[index] = analysis
		}()
	}
	wait.Wait()
	return analyses
}

// mergeDeferred folds one analysis result into the run state.
func (p *Pipeline) mergeDeferred(state *runState, analysis deferredAnalysis) {
	if analysis.readErr != nil {
		state.result.Issues = append(state.result.Issues, model.Issue{
			Code: "js_analysis_failed", Stage: "analyze", URL: analysis.item.source.String(),
			Message: analysis.readErr.Error(),
		})
		return
	}
	mergeSPAEvidence(state.spa, analysis.spa)
	if analysis.vendor {
		for index := range analysis.findings {
			analysis.findings[index].Vendor = true
		}
		for index := range analysis.candidates {
			analysis.candidates[index].Vendor = true
		}
	}
	for _, finding := range analysis.findings {
		key := finding.RuleID + "\x00" + finding.SourceURL + "\x00" + finding.Value
		if _, duplicate := state.findingSeen[key]; duplicate {
			continue
		}
		state.findingSeen[key] = struct{}{}
		state.result.Findings = append(state.result.Findings, finding)
	}
	p.processCandidates(
		state,
		analysis.item.source.String(),
		analysis.candidates,
		analysis.item.depth,
	)
}

func (p *Pipeline) collectBatch(
	ctx context.Context,
	batch []scheduler.Item,
	headers http.Header,
	entry *collect.Response,
	root *url.URL,
	resolutionBase *url.URL,
	deferJS bool,
) []outcome {
	outcomes := make([]outcome, len(batch))
	var wait sync.WaitGroup
	wait.Add(len(batch))
	for index, item := range batch {
		go func() {
			defer wait.Done()
			outcomes[index] = p.collectOne(
				ctx, item, headers, entry, root, resolutionBase, deferJS,
			)
		}()
	}
	wait.Wait()
	return outcomes
}

func (p *Pipeline) collectOne(
	ctx context.Context,
	item scheduler.Item,
	headers http.Header,
	entry *collect.Response,
	root *url.URL,
	resolutionBase *url.URL,
	deferJS bool,
) outcome {
	target, err := url.Parse(item.URL)
	if err != nil {
		return outcome{item: item, err: err}
	}
	var response collect.Response
	if entry != nil && item.Depth == 0 && item.Kind == model.ResourceTypeDocument {
		response = *entry
	} else {
		response, err = p.options.Getter.Get(
			ctx,
			target,
			collect.HeadersForURL(headers, root, target),
		)
		if err != nil {
			return outcome{item: item, err: err}
		}
	}

	result := outcome{item: item, response: response}
	source, err := url.Parse(response.URL)
	if err != nil {
		return result
	}
	discoveryBase := source
	if resolutionBase != root {
		discoveryBase = resolutionBase
	}
	contentType := response.Header.Get("Content-Type")
	if parsed, _, parseErr := mime.ParseMediaType(contentType); parseErr == nil {
		contentType = parsed
	}

	switch {
	case item.Kind == model.ResourceTypeDocument || strings.Contains(contentType, "html"):
		htmlResult := discover.FromHTML(discoveryBase, response.Body)
		mergeSPAEvidence(&result.spa, htmlResult.SPA)
		result.candidates = append(result.candidates, htmlResult.Candidates...)
		// Vue CLI inlines the webpack runtime into the HTML entry, so the
		// chunk map may only exist in the document body.
		result.candidates = append(result.candidates, discover.FromWebpack(
			discoveryBase, response.Body, p.candidateLimit(),
		)...)
		result.candidates = append(result.candidates, discover.APIFromAST(source, response.Body)...)
		textResult := discover.FromJavaScript(source, response.Body, p.options.Analyzer)
		mergeSPAEvidence(&result.spa, textResult.SPA)
		result.findings = append(result.findings, textResult.Findings...)
		result.candidates = append(result.candidates, textResult.Candidates...)
		for _, inline := range htmlResult.InlineScripts {
			inlineResult := discover.FromJavaScript(source, []byte(inline), p.options.Analyzer)
			mergeSPAEvidence(&result.spa, inlineResult.SPA)
			result.findings = append(result.findings, inlineResult.Findings...)
			result.candidates = append(result.candidates, inlineResult.Candidates...)
			result.candidates = append(
				result.candidates,
				discover.APIFromAST(source, []byte(inline))...,
			)
		}
	case item.Kind == model.ResourceTypeScript || item.Kind == model.ResourceTypeChunk ||
		strings.Contains(contentType, "javascript"):
		vendor := discover.IsThirdPartyBundle(response.Body)
		if vendor && p.options.Config.Scope.SkipLibraryBundles {
			// Its license banner identifies a third-party library, so the
			// regex and AST pass would only add vendor noise. The resource is
			// still recorded.
			break
		}
		// With the skip disabled the bundle is still parsed, but everything it
		// yields is labelled so the report can separate library noise from
		// application results.
		result.vendor = vendor
		vendorCandidates, vendorFindings := len(result.candidates), len(result.findings)
		defer func() {
			markVendor(&result, vendor, vendorCandidates, vendorFindings)
		}()
		if !deferJS {
			result.candidates = append(result.candidates, discover.APIFromAST(source, response.Body)...)
		}
		jsResult := discover.FromJavaScript(source, response.Body, p.options.Analyzer)
		mergeSPAEvidence(&result.spa, jsResult.SPA)
		// Fetch-first mode reruns the regex engine and AST extractor over the
		// downloaded bodies after collection, so this pass keeps only the
		// candidates needed to discover follow-up scripts and chunks.
		if deferJS {
			result.candidates = append(result.candidates, jsResult.Candidates...)
		} else {
			result.findings = append(result.findings, jsResult.Findings...)
			result.candidates = append(result.candidates, jsResult.Candidates...)
		}
		result.candidates = append(
			result.candidates,
			discover.FromWebpack(
				discoveryBase,
				response.Body,
				p.candidateLimit(),
			)...,
		)
		result.candidates = append(
			result.candidates,
			discover.FromRequireJS(
				discoveryBase,
				response.Body,
				p.candidateLimit(),
			)...,
		)
		p.absorbSourceMap(&result, source, discoveryBase, response.Body)
	case item.Kind == model.ResourceTypeSourceMap ||
		strings.HasSuffix(strings.ToLower(source.Path), ".map"):
		// A map embeds the unminified originals; run the same extractors over
		// each of them, the way shuji restores sources.
		absorbRecoveredSources(&result, source, response.Body, p.options.Analyzer, p.options.Config.Scope.SkipLibraryBundles)
	case isTextualContentType(contentType):
		textResult := discover.FromJavaScript(source, response.Body, p.options.Analyzer)
		mergeSPAEvidence(&result.spa, textResult.SPA)
		result.findings = append(result.findings, textResult.Findings...)
		result.candidates = append(result.candidates, textResult.Candidates...)
	}
	return result
}

// probeRoutes GETs framework routes on the target origin and compares each
// body against the index page, separating server-backed routes from pure
// SPA fallbacks.
func (p *Pipeline) probeRoutes(
	ctx context.Context,
	result *model.Result,
	headers http.Header,
	root *url.URL,
) {
	const maxRouteProbes = 100
	rootHash, rootOK := p.routeBodyHash(ctx, root, headers)
	probed := 0
	for index := range result.Endpoints {
		endpoint := &result.Endpoints[index]
		if endpoint.Type != "route" {
			continue
		}
		target, err := url.Parse(endpoint.URL)
		if err != nil || target.Host != root.Host || probed >= maxRouteProbes {
			continue
		}
		if target.Fragment != "" {
			// Hash routes are client-side only: a GET would just fetch the
			// index page again.
			continue
		}
		probed++
		response, err := p.options.Getter.Get(ctx, target,
			collect.HeadersForURL(headers, root, target))
		if err != nil {
			endpoint.Probe = "error"
			continue
		}
		endpoint.StatusCode = response.StatusCode
		if !rootOK {
			endpoint.Probe = "unknown"
			continue
		}
		if normalizedBodyHash(response.Body) == rootHash {
			endpoint.Probe = "static"
		} else {
			endpoint.Probe = "server"
		}
	}
}

func (p *Pipeline) routeBodyHash(
	ctx context.Context,
	location *url.URL,
	headers http.Header,
) ([32]byte, bool) {
	var empty [32]byte
	response, err := p.options.Getter.Get(ctx, location,
		collect.HeadersForURL(headers, location, location))
	if err != nil {
		return empty, false
	}
	return normalizedBodyHash(response.Body), true
}

// route-probe noise patterns: template engines, dev servers and server
// frameworks inject values that differ on every request (CSRF nonces, build
// hashes, timestamps, asset versions) even though the page is the same SPA
// fallback. Everything below is stripped before the body hash so such pages
// compare equal.
var (
	routeProbeScriptBlock = regexp.MustCompile(`(?is)<script\b[^>]*>.*?</script>`)
	routeProbeStyleBlock  = regexp.MustCompile(`(?is)<style\b[^>]*>.*?</style>`)
	routeProbeComment     = regexp.MustCompile(`(?s)<!--.*?-->`)
	routeProbeVolatile    = regexp.MustCompile(
		`(?is)\b(?:nonce|csrf[-_a-z]*|token|_?timestamp|ts|etag|sig)\b\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)`)
	routeProbeHiddenValue = regexp.MustCompile(
		`(?is)<input\b[^>]*\btype\s*=\s*["']?hidden["']?[^>]*\bvalue\s*=\s*(?:"[^"]*"|'[^']*')`)
	routeProbeWhitespace = regexp.MustCompile(`\s+`)
)

// normalizedBodyHash hashes a response body after removing the parts that vary
// between requests to the same SPA shell. The raw-body comparison it replaces
// marked every route as "server" whenever the index carried a CSRF nonce or a
// build timestamp.
func normalizedBodyHash(body []byte) [32]byte {
	normalized := routeProbeScriptBlock.ReplaceAll(body, nil)
	normalized = routeProbeStyleBlock.ReplaceAll(normalized, nil)
	normalized = routeProbeComment.ReplaceAll(normalized, nil)
	normalized = routeProbeHiddenValue.ReplaceAll(normalized, nil)
	normalized = routeProbeVolatile.ReplaceAll(normalized, nil)
	normalized = routeProbeWhitespace.ReplaceAll(normalized, []byte(" "))
	return sha256.Sum256(normalized)
}

// routeCanonical returns the dedup and display URL for a route. Hash-router
// routes keep their fragment so "/#/admin" stays distinct from the index URL.
func routeCanonical(candidate *url.URL) string {
	canonical := scope.Canonical(candidate)
	if candidate.Fragment != "" {
		canonical += "#" + candidate.EscapedFragment()
	}
	return canonical
}

// asHashRoute rewrites a path into its hash-router form: a hash-mode SPA
// serves one document and keeps the route after "#", so "/login" is really
// "/#/login". The fragment is appended verbatim so an embedded query keeps
// its original escaping.
func asHashRoute(resolved *url.URL) string {
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

func isRelativeReference(raw string) bool {
	reference, err := url.Parse(strings.TrimSpace(raw))
	return err == nil && reference.Scheme == "" && reference.Host == ""
}

// routeType distinguishes true framework routes (dedicated router rules or
// runtime observation) from generic quoted URLs that only default to the
// route classification.
func routeType(candidate discover.Candidate) string {
	if candidate.Source == "cdp-runtime" ||
		strings.HasPrefix(candidate.RuleID, "url.vue-route") ||
		strings.HasPrefix(candidate.RuleID, "url.react-route") {
		return "route"
	}
	return "link"
}

// candidateEvidence grades a candidate once resolved against its base.
func candidateEvidence(candidate discover.Candidate, resolved *url.URL) string {
	if candidate.Evidence != "" {
		return candidate.Evidence
	}
	if resolved.Scheme == "http" || resolved.Scheme == "https" {
		if !isRelativeReference(candidate.Raw) {
			return model.EvidenceFullURL
		}
	}
	return model.EvidenceStatic
}

func isTextualContentType(contentType string) bool {
	contentType = strings.ToLower(contentType)
	if contentType == "" || strings.HasPrefix(contentType, "text/") {
		return true
	}
	for _, marker := range []string{
		"json", "xml", "yaml", "javascript", "graphql",
		"x-www-form-urlencoded",
	} {
		if strings.Contains(contentType, marker) {
			return true
		}
	}
	return false
}

func mergeSPAEvidence(target *discover.SPAEvidence, source discover.SPAEvidence) {
	target.RootNode = target.RootNode || source.RootNode
	target.DynamicImport = target.DynamicImport || source.DynamicImport
	target.HistoryRouting = target.HistoryRouting || source.HistoryRouting
	target.HashRouting = target.HashRouting || source.HashRouting
	target.DynamicScript = target.DynamicScript || source.DynamicScript
	target.Webpack = target.Webpack || source.Webpack
	target.RequireJS = target.RequireJS || source.RequireJS
	target.LargeBundle = target.LargeBundle || source.LargeBundle
}

// Finalize sorts the result and recomputes its statistics. It is idempotent,
// so callers that merge results from a second pass can refresh the counts the
// report header shows.
func Finalize(result *model.Result) {
	finalize(result)
}

func finalize(result *model.Result) {
	sort.SliceStable(result.Resources, func(i, j int) bool {
		if result.Resources[i].URL != result.Resources[j].URL {
			return result.Resources[i].URL < result.Resources[j].URL
		}
		return result.Resources[i].Type < result.Resources[j].Type
	})
	sort.SliceStable(result.Endpoints, func(i, j int) bool {
		return result.Endpoints[i].URL < result.Endpoints[j].URL
	})
	sort.SliceStable(result.Findings, func(i, j int) bool {
		if result.Findings[i].SourceURL != result.Findings[j].SourceURL {
			return result.Findings[i].SourceURL < result.Findings[j].SourceURL
		}
		if result.Findings[i].Line != result.Findings[j].Line {
			return result.Findings[i].Line < result.Findings[j].Line
		}
		return result.Findings[i].RuleID < result.Findings[j].RuleID
	})

	scripts, chunks := 0, 0
	for _, resource := range result.Resources {
		switch resource.Type {
		case model.ResourceTypeScript:
			scripts++
		case model.ResourceTypeChunk:
			chunks++
		}
	}
	result.Statistics.Resources = len(result.Resources)
	result.Statistics.Scripts = scripts
	result.Statistics.Chunks = chunks
	result.Statistics.Endpoints = len(result.Endpoints)
	result.Statistics.Findings = len(result.Findings)
}
