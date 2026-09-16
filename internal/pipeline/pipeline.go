package pipeline

import (
	"context"
	"crypto/sha256"
	"fmt"
	"mime"
	"net/http"
	"net/url"
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
}

type outcome struct {
	item       scheduler.Item
	response   collect.Response
	err        error
	findings   []model.Finding
	candidates []discover.Candidate
	spa        discover.SPAEvidence
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
}

// deferredJS is one downloaded script or chunk waiting for the regex and AST
// analysis pass that runs after collection completes.
type deferredJS struct {
	source *url.URL
	body   []byte
	depth  int
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
			canonical := scope.Canonical(seedURL)
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

	var spa discover.SPAEvidence
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
	}
	if err := p.drain(ctx, state, headers, entry); err != nil {
		return result, spa, err
	}
	// Fetch-first mode: every script and chunk has been downloaded (and saved)
	// before the regex engine and AST extractor run over the downloaded
	// bodies. Endpoint candidates discovered here may enqueue fresh API
	// probes, so the queue is drained again until nothing new is pending.
	for len(state.pending) > 0 {
		batch := state.pending
		state.pending = nil
		for _, item := range batch {
			p.analyzeDeferred(state, item)
		}
		if err := p.drain(ctx, state, headers, entry); err != nil {
			return result, spa, err
		}
	}

	if p.options.Config.Scope.ProbeRoutes {
		p.probeRoutes(ctx, result, headers, root)
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
	if state.deferJS &&
		(resource.Type == model.ResourceTypeScript ||
			resource.Type == model.ResourceTypeChunk) {
		if source, parseErr := url.Parse(collected.response.URL); parseErr == nil {
			state.pending = append(state.pending, deferredJS{
				source: source,
				body:   collected.response.Body,
				depth:  collected.item.Depth,
			})
		}
	}
	if p.options.Config.Output.DownloadJS &&
		(resource.Type == model.ResourceTypeScript ||
			resource.Type == model.ResourceTypeChunk) {
		if collected.response.Truncated {
			result.Issues = append(result.Issues, model.Issue{
				Code: "js_not_saved", Stage: "storage", URL: resource.URL,
				Message: "truncated JavaScript body was not persisted",
			})
		} else {
			localPath, saveErr := storage.SaveJSIn(
				p.options.Config.Output.Directory,
				state.root,
				p.options.Config.Output.JSDirectory,
				resource,
				collected.response.Body,
			)
			if saveErr != nil {
				result.Issues = append(result.Issues, model.Issue{
					Code: "js_save_failed", Stage: "storage", URL: resource.URL,
					Message: saveErr.Error(),
				})
			} else {
				resource.LocalPath = localPath
			}
		}
	}
	result.Resources = append(result.Resources, resource)
	if collected.item.Kind == model.ResourceTypeAPI {
		if index, exists := state.endpointIndex[collected.item.URL]; exists {
			result.Endpoints[index].StatusCode = collected.response.StatusCode
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
		case discover.KindEndpoint:
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
					Method:   candidate.Method,
					Evidence: candidateEvidence(candidate, resolved),
					Line:     candidate.Line,
					Column:   candidate.Column,
					ContextLines: candidate.ContextLines,
					BodyParams:   candidate.BodyParams,
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
			if _, exists := state.endpointIndex[canonical]; !exists {
				state.endpointIndex[canonical] = len(result.Endpoints)
				result.Endpoints = append(result.Endpoints, model.Endpoint{
					Raw: candidate.Raw, URL: canonical,
					SourceURL:  sourceURL,
					Authorized: state.targetScope.CanProbe(resolved),
					Type:       routeType(candidate),
					Source:     candidate.Source,
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
	if len(endpoint.BodyParams) == 0 && len(candidate.BodyParams) > 0 {
		endpoint.BodyParams = candidate.BodyParams
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

// analyzeDeferred runs the regex engine and AST extractor over one downloaded
// script or chunk, merging findings and endpoint candidates into the result.
// Follow-up resources enqueued here (API probes) are drained by the caller.
func (p *Pipeline) analyzeDeferred(state *runState, item deferredJS) {
	jsResult := discover.FromJavaScript(item.source, item.body, p.options.Analyzer)
	mergeSPAEvidence(state.spa, jsResult.SPA)
	for _, finding := range jsResult.Findings {
		key := finding.RuleID + "\x00" + finding.SourceURL + "\x00" + finding.Value
		if _, duplicate := state.findingSeen[key]; duplicate {
			continue
		}
		state.findingSeen[key] = struct{}{}
		state.result.Findings = append(state.result.Findings, finding)
	}
	p.processCandidates(
		state,
		item.source.String(),
		discover.APIFromAST(item.source, item.body),
		item.depth,
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
				p.options.Config.Limits.MaxResources,
			)...,
		)
		result.candidates = append(
			result.candidates,
			discover.FromRequireJS(
				discoveryBase,
				response.Body,
				p.options.Config.Limits.MaxResources,
			)...,
		)
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
		if sha256.Sum256(response.Body) == rootHash {
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
	return sha256.Sum256(response.Body), true
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
	target.DynamicScript = target.DynamicScript || source.DynamicScript
	target.Webpack = target.Webpack || source.Webpack
	target.RequireJS = target.RequireJS || source.RequireJS
	target.LargeBundle = target.LargeBundle || source.LargeBundle
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

	result.Statistics.Resources = len(result.Resources)
	result.Statistics.Endpoints = len(result.Endpoints)
	result.Statistics.Findings = len(result.Findings)
	for _, resource := range result.Resources {
		switch resource.Type {
		case model.ResourceTypeScript:
			result.Statistics.Scripts++
		case model.ResourceTypeChunk:
			result.Statistics.Chunks++
		}
	}
}
