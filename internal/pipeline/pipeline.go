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

	findingSeen := make(map[string]struct{})
	var spa discover.SPAEvidence
	for queue.Len() > 0 {
		if err := ctx.Err(); err != nil {
			return result, spa, err
		}
		batch := queue.Take(p.options.Config.Concurrency.ResourcesPerTarget)
		outcomes := p.collectBatch(
			ctx, batch, headers, entry, root, resolutionBase,
		)
		for _, collected := range outcomes {
			if collected.err != nil {
				if contextErr := ctx.Err(); contextErr != nil {
					return result, spa, contextErr
				}
				if collected.item.Depth == 0 {
					return result, spa, collected.err
				}
				result.Issues = append(result.Issues, model.Issue{
					Code:      "resource_get_failed",
					Stage:     "collect",
					URL:       collected.item.URL,
					Message:   collected.err.Error(),
					Retryable: true,
				})
				continue
			}
			mergeSPAEvidence(&spa, collected.spa)

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
						root,
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
				if index, exists := endpointIndex[collected.item.URL]; exists {
					result.Endpoints[index].StatusCode = collected.response.StatusCode
				}
			}

			for _, finding := range collected.findings {
				key := finding.RuleID + "\x00" + finding.SourceURL + "\x00" + finding.Value
				if _, duplicate := findingSeen[key]; duplicate {
					continue
				}
				findingSeen[key] = struct{}{}
				result.Findings = append(result.Findings, finding)
			}

			base, parseErr := url.Parse(collected.response.URL)
			if parseErr != nil {
				continue
			}
			for _, candidate := range collected.candidates {
				candidateBase := base
				if resolutionBase != root && isRelativeReference(candidate.Raw) {
					candidateBase = resolutionBase
				}
				resolved, resolveErr := targetScope.Resolve(
					candidate.Raw, candidateBase,
				)
				if resolveErr != nil {
					continue
				}
				if targetScope.IsSuffixBlocked(resolved) {
					continue
				}
				canonical := scope.Canonical(resolved)
				nextDepth := collected.item.Depth + 1
				switch candidate.Kind {
				case discover.KindScript:
					if targetScope.CanFetchScript(resolved) {
						queue.Add(scheduler.Item{
							URL: canonical, Kind: model.ResourceTypeScript,
							SourceURL: collected.response.URL, Depth: nextDepth,
						})
					}
				case discover.KindChunk:
					if targetScope.CanFetchScript(resolved) {
						queue.Add(scheduler.Item{
							URL: canonical, Kind: model.ResourceTypeChunk,
							SourceURL: collected.response.URL, Depth: nextDepth,
						})
					}
				case discover.KindEndpoint:
					authorized := targetScope.CanProbe(resolved)
					if _, exists := endpointIndex[canonical]; !exists {
						endpointIndex[canonical] = len(result.Endpoints)
						result.Endpoints = append(result.Endpoints, model.Endpoint{
							Raw: candidate.Raw, URL: canonical,
							SourceURL: collected.response.URL, Authorized: authorized,
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
						queue.Add(scheduler.Item{
							URL: canonical, Kind: model.ResourceTypeAPI,
							SourceURL: collected.response.URL, Depth: nextDepth,
						})
					}
				case discover.KindRoute:
					if _, exists := endpointIndex[canonical]; !exists {
						endpointIndex[canonical] = len(result.Endpoints)
						result.Endpoints = append(result.Endpoints, model.Endpoint{
							Raw: candidate.Raw, URL: canonical,
							SourceURL:  collected.response.URL,
							Authorized: targetScope.CanProbe(resolved),
							Type:       routeType(candidate),
							Source:     candidate.Source,
						})
					}
				}
			}
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

func (p *Pipeline) collectBatch(
	ctx context.Context,
	batch []scheduler.Item,
	headers http.Header,
	entry *collect.Response,
	root *url.URL,
	resolutionBase *url.URL,
) []outcome {
	outcomes := make([]outcome, len(batch))
	var wait sync.WaitGroup
	wait.Add(len(batch))
	for index, item := range batch {
		go func() {
			defer wait.Done()
			outcomes[index] = p.collectOne(
				ctx, item, headers, entry, root, resolutionBase,
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
		result.candidates = append(result.candidates, discover.APIFromAST(source, response.Body)...)
		jsResult := discover.FromJavaScript(source, response.Body, p.options.Analyzer)
		mergeSPAEvidence(&result.spa, jsResult.SPA)
		result.findings = append(result.findings, jsResult.Findings...)
		result.candidates = append(result.candidates, jsResult.Candidates...)
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
