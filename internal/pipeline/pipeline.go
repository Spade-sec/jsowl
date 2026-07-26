package pipeline

import (
	"context"
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
	result, _, err := p.RunDetailed(ctx, target, headers, nil, nil)
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
) (*model.Result, discover.SPAEvidence, error) {
	root, err := url.Parse(target.URL)
	if err != nil {
		return nil, discover.SPAEvidence{}, fmt.Errorf("parse target URL: %w", err)
	}
	targetScope, err := scope.New(root, p.options.Config.Scope)
	if err != nil {
		return nil, discover.SPAEvidence{}, err
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
	for _, seed := range seeds {
		seedURL, parseErr := url.Parse(seed.URL)
		if parseErr != nil {
			continue
		}
		allowed := seed.Kind == model.ResourceTypeScript &&
			targetScope.CanFetchScript(seedURL)
		if seed.Kind == model.ResourceTypeAPI {
			allowed = targetScope.CanProbe(seedURL)
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
			if _, exists := endpointIndex[canonical]; !exists {
				endpointIndex[canonical] = len(result.Endpoints)
				result.Endpoints = append(result.Endpoints, model.Endpoint{
					Raw: canonical, URL: canonical,
					SourceURL: scope.Canonical(root), Authorized: true,
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
		outcomes := p.collectBatch(ctx, batch, headers, entry)
		for _, collected := range outcomes {
			if collected.err != nil {
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
				resolved, resolveErr := targetScope.Resolve(candidate.Raw, base)
				if resolveErr != nil {
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
						})
					}
				}
			}
		}
	}

	finalize(result)
	return result, spa, nil
}

func (p *Pipeline) collectBatch(
	ctx context.Context,
	batch []scheduler.Item,
	headers http.Header,
	entry *collect.Response,
) []outcome {
	outcomes := make([]outcome, len(batch))
	var wait sync.WaitGroup
	wait.Add(len(batch))
	for index, item := range batch {
		go func() {
			defer wait.Done()
			outcomes[index] = p.collectOne(ctx, item, headers, entry)
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
) outcome {
	target, err := url.Parse(item.URL)
	if err != nil {
		return outcome{item: item, err: err}
	}
	var response collect.Response
	if entry != nil && item.Depth == 0 && item.Kind == model.ResourceTypeDocument {
		response = *entry
	} else {
		response, err = p.options.Getter.Get(ctx, target, headers)
		if err != nil {
			return outcome{item: item, err: err}
		}
	}

	result := outcome{item: item, response: response}
	source, err := url.Parse(response.URL)
	if err != nil {
		return result
	}
	contentType := response.Header.Get("Content-Type")
	if parsed, _, parseErr := mime.ParseMediaType(contentType); parseErr == nil {
		contentType = parsed
	}

	switch {
	case item.Kind == model.ResourceTypeDocument || strings.Contains(contentType, "html"):
		htmlResult := discover.FromHTML(source, response.Body)
		mergeSPAEvidence(&result.spa, htmlResult.SPA)
		result.candidates = append(result.candidates, htmlResult.Candidates...)
		textResult := discover.FromJavaScript(source, response.Body, p.options.Analyzer)
		mergeSPAEvidence(&result.spa, textResult.SPA)
		result.findings = append(result.findings, textResult.Findings...)
		result.candidates = append(result.candidates, textResult.Candidates...)
		for _, inline := range htmlResult.InlineScripts {
			inlineResult := discover.FromJavaScript(source, []byte(inline), p.options.Analyzer)
			mergeSPAEvidence(&result.spa, inlineResult.SPA)
			result.findings = append(result.findings, inlineResult.Findings...)
			result.candidates = append(result.candidates, inlineResult.Candidates...)
		}
	case item.Kind == model.ResourceTypeScript || item.Kind == model.ResourceTypeChunk ||
		strings.Contains(contentType, "javascript"):
		jsResult := discover.FromJavaScript(source, response.Body, p.options.Analyzer)
		mergeSPAEvidence(&result.spa, jsResult.SPA)
		result.findings = append(result.findings, jsResult.Findings...)
		result.candidates = append(result.candidates, jsResult.Candidates...)
		result.candidates = append(
			result.candidates,
			discover.FromWebpack(source, response.Body, p.options.Config.Limits.MaxResources)...,
		)
		result.candidates = append(
			result.candidates,
			discover.FromRequireJS(source, response.Body, p.options.Config.Limits.MaxResources)...,
		)
	default:
		textResult := discover.FromJavaScript(source, response.Body, p.options.Analyzer)
		mergeSPAEvidence(&result.spa, textResult.SPA)
		result.findings = append(result.findings, textResult.Findings...)
		result.candidates = append(result.candidates, textResult.Candidates...)
	}
	return result
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
