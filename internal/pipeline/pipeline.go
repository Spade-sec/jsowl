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

type outcome struct {
	item       scheduler.Item
	response   collect.Response
	err        error
	findings   []model.Finding
	candidates []discover.Candidate
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
	root, err := url.Parse(target.URL)
	if err != nil {
		return nil, fmt.Errorf("parse target URL: %w", err)
	}
	targetScope, err := scope.New(root, p.options.Config.Scope)
	if err != nil {
		return nil, err
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
	queue.Add(scheduler.Item{
		URL: scope.Canonical(root), Kind: model.ResourceTypeDocument,
	})

	endpointIndex := make(map[string]int)
	findingSeen := make(map[string]struct{})
	for queue.Len() > 0 {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		batch := queue.Take(p.options.Config.Concurrency.ResourcesPerTarget)
		outcomes := p.collectBatch(ctx, batch, headers)
		for _, collected := range outcomes {
			if collected.err != nil {
				if collected.item.Depth == 0 {
					return result, collected.err
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

			resource := model.Resource{
				URL:         collected.response.URL,
				Type:        collected.item.Kind,
				SourceURL:   collected.item.SourceURL,
				StatusCode:  collected.response.StatusCode,
				ContentType: collected.response.Header.Get("Content-Type"),
				Size:        int64(len(collected.response.Body)),
				Depth:       collected.item.Depth,
			}
			result.Resources = append(result.Resources, resource)
			if collected.response.Truncated {
				result.Issues = append(result.Issues, model.Issue{
					Code: "body_truncated", Stage: "collect", URL: resource.URL,
					Message: "response exceeded max_body_size",
				})
			}
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
	return result, nil
}

func (p *Pipeline) collectBatch(
	ctx context.Context,
	batch []scheduler.Item,
	headers http.Header,
) []outcome {
	outcomes := make([]outcome, len(batch))
	var wait sync.WaitGroup
	wait.Add(len(batch))
	for index, item := range batch {
		go func() {
			defer wait.Done()
			outcomes[index] = p.collectOne(ctx, item, headers)
		}()
	}
	wait.Wait()
	return outcomes
}

func (p *Pipeline) collectOne(
	ctx context.Context,
	item scheduler.Item,
	headers http.Header,
) outcome {
	target, err := url.Parse(item.URL)
	if err != nil {
		return outcome{item: item, err: err}
	}
	response, err := p.options.Getter.Get(ctx, target, headers)
	if err != nil {
		return outcome{item: item, err: err}
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
		result.candidates = append(result.candidates, htmlResult.Candidates...)
		textResult := discover.FromJavaScript(source, response.Body, p.options.Analyzer)
		result.findings = append(result.findings, textResult.Findings...)
		result.candidates = append(result.candidates, textResult.Candidates...)
		for _, inline := range htmlResult.InlineScripts {
			inlineResult := discover.FromJavaScript(source, []byte(inline), p.options.Analyzer)
			result.findings = append(result.findings, inlineResult.Findings...)
			result.candidates = append(result.candidates, inlineResult.Candidates...)
		}
	case item.Kind == model.ResourceTypeScript || item.Kind == model.ResourceTypeChunk ||
		strings.Contains(contentType, "javascript"):
		jsResult := discover.FromJavaScript(source, response.Body, p.options.Analyzer)
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
		result.findings = append(result.findings, textResult.Findings...)
		result.candidates = append(result.candidates, textResult.Candidates...)
	}
	return result
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
