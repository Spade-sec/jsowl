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
}

// New validates configuration and constructs a reusable Scanner.
func New(config Config) (*Scanner, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	engine, err := analyze.New(config.Rules.Custom, config.Rules.Disabled)
	if err != nil {
		return nil, err
	}
	return &Scanner{
		config: config, analyzer: engine, browserFactory: func(
			config model.BrowserConfig,
		) (collect.BrowserCollector, error) {
			return browser.New(config)
		},
	}, nil
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
	})
	var result *model.Result
	switch s.config.Mode {
	case ModeDirect:
		result, _, err = resourcePipeline.RunDetailed(
			targetContext, target, headers, nil, nil, nil,
		)
	case ModeBrowser:
		result, err = s.scanWithBrowser(
			targetContext, root, target, headers, resourcePipeline, nil,
		)
	case ModeAuto:
		var evidence discover.SPAEvidence
		result, evidence, err = resourcePipeline.RunDetailed(
			targetContext, target, headers, nil, nil, nil,
		)
		if err == nil && needsBrowser(evidence, result) {
			var browserResult *model.Result
			browserResult, err = s.scanWithBrowser(
				targetContext, root, target, headers, resourcePipeline,
				collectedURLs(result),
			)
			if err != nil {
				result.BrowserStatus = model.BrowserStatus{
					Attempted: true,
					Degraded:  true,
					Reason:    err.Error(),
				}
				err = nil
			} else {
				result = mergeResults(result, browserResult)
				result.BrowserStatus = model.BrowserStatus{
					Attempted: true, Used: true,
				}
			}
		}
	}
	if result != nil {
		result.StartedAt = started
		result.FinishedAt = time.Now()
		result.UserAgent = userAgent
	}
	return result, err
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
	resourcePipeline *pipeline.Pipeline,
	previouslySeen []string,
) (*model.Result, error) {
	collector, err := s.browserFactory(s.config.Browser)
	if err != nil {
		return nil, fmt.Errorf("create browser collector: %w", err)
	}
	rendered, err := collector.Collect(ctx, root, headers)
	if err != nil {
		return nil, fmt.Errorf("collect browser page: %w", err)
	}
	entry := collect.Response{
		URL: root.String(), StatusCode: http.StatusOK,
		Header: http.Header{"Content-Type": {"text/html; charset=utf-8"}},
		Body:   rendered.HTML,
	}
	seeds := browserSeeds(rendered)
	result, _, err := resourcePipeline.RunDetailed(
		ctx, target, headers, &entry, seeds, previouslySeen,
	)
	if result != nil {
		result.BrowserStatus = model.BrowserStatus{Attempted: true, Used: true}
	}
	return result, err
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

func browserSeeds(rendered collect.BrowserResult) []pipeline.Seed {
	seen := make(map[string]model.ResourceType)
	for _, record := range rendered.Network {
		kind := model.ResourceType("")
		switch strings.ToLower(record.ResourceType) {
		case "script":
			kind = model.ResourceTypeScript
		case "xhr", "fetch":
			kind = model.ResourceTypeAPI
		}
		if kind == "" && strings.Contains(
			strings.ToLower(record.ContentType), "javascript",
		) {
			kind = model.ResourceTypeScript
		}
		if kind != "" {
			seen[record.URL] = kind
		}
	}
	for _, raw := range rendered.URLs {
		parsed, err := url.Parse(raw)
		if err == nil && isJavaScriptExtension(parsed.Path) {
			seen[raw] = model.ResourceTypeScript
		}
	}
	seeds := make([]pipeline.Seed, 0, len(seen))
	for raw, kind := range seen {
		seeds = append(seeds, pipeline.Seed{URL: raw, Kind: kind})
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
