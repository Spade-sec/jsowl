package jsowl

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"time"

	"github.com/youmulijiang/jsowl/internal/analyze"
	"github.com/youmulijiang/jsowl/internal/collect/direct"
	"github.com/youmulijiang/jsowl/internal/model"
	"github.com/youmulijiang/jsowl/internal/pipeline"
	"github.com/youmulijiang/jsowl/internal/ua"
)

// Scanner owns immutable scan configuration and a compiled extraction engine.
type Scanner struct {
	config   model.Config
	analyzer *analyze.Engine
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
	return &Scanner{config: config, analyzer: engine}, nil
}

// Scan executes an isolated scan for one target and returns partial diagnostics on failure.
func (s *Scanner) Scan(ctx context.Context, target Target) (*Result, error) {
	if s.config.Mode == ModeBrowser {
		return nil, fmt.Errorf("browser mode is not available until a browser collector is configured")
	}
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
	result, err := resourcePipeline.Run(targetContext, target, headers)
	if result != nil {
		result.StartedAt = started
		result.FinishedAt = time.Now()
		result.UserAgent = userAgent
	}
	return result, err
}
