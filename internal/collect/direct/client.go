package direct

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/surf"
	"github.com/youmulijiang/jsowl/internal/collect"
	"github.com/youmulijiang/jsowl/internal/model"
)

// Client adapts a surf session to JsOwl's bounded GET collector interface.
type Client struct {
	surfClient *surf.Client
	httpClient *http.Client
	maxBody    int64
	retry      int
}

// New creates a surf-backed client with session cookies and same-origin redirects.
func New(
	config model.RequestConfig,
	maxBodySize int64,
	jar http.CookieJar,
) (*Client, error) {
	if config.Timeout <= 0 {
		return nil, errors.New("request timeout must be positive")
	}

	builder := surf.NewClient().Builder().Session()
	if config.Proxy != "" {
		builder = builder.Proxy(g.String(config.Proxy))
	}
	built := builder.Build()
	if built.IsErr() {
		return nil, fmt.Errorf("build surf client: %w", built.Err())
	}
	surfClient := built.Ok()
	httpClient := surfClient.Std()
	httpClient.Timeout = config.Timeout
	if jar != nil {
		httpClient.Jar = jar
	}
	httpClient.CheckRedirect = sameOriginRedirect

	return &Client{
		surfClient: surfClient,
		httpClient: httpClient,
		maxBody:    maxBodySize,
		retry:      max(0, config.Retry),
	}, nil
}

// Get sends one GET request and reads at most the configured number of body bytes.
func (c *Client) Get(
	ctx context.Context,
	target *url.URL,
	headers http.Header,
) (collect.Response, error) {
	if target == nil {
		return collect.Response{}, errors.New("target URL is nil")
	}
	started := time.Now()
	var response *http.Response
	var err error
	for attempt := 0; attempt <= c.retry; attempt++ {
		request, requestErr := http.NewRequestWithContext(
			ctx,
			http.MethodGet,
			target.String(),
			nil,
		)
		if requestErr != nil {
			return collect.Response{}, fmt.Errorf("create GET request: %w", requestErr)
		}
		request.Header = headers.Clone()

		response, err = c.httpClient.Do(request)
		if err == nil {
			break
		}
		if ctx.Err() != nil || attempt == c.retry {
			return collect.Response{}, fmt.Errorf("GET %s: %w", target, err)
		}
	}
	defer response.Body.Close()

	// maxBody <= 0 means no cap: read the whole body without truncation.
	if c.maxBody <= 0 {
		body, err := io.ReadAll(response.Body)
		if err != nil {
			return collect.Response{}, fmt.Errorf("read %s: %w", target, err)
		}
		return collect.Response{
			URL:        response.Request.URL.String(),
			StatusCode: response.StatusCode,
			Header:     response.Header.Clone(),
			Body:       body,
			Duration:   time.Since(started),
		}, nil
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, c.maxBody+1))
	if err != nil {
		return collect.Response{}, fmt.Errorf("read %s: %w", target, err)
	}
	truncated := int64(len(body)) > c.maxBody
	if truncated {
		body = body[:c.maxBody]
	}

	return collect.Response{
		URL:        response.Request.URL.String(),
		StatusCode: response.StatusCode,
		Header:     response.Header.Clone(),
		Body:       body,
		Truncated:  truncated,
		Duration:   time.Since(started),
	}, nil
}

// Close releases surf transports and idle connections owned by the client.
func (c *Client) Close() error {
	if c == nil {
		return nil
	}
	if c.httpClient != nil {
		c.httpClient.CloseIdleConnections()
	}
	if c.surfClient != nil {
		return c.surfClient.Close()
	}
	return nil
}

func sameOriginRedirect(request *http.Request, via []*http.Request) error {
	if len(via) == 0 || originsMatch(via[0].URL, request.URL) {
		return nil
	}
	return http.ErrUseLastResponse
}

func originsMatch(left, right *url.URL) bool {
	return strings.EqualFold(left.Scheme, right.Scheme) &&
		strings.EqualFold(left.Hostname(), right.Hostname()) &&
		effectivePort(left) == effectivePort(right)
}

func effectivePort(target *url.URL) string {
	if port := target.Port(); port != "" {
		return port
	}
	if strings.EqualFold(target.Scheme, "https") {
		return "443"
	}
	return "80"
}
