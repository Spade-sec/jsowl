package collect

import (
	"context"
	"net/http"
	"net/url"
	"time"
)

// Response is the bounded representation of one collected HTTP response.
type Response struct {
	URL        string
	StatusCode int
	Header     http.Header
	Body       []byte
	Truncated  bool
	Duration   time.Duration
}

// Getter retrieves one URL with GET and returns a bounded response.
type Getter interface {
	Get(context.Context, *url.URL, http.Header) (Response, error)
}

// NetworkRecord describes one response observed by a browser collector.
type NetworkRecord struct {
	URL          string
	StatusCode   int
	ContentType  string
	ResourceType string
}

// BrowserResult contains the rendered document and resources observed at runtime.
type BrowserResult struct {
	HTML    []byte
	URLs    []string
	Network []NetworkRecord
}

// BrowserCollector renders one entry URL and observes its runtime resources.
type BrowserCollector interface {
	Collect(context.Context, *url.URL, http.Header) (BrowserResult, error)
}
