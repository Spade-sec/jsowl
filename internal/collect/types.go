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
	// Method is the observed HTTP verb; POST/PUT/PATCH matter most because
	// JsOwl itself never sends them.
	Method string
	// InitiatorURL, Line and Column locate the script that issued the
	// request, when the browser reported a stack.
	InitiatorURL string
	Line         int
	Column       int
}

// BrowserRoute is one framework route observed at runtime.
type BrowserRoute struct {
	Path   string
	Name   string
	Source string // vue, history-hook, or dom
}

// BrowserResult contains the rendered document and resources observed at runtime.
type BrowserResult struct {
	HTML []byte
	URLs []string
	// Scripts lists JavaScript the page loaded, including extension-less
	// script URLs that a generic URL list cannot classify.
	Scripts []string
	Routes  []BrowserRoute
	Network []NetworkRecord
	Cookies []*http.Cookie
}

// BrowserCollector renders one entry URL and observes its runtime resources.
type BrowserCollector interface {
	Collect(context.Context, *url.URL, http.Header) (BrowserResult, error)
}
