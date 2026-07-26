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
