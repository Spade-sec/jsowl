package jsowl

import (
	"context"
	"errors"
	"net/http"
	"net/url"

	"github.com/youmulijiang/jsowl/internal/collect"
)

// RequestEvent describes a completed HTTP collection (after retries) or browser
// page request. Size counts collected/decoded body bytes, not Content-Length.
type RequestEvent = collect.RequestEvent

// SetRequestSink configures ordered, lossless request delivery. Set it before
// scanning. The caller must drain the channel until ScanBatch closes, then may
// close it. A full channel applies backpressure to collection workers.
func (s *Scanner) SetRequestSink(sink chan<- RequestEvent) { s.requestSink = sink }

type reportingGetter struct {
	collect.Getter
	sink chan<- RequestEvent
}

func (g reportingGetter) Get(ctx context.Context, target *url.URL, headers http.Header) (collect.Response, error) {
	response, err := g.Getter.Get(ctx, target, headers)
	event := RequestEvent{Method: http.MethodGet, URL: target.String(), Success: err == nil}
	if err == nil {
		if response.URL != "" {
			event.URL = response.URL
		}
		event.StatusCode = response.StatusCode
		event.Size = int64(len(response.Body))
	}
	g.sink <- event
	return response, err
}

// Post forwards the empty-JSON probe to a collector that supports it, so the
// request stream carries the real verb instead of reporting it as a GET.
func (g reportingGetter) Post(
	ctx context.Context,
	target *url.URL,
	headers http.Header,
	body []byte,
) (collect.Response, error) {
	poster, ok := g.Getter.(collect.Poster)
	if !ok {
		return collect.Response{}, errors.New("collector does not support POST")
	}
	response, err := poster.Post(ctx, target, headers, body)
	event := RequestEvent{Method: http.MethodPost, URL: target.String(), Success: err == nil}
	if err == nil {
		if response.URL != "" {
			event.URL = response.URL
		}
		event.StatusCode = response.StatusCode
		event.Size = int64(len(response.Body))
	}
	g.sink <- event
	return response, err
}
