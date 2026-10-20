package browser

import (
	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
	"github.com/youmulijiang/jsowl/internal/collect"
)

// SetRequestSink enables lossless completion events for page network requests.
// Configure it before Collect; the consumer must drain it throughout collection.
func (c *Collector) SetRequestSink(sink chan<- collect.RequestEvent) { c.requestSink = sink }

// One event subscription processes messages in order, without shared map writes.
// Cleanup waits for the observer so no sender outlives Collect.
func observeRequestOutput(page *rod.Page, sink chan<- collect.RequestEvent) func() {
	if sink == nil {
		return func() {}
	}
	observedPage, cancel := page.WithCancel()
	requests := make(map[proto.NetworkRequestID]collect.RequestEvent)
	finish := func(id proto.NetworkRequestID, success bool) {
		if event, ok := requests[id]; ok {
			event.Success = success
			if !success {
				event.StatusCode = 0
				event.Size = 0
			}
			sink <- event
			delete(requests, id)
		}
	}
	wait := observedPage.EachEvent(
		func(e *proto.NetworkRequestWillBeSent) {
			if e.Request == nil {
				return
			}
			if e.RedirectResponse != nil {
				if event, ok := requests[e.RequestID]; ok {
					event.StatusCode = int(e.RedirectResponse.Status)
					requests[e.RequestID] = event
					finish(e.RequestID, true)
				}
			}
			requests[e.RequestID] = collect.RequestEvent{Method: e.Request.Method, URL: e.Request.URL}
		},
		func(e *proto.NetworkResponseReceived) {
			if event, ok := requests[e.RequestID]; ok && e.Response != nil {
				event.StatusCode = int(e.Response.Status)
				requests[e.RequestID] = event
			}
		},
		func(e *proto.NetworkDataReceived) {
			if event, ok := requests[e.RequestID]; ok {
				event.Size += int64(e.DataLength)
				requests[e.RequestID] = event
			}
		},
		func(e *proto.NetworkLoadingFinished) { finish(e.RequestID, true) },
		func(e *proto.NetworkLoadingFailed) { finish(e.RequestID, false) },
	)
	done := make(chan struct{})
	go func() { defer close(done); wait() }()
	return func() { cancel(); <-done }
}
