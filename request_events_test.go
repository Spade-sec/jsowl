package jsowl

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/youmulijiang/jsowl/internal/collect"
)

type eventGetter func(context.Context, *url.URL, http.Header) (collect.Response, error)

func (f eventGetter) Get(ctx context.Context, u *url.URL, h http.Header) (collect.Response, error) {
	return f(ctx, u, h)
}

func TestRequestEventsArriveBeforeSlowConcurrentRequest(t *testing.T) {
	blocked, release := make(chan struct{}), make(chan struct{})
	done := make(chan struct{})
	defer func() { close(release); <-done }()
	events := make(chan RequestEvent, 2)
	getter := reportingGetter{sink: events, Getter: eventGetter(func(_ context.Context, u *url.URL, _ http.Header) (collect.Response, error) {
		if u.Path == "/slow" {
			close(blocked)
			<-release
		}
		return collect.Response{URL: u.String(), StatusCode: 403, Body: []byte("denied")}, nil
	})}
	slow, _ := url.Parse("http://example.test/slow")
	fast, _ := url.Parse("http://example.test/fast")
	go func() { defer close(done); getter.Get(context.Background(), slow, nil) }()
	<-blocked
	getter.Get(context.Background(), fast, nil)
	select {
	case e := <-events:
		if e.URL != fast.String() || !e.Success || e.StatusCode != 403 || e.Size != 6 {
			t.Fatalf("event = %+v", e)
		}
	case <-time.After(time.Second):
		t.Fatal("fast request output waited for slow request")
	}
	// The buffered sink also permits the slow worker to exit after release.
}

func TestRequestEventReportsFailureAndBackpressure(t *testing.T) {
	events := make(chan RequestEvent)
	wantErr := errors.New("connection failed")
	getter := reportingGetter{sink: events, Getter: eventGetter(func(context.Context, *url.URL, http.Header) (collect.Response, error) {
		return collect.Response{}, wantErr
	})}
	u, _ := url.Parse("http://example.test/fail")
	done := make(chan error, 1)
	go func() { _, err := getter.Get(context.Background(), u, nil); done <- err }()
	select {
	case <-done:
		t.Fatal("request event was dropped")
	case <-time.After(20 * time.Millisecond):
	}
	e := <-events
	if e.Success || e.StatusCode != 0 || e.Size != 0 || e.URL != u.String() {
		t.Fatalf("failure event = %+v", e)
	}
	if err := <-done; !errors.Is(err, wantErr) {
		t.Fatalf("error = %v", err)
	}
}
