package direct

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/youmulijiang/jsowl/internal/model"
)

func TestClientUsesGETHeadersCookiesAndBodyLimit(t *testing.T) {
	type observedRequest struct {
		method string
		header string
		cookie string
	}
	observed := make(chan observedRequest, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		observed <- observedRequest{
			method: request.Method,
			header: request.Header.Get("X-Test"),
			cookie: request.Header.Get("Cookie"),
		}
		writer.Header().Set("Content-Type", "application/javascript")
		_, _ = writer.Write([]byte(strings.Repeat("x", 32)))
	}))
	defer server.Close()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	target := parseDirectURL(t, server.URL+"/app.js")
	jar.SetCookies(target, []*http.Cookie{{Name: "session", Value: "abc"}})
	client, err := New(model.RequestConfig{Timeout: time.Second}, 16, jar)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	headers := make(http.Header)
	headers.Set("X-Test", "value")
	response, err := client.Get(context.Background(), target, headers)
	if err != nil {
		t.Fatal(err)
	}

	request := <-observed
	if request.method != http.MethodGet {
		t.Fatalf("method = %q, want GET", request.method)
	}
	if request.header != "value" || request.cookie != "session=abc" {
		t.Fatalf("observed request = %#v", request)
	}
	if !response.Truncated || len(response.Body) != 16 {
		t.Fatalf("body len=%d truncated=%t", len(response.Body), response.Truncated)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", response.StatusCode)
	}
	if response.Header.Get("Content-Type") != "application/javascript" {
		t.Fatalf("content type = %q", response.Header.Get("Content-Type"))
	}
}

func TestClientStopsRedirectWhenOriginChanges(t *testing.T) {
	externalRequests := 0
	external := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		externalRequests++
	}))
	defer external.Close()

	start := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, external.URL+"/outside", http.StatusFound)
	}))
	defer start.Close()

	client, err := New(model.RequestConfig{Timeout: time.Second}, 1024, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	response, err := client.Get(
		context.Background(),
		parseDirectURL(t, start.URL+"/start"),
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", response.StatusCode)
	}
	if externalRequests != 0 {
		t.Fatalf("external requests = %d, want 0", externalRequests)
	}
}

func TestClientHonorsContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		<-request.Context().Done()
	}))
	defer server.Close()

	client, err := New(model.RequestConfig{Timeout: time.Second}, 1024, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err = client.Get(ctx, parseDirectURL(t, server.URL), nil)
	if err == nil || !strings.Contains(err.Error(), "context deadline exceeded") {
		t.Fatalf("Get() error = %v", err)
	}
}

func TestClientRetriesTransportFailureOnly(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		if attempts.Add(1) == 1 {
			hijacker, ok := writer.(http.Hijacker)
			if !ok {
				t.Error("response writer does not support hijacking")
				return
			}
			connection, _, err := hijacker.Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			_ = connection.Close()
			return
		}
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("ok"))
	}))
	defer server.Close()

	client, err := New(model.RequestConfig{Timeout: time.Second, Retry: 1}, 1024, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	response, err := client.Get(context.Background(), parseDirectURL(t, server.URL), nil)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || string(response.Body) != "ok" {
		t.Fatalf("response = %#v", response)
	}
	if attempts.Load() != 2 {
		t.Fatalf("attempts = %d, want 2", attempts.Load())
	}
}

func parseDirectURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}
