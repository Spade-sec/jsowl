package jsowl

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	"github.com/youmulijiang/jsowl/internal/analyze"
	"github.com/youmulijiang/jsowl/internal/model"
	"github.com/youmulijiang/jsowl/internal/scope"
)

func BenchmarkAnalyzeLargeBundle(b *testing.B) {
	engine, err := analyze.New(nil, nil)
	if err != nil {
		b.Fatal(err)
	}
	body := bytes.Repeat(
		[]byte(`fetch("/api/users");const token="fixture";`),
		10000,
	)
	reference := analyze.ResourceRef{
		URL: "https://example.test/app.js", Type: model.ResourceTypeScript,
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	for b.Loop() {
		engine.Analyze(reference, body)
	}
}

func BenchmarkCanonical(b *testing.B) {
	parsed, err := url.Parse("HTTPS://Example.TEST:443/a/../b.js?x=1#fragment")
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		scope.Canonical(parsed)
	}
}

func BenchmarkBatch(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		_ *http.Request,
	) {
		writer.Header().Set("Content-Type", "text/html")
		_, _ = writer.Write([]byte("<html></html>"))
	}))
	defer server.Close()
	config := DefaultConfig()
	config.Mode = ModeDirect
	config.Concurrency.Targets = 8
	config.Output.JSON = false
	config.Output.HTML = false
	scanner, err := New(config)
	if err != nil {
		b.Fatal(err)
	}
	targets := make([]Target, 100)
	for index := range targets {
		targets[index] = Target{
			URL: server.URL + "/?target=" + strconv.Itoa(index),
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		count := 0
		for item := range scanner.ScanBatch(context.Background(), targets) {
			if item.Err != nil {
				b.Fatal(item.Err)
			}
			count++
		}
		if count != len(targets) {
			b.Fatalf("results = %d", count)
		}
	}
}
