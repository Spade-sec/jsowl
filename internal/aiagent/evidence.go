// Package aiagent implements the post-scan AI analysis phase (ai.mode:
// agent). After every collection, probe and deterministic analysis pass has
// finished, an agent loop lets the model walk the complete evidence — the
// scan result, endpoint specs, findings and the JavaScript bodies persisted
// under the report directory — through read-only tools before it writes its
// verdict. The agent can never touch the network: its tools read local
// state only, so a prompt injection planted in the target's JavaScript
// cannot steer the scan anywhere.
package aiagent

import (
	"strings"
	"sync"

	"github.com/youmulijiang/jsowl/internal/model"
	"github.com/youmulijiang/jsowl/internal/storage"
)

// maxSourceBytes caps one script body kept in the evidence cache. Bundles
// beyond it are searchable only in their first maxSourceBytes bytes, which
// keeps one minified monster bundle from pinning the agent's memory.
const maxSourceBytes = 2 << 20

// Evidence is the read-only evidence base the agent's tools query. Source
// bodies load lazily from the report directory on first use and are cached;
// a body that was never persisted (truncated, storage failure, download_js
// off) is simply absent and tools say so instead of guessing.
type Evidence struct {
	result    *model.Result
	reportDir string

	mu      sync.Mutex
	sources map[string]string // resource URL -> body ("" = known absent)

	// loadSource reads one persisted body relative to the report directory;
	// storage.LoadJS in production, a stub in tests.
	loadSource func(reportDirectory, relativePath string) ([]byte, error)
}

// NewEvidence builds the evidence base over one finished scan result.
func NewEvidence(result *model.Result) *Evidence {
	return &Evidence{
		result:     result,
		reportDir:  result.ReportDirectory,
		sources:    map[string]string{},
		loadSource: storage.LoadJS,
	}
}

// Result exposes the underlying scan result (read-only by convention).
func (e *Evidence) Result() *model.Result { return e.result }

// source returns the persisted body of one source URL, loading and caching
// it on first request. ok is false when the URL has no persisted body.
func (e *Evidence) source(sourceURL string) (string, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if body, cached := e.sources[sourceURL]; cached {
		return body, body != ""
	}
	var resource *model.Resource
	for i := range e.result.Resources {
		if e.result.Resources[i].URL == sourceURL && e.result.Resources[i].LocalPath != "" {
			resource = &e.result.Resources[i]
			break
		}
	}
	if resource == nil || e.reportDir == "" || e.loadSource == nil {
		e.sources[sourceURL] = ""
		return "", false
	}
	body, err := e.loadSource(e.reportDir, resource.LocalPath)
	if err != nil || len(body) == 0 {
		e.sources[sourceURL] = ""
		return "", false
	}
	if len(body) > maxSourceBytes {
		body = body[:maxSourceBytes]
	}
	text := string(body)
	e.sources[sourceURL] = text
	return text, true
}

// sourceURLs lists the URLs of every script, chunk or source map resource
// that carries a persisted body, sorted for deterministic tool output.
func (e *Evidence) sourceURLs() []string {
	var urls []string
	for i := range e.result.Resources {
		resource := &e.result.Resources[i]
		if resource.LocalPath == "" {
			continue
		}
		switch resource.Type {
		case model.ResourceTypeScript, model.ResourceTypeChunk, model.ResourceTypeSourceMap:
			urls = append(urls, resource.URL)
		}
	}
	return urls
}

// lineWindow extracts the 1-based lines [start, end] of a body, tolerant of
// CRLF endings. out-of-range bounds clamp; a zero or negative start yields
// nothing.
func lineWindow(body string, start, end int) []string {
	if start < 1 {
		start = 1
	}
	if end < start {
		return nil
	}
	var lines []string
	current := 1
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if current >= start && current <= end {
			lines = append(lines, line)
		}
		current++
		if current > end {
			break
		}
	}
	return lines
}
