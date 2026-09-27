package discover

import (
	"strings"

	"github.com/youmulijiang/jsowl/internal/model"
)

// Kind identifies how a discovered URL should be processed by the scan queue.
type Kind string

const (
	KindScript    Kind = "script"
	KindChunk     Kind = "chunk"
	KindEndpoint  Kind = "endpoint"
	KindRoute     Kind = "route"
	KindAsset     Kind = "asset"
	KindSourceMap Kind = "sourcemap"
)

// Candidate describes a URL-like value and the resource that exposed it.
type Candidate struct {
	Raw       string
	Kind      Kind
	SourceURL string
	Depth     int
	// Method is the HTTP method bound to an endpoint candidate, if known.
	Method string
	// Evidence marks extraction strength: full-url, static, or runtime.
	Evidence string
	// Line and Column locate the match inside the source (1-based).
	Line   int
	Column int
	// ContextLines carries the surrounding source lines of the match.
	ContextLines []model.ContextLine
	// BodyParams lists request-body field names for write methods.
	BodyParams []string
	// Spec is the normalized request shape (content type, query and body
	// parameters with per-value evidence) recovered from the AST call site.
	Spec *model.RequestSpec
	// Vendor marks a candidate extracted from a third-party library bundle.
	Vendor bool
	// Source records the extractor that produced this candidate: ast or regex.
	Source string
	// RuleID is the regex rule that matched, when extraction came from rules.
	RuleID string
}

// IsNoiseEndpoint reports whether an endpoint candidate is an extraction
// artifact rather than a real reference — a value consisting of slashes
// only ("//", "///") comes from regexes over comment markers.
func IsNoiseEndpoint(raw string) bool {
	return strings.Trim(raw, "/") == ""
}

// SPAEvidence records static signals that indicate browser rendering may add resources.
type SPAEvidence struct {
	RootNode       bool
	DynamicImport  bool
	HistoryRouting bool
	// HashRouting marks hash-mode routers (createWebHashHistory, mode:"hash"):
	// the SPA serves one document and keeps the route after "#".
	HashRouting   bool
	DynamicScript bool
	Webpack       bool
	RequireJS     bool
	LargeBundle   bool
}

// HTMLResult contains resources, inline scripts, and SPA signals extracted from HTML.
type HTMLResult struct {
	Candidates    []Candidate
	InlineScripts []string
	SPA           SPAEvidence
}

// JSResult contains analyzer output and runtime-loading signals extracted from JavaScript.
type JSResult struct {
	Candidates []Candidate
	Findings   []model.Finding
	SPA        SPAEvidence
}
