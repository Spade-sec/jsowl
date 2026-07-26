package discover

import "github.com/youmulijiang/jsowl/internal/model"

// Kind identifies how a discovered URL should be processed by the scan queue.
type Kind string

const (
	KindScript   Kind = "script"
	KindChunk    Kind = "chunk"
	KindEndpoint Kind = "endpoint"
	KindRoute    Kind = "route"
	KindAsset    Kind = "asset"
)

// Candidate describes a URL-like value and the resource that exposed it.
type Candidate struct {
	Raw       string
	Kind      Kind
	SourceURL string
	Depth     int
}

// SPAEvidence records static signals that indicate browser rendering may add resources.
type SPAEvidence struct {
	RootNode       bool
	DynamicImport  bool
	HistoryRouting bool
	DynamicScript  bool
	Webpack        bool
	RequireJS      bool
	LargeBundle    bool
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
