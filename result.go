package jsowl

import (
	"github.com/youmulijiang/jsowl/internal/model"
	"github.com/youmulijiang/jsowl/internal/report"
)

// Result is the deterministic output of one target scan.
type Result = model.Result

// Issue records a non-fatal diagnostic event.
type Issue = model.Issue

// Resource records one collected document, script, chunk, or API.
type Resource = model.Resource

// Endpoint records one extracted route or API and optional GET status.
type Endpoint = model.Endpoint

// Finding records one URL or sensitive-information rule match.
type Finding = model.Finding

// Statistics summarizes a scan result.
type Statistics = model.Statistics

// BrowserStatus describes browser usage or auto-mode degradation.
type BrowserStatus = model.BrowserStatus

// ResourceType classifies collected resources.
type ResourceType = model.ResourceType

const (
	ResourceTypeDocument = model.ResourceTypeDocument
	ResourceTypeScript   = model.ResourceTypeScript
	ResourceTypeChunk    = model.ResourceTypeChunk
	ResourceTypeAPI      = model.ResourceTypeAPI
	ResourceTypeRoute    = model.ResourceTypeRoute
	ResourceTypeAsset    = model.ResourceTypeAsset
	ResourceTypeExternal = model.ResourceTypeExternal
)

// WriteJSONReport atomically writes the complete scan result as JSON.
func WriteJSONReport(path string, result *Result) error {
	return report.WriteJSON(path, result)
}

// WriteHTMLReport atomically writes a self-contained interactive HTML report.
func WriteHTMLReport(path string, result *Result) error {
	return report.WriteHTML(path, result)
}
