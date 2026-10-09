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

// ParamHit records one parameter name extracted from source code together
// with its extraction scenario (object property, destructuring, function
// parameter, ...).
type ParamHit = model.ParamHit

// Parameter extraction scenarios; see ParamHit.Scenario.
const (
	ParamScenarioObjectProperty     = model.ParamScenarioObjectProperty
	ParamScenarioDestructuring      = model.ParamScenarioDestructuring
	ParamScenarioNestedDestructurin = model.ParamScenarioNestedDestructurin
	ParamScenarioFunctionParam      = model.ParamScenarioFunctionParam
	ParamScenarioVariable           = model.ParamScenarioVariable
	ParamScenarioAPIRequest         = model.ParamScenarioAPIRequest
	ParamScenarioURLQuery           = model.ParamScenarioURLQuery
	ParamScenarioConfigObject       = model.ParamScenarioConfigObject
	ParamScenarioRouteParam         = model.ParamScenarioRouteParam
)

// ParamScenarioLabel renders a scenario code in its report-facing form.
func ParamScenarioLabel(code string) string { return model.ParamScenarioLabel(code) }

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

// ProbeEvent is emitted the moment one API probe completes; see Scanner.SetProbeSink.
type ProbeEvent = model.ProbeEvent

// WriteJSONReport atomically writes the complete scan result as JSON.
func WriteJSONReport(path string, result *Result) error {
	return report.WriteJSON(path, result)
}

// WriteHTMLReport atomically writes a self-contained interactive HTML report.
func WriteHTMLReport(path string, result *Result) error {
	return report.WriteHTML(path, result)
}

// WriteTextReports atomically writes api绝对路径.txt, api相对路径.txt,
// 参数.txt, 敏感信息.txt and 路由.txt into the target's report directory.
func WriteTextReports(directory string, result *Result) error {
	return report.WriteTextReports(directory, result)
}

// WriteSplitReports writes the split topic HTML reports (API/敏感信息/参数/
// 资源) plus a navigation index into the target's report directory.
func WriteSplitReports(directory string, result *Result) error {
	return report.WriteSplitReports(directory, result)
}
