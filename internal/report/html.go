package report

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"html/template"
	"time"

	"github.com/youmulijiang/jsowl/internal/analyze"
	"github.com/youmulijiang/jsowl/internal/model"
)

//go:embed assets/report.html
var htmlTemplate string

//go:embed assets/interactions.js
var reportInteractions string

//go:embed assets/dashboard.js
var reportDashboard string

//go:embed assets/charts.js
var reportCharts string

//go:embed assets/csv.js
var reportCSV string

// reportView is what the interactive template renders: the untouched scan
// result plus the aggregated summary.
type reportView struct {
	Result  *model.Result
	Summary reportSummary
}

// endpointView is one endpoint plus its reconstructed request packet. The
// packet is rendered with the same analyze.RenderPacket the API report uses,
// so the main report never invents a second, divergent reconstruction.
type endpointView struct {
	model.Endpoint
	Packet string `json:"packet,omitempty"`
}

func endpointViews(result *model.Result) []endpointView {
	views := make([]endpointView, 0, len(result.Endpoints))
	for _, endpoint := range result.Endpoints {
		views = append(views, endpointView{
			Endpoint: endpoint,
			Packet:   analyze.RenderPacket(endpoint.Template),
		})
	}
	return views
}

var reportFuncs = template.FuncMap{
	"interactions": func() template.JS { return template.JS(reportInteractions) },
	"charts":       func() template.JS { return template.JS(reportCharts) },
	"dashboard":    func() template.JS { return template.JS(reportDashboard) },
	"csv":          func() template.JS { return template.JS(reportCSV) },
	"endpoints":    func(result *model.Result) template.JS { return toJSON(endpointViews(result)) },
	"json":         toJSON,
}

func toJSON(v any) template.JS {
	b, err := json.Marshal(v)
	if err != nil {
		b = []byte("null")
	}
	return template.JS(b)
}

// WriteHTML atomically writes a self-contained, escaped interactive report.
// The embedded summary is computed once per write, so the dashboard charts,
// CSV export and print view all read the same numbers as the split reports.
func WriteHTML(path string, result *model.Result) error {
	return writeHTMLReport(path, result, time.Now())
}

// writeHTMLReport takes the generation timestamp so tests can pin the
// reported "报告生成时间".
func writeHTMLReport(path string, result *model.Result, generatedAt time.Time) error {
	reportTemplate, err := template.New("jsowl-report").Funcs(reportFuncs).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("parse HTML report template: %w", err)
	}
	var output bytes.Buffer
	view := reportView{Result: result, Summary: buildSummary(result, generatedAt)}
	if err := reportTemplate.Execute(&output, view); err != nil {
		return fmt.Errorf("render HTML report: %w", err)
	}
	return writeAtomic(path, output.Bytes())
}
