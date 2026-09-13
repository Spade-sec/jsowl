package report

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"html/template"

	"github.com/youmulijiang/jsowl/internal/model"
)

//go:embed assets/report.html
var htmlTemplate string

var reportFuncs = template.FuncMap{
	"json": func(v any) template.JS {
		b, err := json.Marshal(v)
		if err != nil {
			b = []byte("null")
		}
		return template.JS(b)
	},
}

// WriteHTML atomically writes a self-contained, escaped interactive report.
func WriteHTML(path string, result *model.Result) error {
	reportTemplate, err := template.New("jsowl-report").Funcs(reportFuncs).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("parse HTML report template: %w", err)
	}
	var output bytes.Buffer
	if err := reportTemplate.Execute(&output, result); err != nil {
		return fmt.Errorf("render HTML report: %w", err)
	}
	return writeAtomic(path, output.Bytes())
}
