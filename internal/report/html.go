package report

import (
	"bytes"
	_ "embed"
	"fmt"
	"html/template"

	"github.com/youmulijiang/jsowl/internal/model"
)

//go:embed assets/report.html
var htmlTemplate string

// WriteHTML atomically writes a self-contained, escaped interactive report.
func WriteHTML(path string, result *model.Result) error {
	reportTemplate, err := template.New("jsowl-report").Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("parse HTML report template: %w", err)
	}
	var output bytes.Buffer
	if err := reportTemplate.Execute(&output, result); err != nil {
		return fmt.Errorf("render HTML report: %w", err)
	}
	return writeAtomic(path, output.Bytes())
}
