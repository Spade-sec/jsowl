package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReportInteractionsRenderedAndFilterAttributesEscaped(t *testing.T) {
	result := sampleResult()
	result.Findings[0].RuleName = `Token" data-injected="yes`
	directory := t.TempDir()
	if err := WriteSplitReports(directory, result); err != nil {
		t.Fatal(err)
	}
	if err := WriteHTML(filepath.Join(directory, "report.html"), result); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"report.html", "API报告.html", "URL报告.html", "敏感信息报告.html", "参数报告.html", "路由报告.html", "资源报告.html"} {
		data, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			t.Fatal(err)
		}
		page := string(data)
		if !strings.Contains(page, "function bindReportSort(") || strings.Contains(page, "{{interactions}}") {
			t.Errorf("%s missing rendered sorting controller", name)
		}
		if name == "敏感信息报告.html" {
			for _, want := range []string{`id="sensitive-filters"`, `data-filter="severity"`, `data-filter="rule"`, `data-filter="source"`, `type="search"`, `id="sensitive-count"`, htmlEscape(result.Findings[0].RuleName)} {
				if !strings.Contains(page, want) {
					t.Errorf("sensitive report missing %q", want)
				}
			}
			if strings.Contains(page, `data-injected="yes`) {
				t.Error("finding escaped its filter attribute")
			}
		}
	}
}
