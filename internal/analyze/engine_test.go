package analyze

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/youmulijiang/jsowl/internal/model"
)

func TestAnalyzeReportsCaptureLocationAndCandidate(t *testing.T) {
	engine, err := New([]model.Rule{{
		ID:       "test.api",
		Name:     "API",
		Category: model.RuleCategoryURL,
		Severity: model.SeverityInfo,
		Pattern:  `fetch\(["']([^"']+)["']`,
		Group:    1,
		Enabled:  true,
	}}, builtinIDs())
	if err != nil {
		t.Fatal(err)
	}

	findings, candidates := engine.Analyze(ResourceRef{
		URL:  "https://example.test/app.js",
		Type: model.ResourceTypeScript,
	}, []byte("const ready = true;\nfetch('/api/users')"))

	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
	if findings[0].Value != "/api/users" {
		t.Fatalf("Value = %q", findings[0].Value)
	}
	if findings[0].Line != 2 || findings[0].Column != 8 {
		t.Fatalf("location = %d:%d, want 2:8", findings[0].Line, findings[0].Column)
	}
	if len(candidates) != 1 || candidates[0].Raw != "/api/users" {
		t.Fatalf("candidates = %#v", candidates)
	}
}

func TestAnalyzeDeduplicatesSameRuleSourceAndValue(t *testing.T) {
	engine, err := New([]model.Rule{{
		ID:       "test.path",
		Name:     "Path",
		Category: model.RuleCategoryURL,
		Severity: model.SeverityInfo,
		Pattern:  `["'](/same)["']`,
		Group:    1,
		Enabled:  true,
	}}, builtinIDs())
	if err != nil {
		t.Fatal(err)
	}

	findings, candidates := engine.Analyze(ResourceRef{
		URL: "https://example.test/app.js",
	}, []byte(`const a="/same"; const b="/same";`))

	if len(findings) != 1 || len(candidates) != 1 {
		t.Fatalf("dedupe findings=%d candidates=%d", len(findings), len(candidates))
	}
}

func TestAnalyzeContextContainsExactlyThreeSurroundingLines(t *testing.T) {
	engine, err := New([]model.Rule{{
		ID:       "test.context",
		Name:     "Context",
		Category: model.RuleCategorySensitive,
		Severity: model.SeverityHigh,
		Pattern:  `TOKEN`,
		Enabled:  true,
	}}, builtinIDs())
	if err != nil {
		t.Fatal(err)
	}

	body := []byte(strings.Join([]string{
		"line one",
		"line two",
		"line three",
		"line four",
		"const secret = TOKEN",
		"line six",
		"line seven",
		"line eight",
		"line nine",
	}, "\r\n"))
	findings, _ := engine.Analyze(ResourceRef{URL: "context.js"}, body)
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}

	context := findings[0].ContextLines
	wantLines := []struct {
		num   int
		match bool
	}{
		{2, false},
		{3, false},
		{4, false},
		{5, true},
		{6, false},
		{7, false},
		{8, false},
	}
	if len(context) != len(wantLines) {
		t.Fatalf("len(ContextLines) = %d, want %d", len(context), len(wantLines))
	}
	for i, want := range wantLines {
		if context[i].LineNumber != want.num {
			t.Errorf("ContextLines[%d].LineNumber = %d, want %d", i, context[i].LineNumber, want.num)
		}
		gotMatch := context[i].MatchStart >= 0 && context[i].MatchEnd > context[i].MatchStart
		if gotMatch != want.match {
			t.Errorf("ContextLines[%d] match = %v, want %v", i, gotMatch, want.match)
		}
		if want.match && !strings.Contains(context[i].Content, "TOKEN") {
			t.Errorf("ContextLines[%d].Content does not contain TOKEN: %q", i, context[i].Content)
		}
	}
	for _, excluded := range []string{"line one", "line nine"} {
		for _, line := range context {
			if strings.Contains(line.Content, excluded) {
				t.Errorf("Context unexpectedly contains %q in line %d", excluded, line.LineNumber)
			}
		}
	}
}

func TestNewRejectsInvalidPatternAndCaptureGroup(t *testing.T) {
	tests := []model.Rule{
		{ID: "bad.regex", Pattern: `(?=lookahead)`, Enabled: true},
		{ID: "bad.group", Pattern: `(one)`, Group: 2, Enabled: true},
	}
	for _, rule := range tests {
		_, err := New([]model.Rule{rule}, builtinIDs())
		if err == nil || !strings.Contains(err.Error(), rule.ID) {
			t.Fatalf("New(%s) error = %v", rule.ID, err)
		}
	}
}

type builtinCase struct {
	Rule     string `json:"rule"`
	Positive string `json:"positive"`
	Negative string `json:"negative"`
}

func TestBuiltinRulesHavePositiveAndNegativeCases(t *testing.T) {
	data, err := os.ReadFile("testdata/cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []builtinCase
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}

	engine, err := New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	covered := make(map[string]bool, len(cases))
	for _, test := range cases {
		t.Run(test.Rule, func(t *testing.T) {
			positive, _ := engine.Analyze(ResourceRef{URL: "positive.js"}, []byte(test.Positive))
			if !hasRule(positive, test.Rule) {
				t.Fatalf("rule %q did not match positive %q", test.Rule, test.Positive)
			}
			negative, _ := engine.Analyze(ResourceRef{URL: "negative.js"}, []byte(test.Negative))
			if hasRule(negative, test.Rule) {
				t.Fatalf("rule %q matched negative %q", test.Rule, test.Negative)
			}
			covered[test.Rule] = true
		})
	}
	for _, rule := range BuiltinRules() {
		if !covered[rule.ID] {
			t.Errorf("built-in rule %q has no fixture", rule.ID)
		}
	}
}

func hasRule(findings []model.Finding, id string) bool {
	for _, finding := range findings {
		if finding.RuleID == id {
			return true
		}
	}
	return false
}

func builtinIDs() []string {
	rules := BuiltinRules()
	ids := make([]string, 0, len(rules))
	for _, rule := range rules {
		ids = append(ids, rule.ID)
	}
	return ids
}
