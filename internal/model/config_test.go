package model

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadRules(t *testing.T, content string) RulesConfig {
	t.Helper()
	directory := t.TempDir()
	path := filepath.Join(directory, "rules.yml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	rules, err := loadRulesFile(path)
	if err != nil {
		t.Fatalf("loadRulesFile: %v", err)
	}
	return rules
}

func TestRuleEnabledDefaultsToTrueWhenOmitted(t *testing.T) {
	rules := loadRules(t, `custom:
  - id: fixture.omitted
    name: Fixture
    category: sensitive
    severity: high
    pattern: 'fixture'
  - id: fixture.off
    name: Fixture off
    category: sensitive
    severity: low
    pattern: 'fixture'
    enabled: false
`)
	if len(rules.Custom) != 2 {
		t.Fatalf("Custom = %d rules, want 2", len(rules.Custom))
	}
	if !rules.Custom[0].Enabled {
		t.Fatal("omitted enabled must default to true")
	}
	if rules.Custom[1].Enabled {
		t.Fatal("explicit enabled: false must stay false")
	}
}

func TestRuleRejectsUnknownField(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "rules.yml")
	content := "custom:\n  - id: x\n    pattern: 'x'\n    mistery: 1\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadRulesFile(path); err == nil || !strings.Contains(err.Error(), "mistery") {
		t.Fatalf("expected unknown-field error, got %v", err)
	}
}

func TestRulesIncludeMergesAndDetectsCycles(t *testing.T) {
	directory := t.TempDir()
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(directory, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("extra.yml", `custom:
  - id: fixture.included
    name: Included
    category: sensitive
    severity: low
    pattern: 'included'
`)
	write("rules.yml", `include:
  - ./extra.yml
disabled:
  - fixture.included
custom:
  - id: fixture.main
    name: Main
    category: sensitive
    severity: high
    pattern: 'main'
`)
	rules, err := loadRulesFile(filepath.Join(directory, "rules.yml"))
	if err != nil {
		t.Fatalf("loadRulesFile: %v", err)
	}
	if len(rules.Custom) != 2 || rules.Disabled[0] != "fixture.included" {
		t.Fatalf("include did not merge: %+v", rules)
	}

	// 循环引入必须报错而不是无限递归。
	write("rules.yml", "include:\n  - ./rules.yml\n")
	if _, err := loadRulesFile(filepath.Join(directory, "rules.yml")); err == nil ||
		!strings.Contains(err.Error(), "cycle") {
		t.Fatalf("expected include-cycle error, got %v", err)
	}
}

func TestHaERulesDocumentParsesNatively(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "hae.yml")
	content := `rules:
- group: 疑似漏洞
  rule:
  - name: GET 明文id
    loaded: true
    f_regex: (\b(?<!_)(id|\w+id)=(\d{2,15})\b(?![-_\/]))
    s_regex: ''
    format: '{0}'
    color: green
    scope: request line
    engine: nfa
    sensitive: false
  - name: 关闭的规则
    loaded: false
    f_regex: (never)
    engine: nfa
  - name: 区分大小写
    loaded: true
    f_regex: ([A-Z]{8})
    color: red
    scope:
      - response
    engine: nfa
    sensitive: true
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	rules, err := loadRulesFile(path)
	if err != nil {
		t.Fatalf("loadRulesFile: %v", err)
	}
	// loaded:false 的规则不加载；共 2 条。
	if len(rules.Custom) != 2 {
		t.Fatalf("Custom = %d rules, want 2", len(rules.Custom))
	}
	first := rules.Custom[0]
	if first.ID != "hae.疑似漏洞.get-明文id" {
		t.Fatalf("unexpected generated ID %q", first.ID)
	}
	if first.Pattern == "" || first.Format != "{0}" || !first.Enabled {
		t.Fatalf("basic HaE fields lost: %+v", first)
	}
	if !first.IgnoreCase {
		t.Fatal("sensitive:false must enable case-insensitive matching")
	}
	if first.Severity != SeverityLow || first.Category != RuleCategorySensitive {
		t.Fatalf("color green must map to low/sensitive: %+v", first)
	}
	second := rules.Custom[1]
	if second.IgnoreCase {
		t.Fatal("sensitive:true must keep case-sensitive matching")
	}
	if second.Severity != SeverityCritical {
		t.Fatalf("color red must map to critical, got %q", second.Severity)
	}
}

func TestHaERulesExplicitSeverityAndCategoryOverrideColor(t *testing.T) {
	rules := loadRules(t, `rules:
- group: 自定义
  rule:
  - name: 测试规则
    f_regex: (abc)
    color: green
    severity: critical
    category: url
`)
	rule := rules.Custom[0]
	if rule.Severity != SeverityCritical || rule.Category != RuleCategoryURL {
		t.Fatalf("explicit overrides lost: %+v", rule)
	}
	if rule.ID != "hae.自定义.测试规则" {
		t.Fatalf("unexpected generated ID %q", rule.ID)
	}
}

func TestHaERulesUnknownFieldsAreTolerated(t *testing.T) {
	// HaE 生态的文件字段随版本漂移，解析必须宽容。
	rules := loadRules(t, `rules:
- group: g
  rule:
  - name: n
    f_regex: (x)
    some_future_field: 1
    another:
      nested: true
`)
	if len(rules.Custom) != 1 {
		t.Fatalf("lenient decode failed: %+v", rules)
	}
}
