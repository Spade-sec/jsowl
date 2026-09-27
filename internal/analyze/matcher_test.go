package analyze

import (
	"testing"
	"time"

	"github.com/youmulijiang/jsowl/internal/model"
)

func TestNFAEngineSupportsLookarounds(t *testing.T) {
	engine, err := New([]model.Rule{{
		ID: "test.nfa-idcard", Name: "nfa", Category: model.RuleCategorySensitive,
		Severity: model.SeverityHigh, Engine: "nfa", Group: 0, Enabled: true,
		Pattern: `(?<![0-9Xx])[1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[0-9Xx](?![0-9Xx])`,
	}}, nil)
	if err != nil {
		t.Fatalf("compile NFA rule: %v", err)
	}
	findings, _ := engine.Analyze(ResourceRef{URL: "https://example.com/a.js"}, []byte(
		`var a="110101199003078515";var b="91101011990030785151";`,
	))
	if len(findings) != 1 || findings[0].Value != "110101199003078515" {
		t.Fatalf("expected exactly the clean ID, got %+v", findings)
	}
}

func TestNFAEngineByteOffsetsWithMultibyteBody(t *testing.T) {
	engine, err := New([]model.Rule{{
		ID: "test.nfa-token", Name: "nfa", Category: model.RuleCategorySensitive,
		Severity: model.SeverityHigh, Engine: "nfa", Group: 0, Enabled: true,
		Pattern: `KX-[A-Za-z0-9]{16}`,
	}}, nil)
	if err != nil {
		t.Fatalf("compile NFA rule: %v", err)
	}
	// 中文注释在前：regexp2 的 rune 索引必须换算成字节偏移才能定位行列。
	body := []byte("// 密钥如下\nconst key = 'KX-ABCDEFGHIJKLMNOP';\n")
	findings, _ := engine.Analyze(ResourceRef{URL: "https://example.com/a.js"}, body)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %+v", findings)
	}
	if findings[0].Line != 2 || findings[0].Value != "KX-ABCDEFGHIJKLMNOP" {
		t.Fatalf("wrong location/value: %+v", findings[0])
	}
}

func TestSRegexFiltersFalsePositives(t *testing.T) {
	engine, err := New([]model.Rule{{
		ID: "test.email", Name: "email", Category: model.RuleCategorySensitive,
		Severity: model.SeverityMedium, Engine: "nfa", Group: 0, Enabled: true,
		Pattern: `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+\.[A-Za-z]{2,6}\b`,
		SRegex:  `(?i)^(?![A-Za-z0-9.-]+\.(?:png|jpe?g|gif|svg)).+`,
	}}, nil)
	if err != nil {
		t.Fatalf("compile rule: %v", err)
	}
	findings, _ := engine.Analyze(ResourceRef{URL: "https://example.com/a.js"}, []byte(
		`var mail="admin@example.com";var img="logo.png@example-cdn.net";`,
	))
	if len(findings) != 1 || findings[0].Value != "admin@example.com" {
		t.Fatalf("expected only the real email, got %+v", findings)
	}
}

func TestSRegexGroupReplacesValue(t *testing.T) {
	engine, err := New([]model.Rule{{
		ID: "test.auth", Name: "auth", Category: model.RuleCategorySensitive,
		Severity: model.SeverityHigh, Group: 0, Enabled: true,
		Pattern: `Authorization["']?\s*[:=]\s*["']?Basic\s+([A-Za-z0-9=+/-]{16,})`,
		SRegex:  `Basic\s+([A-Za-z0-9=+/-]+)`,
		SGroup:  1,
	}}, nil)
	if err != nil {
		t.Fatalf("compile rule: %v", err)
	}
	findings, _ := engine.Analyze(ResourceRef{URL: "https://example.com/a.js"}, []byte(
		`h.Authorization = "Basic dXNlcjpwYXNzd29yZA==";`,
	))
	if len(findings) != 1 || findings[0].Value != "dXNlcjpwYXNzd29yZA==" {
		t.Fatalf("expected s_regex group as value, got %+v", findings)
	}
}

func TestNFAEngineTimeoutDoesNotHangOrPoisonOtherRules(t *testing.T) {
	slow := model.Rule{
		ID: "test.slow", Name: "slow", Category: model.RuleCategorySensitive,
		Severity: model.SeverityLow, Engine: "nfa", Group: 0, Enabled: true,
		Pattern: `(a+)+$`,
	}
	fast := model.Rule{
		ID: "test.fast", Name: "fast", Category: model.RuleCategorySensitive,
		Severity: model.SeverityMedium, Group: 0, Enabled: true,
		Pattern: `token-[0-9]{3}`,
	}
	engine, err := New([]model.Rule{slow, fast}, nil)
	if err != nil {
		t.Fatalf("compile rules: %v", err)
	}
	// 60 个 a 后接 ! 使 (a+)+$ 灾难性回溯：必须被 nfaMatchTimeout 截断，
	// 且不影响同批其他规则（fast）的命中。
	body := []byte(`var t="token-123";var bomb="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!";`)
	start := time.Now()
	findings, _ := engine.Analyze(ResourceRef{URL: "https://example.com/a.js"}, body)
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("analysis hung for %v instead of honouring the match timeout", elapsed)
	}
	if len(findings) != 1 || findings[0].RuleID != "test.fast" {
		t.Fatalf("expected only the fast rule's finding, got %+v", findings)
	}
}

func TestFormatExpandsCaptureGroups(t *testing.T) {
	engine, err := New([]model.Rule{{
		ID: "test.format", Name: "format", Category: model.RuleCategorySensitive,
		Severity: model.SeverityHigh, Group: 0, Enabled: true,
		Pattern: `(?i)\bid=(\d{2,15})\b`,
		Format:  "明文ID:{1}",
	}}, nil)
	if err != nil {
		t.Fatalf("compile rule: %v", err)
	}
	findings, _ := engine.Analyze(ResourceRef{URL: "https://example.com/a.js"}, []byte(
		`var u = "?userid=123456&id=987654";`,
	))
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %+v", findings)
	}
	if findings[0].Value != "明文ID:987654" {
		t.Fatalf("format expansion wrong: %q", findings[0].Value)
	}
}

func TestIgnoreCaseOptionFromRule(t *testing.T) {
	pattern := `\bsecret-[a-z]{6}\b`
	engine, err := New([]model.Rule{
		{
			ID: "test.sensitive", Name: "s", Category: model.RuleCategorySensitive,
			Severity: model.SeverityLow, Group: 0, Enabled: true,
			Pattern: pattern, // 无 ignore_case：必须区分大小写
		},
		{
			ID: "test.insensitive", Name: "i", Category: model.RuleCategorySensitive,
			Severity: model.SeverityLow, Group: 0, Enabled: true,
			Pattern: pattern, IgnoreCase: true,
		},
	}, nil)
	if err != nil {
		t.Fatalf("compile rules: %v", err)
	}
	findings, _ := engine.Analyze(ResourceRef{URL: "https://example.com/a.js"}, []byte(
		`var a = "SECRET-abcdef";`,
	))
	ids := make([]string, 0, len(findings))
	for _, finding := range findings {
		ids = append(ids, finding.RuleID)
	}
	if len(ids) != 1 || ids[0] != "test.insensitive" {
		t.Fatalf("ignore_case must be opt-in, got %v", ids)
	}
}
