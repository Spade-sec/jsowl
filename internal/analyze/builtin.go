package analyze

import (
	"fmt"

	"go.yaml.in/yaml/v3"

	"github.com/youmulijiang/jsowl/internal/model"
)

// RulesConfig re-exported for the YAML marshal below.
type RulesConfig = model.RulesConfig

// APIRules returns the URL-extraction rules hard-wired into JsOwl. They are
// compiled unconditionally and cannot be disabled or replaced through rule
// files, so API discovery never depends on configuration.
func APIRules() []model.Rule {
	return []model.Rule{
		urlMethodRule(
			"url.api-call",
			"API request URL",
			`(?i)((?:\$fetch)|(?:ofetch)|(?:\$ofetch)|(?:ky)|(?:fetch)|(?:axios\.(?:get|post|put|delete|patch|request))|(?:\$\s*\.\s*(?:get|post|put|delete|patch|getJSON|ajax))|(?:ajax))\s*\(\s*["']([^"']+)["']`,
			2, 1,
		),
		urlMethodRule(
			"url.xhr-open",
			"XMLHttpRequest URL",
			`(?i)\.open\s*\(\s*["'](get|post|put|delete|patch|head|options)["']\s*,\s*["']([^"']+)["']`,
			2, 1,
		),
		urlRule(
			"url.api-prefix",
			"API path prefix",
			`(?:^|[\s"'`+"`"+`])(/(?:api|v[0-9]+|rest|graphql|ws)/[^\s"'<>{}|\\`+"`"+`\[\]]+)`,
			1,
		),
		urlRule(
			"url.vue-route",
			"Vue router path",
			`(?i)path\s*:\s*["']([a-zA-Z0-9_?=/.-]+)["'][\s\S]{0,40}component\s*:`,
			1,
		),
		urlRule(
			"url.react-route-element",
			"React router path (element config)",
			`\{\s*path\s*:\s*["']([^"'\s]{1,200})["']\s*,\s*(?:element|children|Component|loader|index)\s*[,:]`,
			1,
		),
		urlRule(
			"url.react-route-jsx",
			"React router path (compiled JSX)",
			`(?i)(?:createElement|jsx|jsxs)\s*\(\s*"?[A-Za-z$_][\w$]*"?\s*,\s*\{[^{}]{0,200}?path\s*:\s*["']([^"']{1,200})["']`,
			1,
		),
		urlRule(
			"url.assignment",
			"URL assignment",
			`(?i)(?:url|href|src)\s*[:=]\s*(?:[\w$.]+\s*\+\s*)?["']([^"']+)["']`,
			1,
		),
		urlRule(
			"url.attribute",
			"HTML URL attribute",
			`(?i)(?:href|src|url|action|data-(?:url|src|href))\s*=\s*["']([^"'\s]+)["']`,
			1,
		),
		urlRule(
			"url.path-variable",
			"Path variable",
			`(?i)(?:path|route|uri|url|endpoint|baseURL|base_url|prefix|api_?path|api_?url|redirect|next|callback_?url|return_?url)\s*[:=]\s*["']([^"']*/[^"']*)["']`,
			1,
		),
		urlRule(
			"url.quoted",
			"Quoted URL",
			`["'](https?://[^"'\s]+|(?:\.\./|\./|/)[^"'\s<>{}|\\`+"`"+`\[\]]+)["']`,
			1,
		),
		urlRule(
			"url.static-resource",
			"Static resource",
			`(?i)["']((?:\.\./|\./|/)?[\w./-]+\.(?:js|mjs|jsx|ts|tsx|json|xml|html?|css|map|wasm))["']`,
			1,
		),
		urlRule(
			"url.webpack-loader",
			"Webpack loader path",
			`function\s+\w+\([^)]*\)\s*\{\s*return\s+\w+\.p\s*\+\s*["']([^"']{2,})["']`,
			1,
		),
	}
}

// BuiltinRules returns the sensitive-information rules shipped with JsOwl.
// URL extraction lives in APIRules and is always compiled separately.
func BuiltinRules() []model.Rule {
	return []model.Rule{
		sensitiveRule(
			"secret.account",
			"Cloud account value",
			model.SeverityMedium,
			`(?i)account[_-]?(?:name|key)?\s*[:=]\s*["']?([\w-]+)`,
			1,
		),
		sensitiveRule(
			"secret.private-key-id",
			"Private key identifier",
			model.SeverityHigh,
			`(?i)private[_-]?key[_-]?(?:id)?\s*[:=]\s*["']?([\w-]+)`,
			1,
		),
		sensitiveRule(
			"secret.jwt",
			"JWT token",
			model.SeverityHigh,
			`["'](ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]{10,})["']`,
			1,
		),
		sensitiveRule(
			"secret.credential",
			"Credential value",
			model.SeverityHigh,
			`(?i)(?:password|username|access[_-]?key|access[_-]?token|secret|pwd)\s*[:=]\s*["']?([^"',\s]+)`,
			1,
		),
		sensitiveRule(
			"secret.huawei-oss",
			"Huawei OSS credential",
			model.SeverityHigh,
			`(?i)huawei\.oss\.(?:ak|sk|bucket\.name|endpoint|local\.path)\s*[:=]\s*["']?([\w.-]+)`,
			1,
		),
		sensitiveRule(
			"secret.aws-access-key",
			"AWS access key",
			model.SeverityCritical,
			`\b(?:AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Za-z0-9]{16}\b`,
			0,
		),
		sensitiveRule(
			"secret.alibaba-access-key",
			"Alibaba Cloud access key",
			model.SeverityCritical,
			`\bLTAI[A-Za-z0-9]{12,20}\b`,
			0,
		),
		sensitiveRule(
			"secret.github-token",
			"GitHub token",
			model.SeverityCritical,
			`\b(?:ghp|ghu)_[A-Za-z0-9]{36}\b`,
			0,
		),
		sensitiveRule(
			"secret.google-oauth",
			"Google OAuth token",
			model.SeverityCritical,
			`\bya29\.[0-9A-Za-z_-]+\b`,
			0,
		),
		sensitiveRule(
			"secret.private-key-block",
			"Private key block",
			model.SeverityCritical,
			`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`,
			0,
		),
		sensitiveRule(
			"secret.jdbc",
			"JDBC connection string",
			model.SeverityHigh,
			`(?i)\bjdbc:[a-z0-9]+://[a-z0-9._:@/?&=;-]+`,
			0,
		),
		sensitiveRule(
			"pii.cn-mobile",
			"Chinese mobile number",
			model.SeverityMedium,
			`\b1(?:3[0-9]|4[5-9]|5[0-35-9]|6[6]|7[0-8]|8[0-9]|9[0-9])[0-9]{8}\b`,
			0,
		),
	}
}

func urlRule(id, name, pattern string, group int) model.Rule {
	return model.Rule{
		ID: id, Name: name, Category: model.RuleCategoryURL,
		Severity: model.SeverityInfo, Pattern: pattern, Group: group, Enabled: true,
	}
}

// urlMethodRule is a URL rule whose match also captures the HTTP verb in a
// second capture group.
func urlMethodRule(id, name, pattern string, group, methodGroup int) model.Rule {
	rule := urlRule(id, name, pattern, group)
	rule.MethodGroup = methodGroup
	return rule
}

// rulesFileHeader explains the generated user-level rules file.
const rulesFileHeader = `# JsOwl 用户级敏感信息规则（首次运行时自动生成，可自由编辑）。
# - id 与内置规则同名时覆盖内置定义；enabled: false 关闭该条；
#   从文件中删除某条规则不会关闭同名内置规则，请用 enabled: false。
# - 修改 pattern / 新增规则后，下次扫描即生效，无需其他配置。
# - 若配置文件设置了 rules_file，则以该规则文件为准，本文件不再加载。
`

// BuiltinRulesYAML renders the built-in sensitive rules as a user-editable
// rules file: the seed content of ~/.jsowl/rules.yaml. Built-in IDs are
// preserved so an edited entry overrides its built-in counterpart through
// the custom-rule override path in Engine.New.
func BuiltinRulesYAML() ([]byte, error) {
	encoded, err := yaml.Marshal(RulesConfig{Custom: BuiltinRules()})
	if err != nil {
		return nil, fmt.Errorf("marshal builtin rules: %w", err)
	}
	return append([]byte(rulesFileHeader), encoded...), nil
}

func sensitiveRule(
	id string,
	name string,
	severity model.Severity,
	pattern string,
	group int,
) model.Rule {
	return model.Rule{
		ID: id, Name: name, Category: model.RuleCategorySensitive,
		Severity: severity, Pattern: pattern, Group: group, Enabled: true,
	}
}
