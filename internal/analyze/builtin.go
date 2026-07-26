package analyze

import "github.com/youmulijiang/jsowl/internal/model"

// BuiltinRules returns the RE2-compatible rules shipped with JsOwl.
func BuiltinRules() []model.Rule {
	return []model.Rule{
		urlRule(
			"url.api-call",
			"API request URL",
			`(?i)(?:fetch|axios\.(?:get|post|put|delete|patch|request)|ajax)\s*\(\s*["']([^"']+)["']`,
			1,
		),
		urlRule(
			"url.vue-route",
			"Vue router path",
			`(?i)path\s*:\s*["']([a-zA-Z0-9_?=/.-]+)["'][\s\S]{0,40}component\s*:`,
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
			"url.quoted",
			"Quoted URL",
			`["'](https?://[^"'\s]+|(?:\.\./|\./|/)[^"'\s<>{}|\\`+"`"+`\[\]]+)["']`,
			1,
		),
		urlRule(
			"url.api-prefix",
			"API path prefix",
			`(?:^|[\s"'`+"`"+`])(/(?:api|v[0-9]+|rest|graphql|ws)/[^\s"'<>{}|\\`+"`"+`\[\]]+)`,
			1,
		),
		urlRule(
			"url.path-variable",
			"Path variable",
			`(?i)(?:path|route|uri|url|endpoint|baseURL|base_url|prefix|api_?path|api_?url|redirect|next|callback_?url|return_?url)\s*[:=]\s*["']([^"']*/[^"']*)["']`,
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
