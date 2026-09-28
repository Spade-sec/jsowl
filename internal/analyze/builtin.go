package analyze

import (
	"fmt"

	"github.com/youmulijiang/jsowl/internal/model"
)

// RulesConfig re-exported for the YAML marshal below.
type RulesConfig = model.RulesConfig

// defaultRulesYAML holds the default rules document (config/rules.yml, HaE
// native format). go:embed cannot reach ../config from this package, so the
// root jsowl package embeds the file and injects the bytes via
// SetDefaultRulesYAML from its init; internal test binaries load the same
// file from the repository in their TestMain.
var defaultRulesYAML []byte

// SetDefaultRulesYAML installs the default rules document parsed by
// DefaultRules and returned by DefaultRulesYAML. It is called once at
// process start by the root jsowl package's init.
func SetDefaultRulesYAML(data []byte) error {
	if _, err := model.ParseRules("config/rules.yml", data); err != nil {
		return err
	}
	defaultRulesYAML = data
	return nil
}

// DefaultRules returns the default sensitive and URL rules parsed from the
// rules document injected via SetDefaultRulesYAML (config/rules.yml in the
// repository). URL extraction also lives in APIRules and is always compiled
// separately.
func DefaultRules() []model.Rule {
	if len(defaultRulesYAML) == 0 {
		panic("analyze: default rules not injected; import the root jsowl package or call SetDefaultRulesYAML")
	}
	config, err := model.ParseRules("config/rules.yml", defaultRulesYAML)
	if err != nil {
		// The injected document is compiled and tested with the package, so a
		// parse failure here indicates a build-time regression, not input.
		panic(fmt.Sprintf("parse default rules: %v", err))
	}
	return config.Custom
}

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
# 本文件由 config/rules.yml 播种生成，为 HaE 原生格式；编辑后下次扫描即生效。
# - 规则 ID 由 组名/规则名 自动生成（hae.<组名>.<规则名>）；同名同组的
#   条目覆盖内嵌默认规则，loaded: false 关闭该条。
# - 项目目录下的 config/rules.yml 存在时优先生效，本文件不再加载；
#   配置文件设置 rules_file 时则以该规则文件为准。
`

// DefaultRulesYAML returns the injected rules document (config/rules.yml),
// prefixed with the user-facing header. It is the seed content of
// ~/.jsowl/rules.yaml, so the editable default is byte-identical to the
// compiled-in default.
func DefaultRulesYAML() ([]byte, error) {
	if len(defaultRulesYAML) == 0 {
		return nil, fmt.Errorf("default rules not injected; import the root jsowl package or call SetDefaultRulesYAML")
	}
	return append([]byte(rulesFileHeader), defaultRulesYAML...), nil
}
