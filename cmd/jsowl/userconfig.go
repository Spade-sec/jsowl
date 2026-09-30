package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/youmulijiang/jsowl/internal/analyze"
)

// userConfigDirName and userConfigFileName locate the user-level config file:
// ~/.jsowl/config.yml. It is created with the template below on first run.
const (
	userConfigDirName  = ".jsowl"
	userConfigFileName = "config.yml"
	// userRulesFileName is the user-level sensitive-rule seed generated on
	// first run and loaded by default unless a config layer sets rules_file.
	userRulesFileName = "rules.yaml"
)

// userConfigTemplate is written on first run. It presets every default so
// the file doubles as living documentation: users edit values in place
// instead of uncommenting lines. Values mirror DefaultConfig exactly (a test
// DeepEqual-guards against drift); an empty value means "fall back to the
// built-in default" for fields where that is meaningful. rules_file stays
// commented because setting it would replace the default ~/.jsowl/rules.yaml.
const userConfigTemplate = `# JsOwl 用户级配置文件（首次运行时自动生成，已预置全部默认值）。
# 直接修改各项数值即可生效，对本机所有 jsowl 扫描生效。
# 优先级：命令行参数 > 当前目录 config/config.yml > 本文件 > 内置默认值。
# 各项含义与完整示例见 jsowl 仓库中的 config.example.yml。

mode: auto

request:
  timeout: 15s
  target_timeout: 5m
  retry: 1
  proxy: ""
  user_agent: ""
  headers: {}
  cookies: {}

browser:
  # 浏览器可执行文件路径，留空时只搜索本地已安装的 Chrome/Chromium。
  path: ""
  wait: 3s
  idle: 800ms
  idle_max: 5s
  timeout: 45s
  headless: true
  no_sandbox: false
  collector_script: ""
  disable_injection: false
  # 渲染发现的每个框架路由视图，观测该视图自身发出的请求。
  crawl_routes: true
  max_routes: 0      # 0 = 不限制，只受 crawl_timeout 约束
  crawl_timeout: 60s
  # 运行时自动填表提交 / 点击交互元素（会触发目标写操作，谨慎开启）。
  auto_form: false
  trigger_events: false
  max_interactions: 20
  # 激进模式：disabled/隐藏控件也填写点击，攻击面更大也更嘈杂。
  aggressive: false

concurrency:
  targets: 4
  resources_per_target: 16

limits:
  max_depth: 5
  max_resources: 0   # 0 = 不限制
  max_body_size: 0   # 0 = 不限制，完整下载响应体

scope:
  allow_domains: []
  restrict_domains: []
  fetch_external_scripts: true
  probe_external_endpoints: false
  probe_routes: false
  probe_source_maps: true
  skip_library_bundles: true
  # 已知的第三方库/静态资源黑名单，按需增删。
  suffix_blacklist:
    - .png
    - .jpg
    - .jpeg
    - .gif
    - .webp
    - .svg
    - .ico
    - .bmp
    - .tif
    - .tiff
    - .woff
    - .woff2
    - .ttf
    - .otf
    - .eot
    - .mp3
    - .wav
    - .ogg
    - .flac
    - .mp4
    - .webm
    - .avi
    - .mov
    - .mkv
    - .zip
    - .rar
    - .7z
    - .tar
    - .gz
    - .bz2
    - .xz
    - .pdf
    - .wasm
    - .exe
    - .dll
    - .dmg
    - .iso
    - .css
  source_map_blacklist:
    - chunk-vendors
    - chunk-libs
    - vendors~
    - /vendor
    - node_modules
    - /polyfills
    - /runtime.
    - /libs/
    - axios
    - lodash
    - jquery
    - moment
    - echarts
    - element-ui
    - elementui
    - antd
    - highlight.js
    - /umd/
    - core-js
    - regenerator-runtime
    - zone.js
    - bootstrap

output:
  directory: ./jsowl-report
  json: true
  html: true
  download_js: true
  js_directory: js
  request_template: true

# AI 增强配置（配合 -ai 参数使用；api_key 建议手动填写在配置里而不是命令行）。
ai:
  enabled: false
  api_key: ""
  base_url: ""                     # 例如 https://open.bigmodel.cn/api/paas/v4
  # 上游协议格式（图片中选择器的落盘形式）：
  #   openai-chat          OpenAI Chat Completions（默认，GLM/one-api/vLLM）
  #   openai-responses     OpenAI Responses API
  #   anthropic-messages   Anthropic Messages（原生，Claude）
  #   gemini-native        Gemini generateContent（原生）
  format: "openai-chat"
  model: ""                        # 例如 glm-4-flash
  max_requests: 20                 # 单次扫描 AI 请求上限

# 敏感信息规则默认从内嵌的 HaE 规则集加载。项目目录下存在 config/rules.yml
# 时以它为项目级规则（改动即生效）；否则首次运行会播种 ~/.jsowl/rules.yaml
# 供全局编辑。下面的 rules_file 用于改用其他规则文件（HaE 原生格式亦可），
# 设置后以上来源都不再加载。相对路径以本文件所在目录（~/.jsowl）为基准。
# rules_file: ./rules.yml
`

// userConfigPath returns the user-level config file path under home.
func userConfigPath(home string) string {
	return filepath.Join(home, userConfigDirName, userConfigFileName)
}

// userRulesPath returns the user-level rules file path under home.
func userRulesPath(home string) string {
	return filepath.Join(home, userConfigDirName, userRulesFileName)
}

// ensureUserRulesFile creates the user-level rules file seeded with the
// built-in sensitive rules when it does not exist, and reports whether it
// was created. An existing file is never touched: edits survive upgrades.
func ensureUserRulesFile(path string) (bool, error) {
	if _, err := os.Stat(path); err == nil {
		return false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("inspect user rules %s: %w", path, err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return false, fmt.Errorf("create user config directory: %w", err)
	}
	seed, err := analyze.DefaultRulesYAML()
	if err != nil {
		return false, fmt.Errorf("render user rules seed: %w", err)
	}
	if err := os.WriteFile(path, seed, 0o600); err != nil {
		return false, fmt.Errorf("write user rules %s: %w", path, err)
	}
	return true, nil
}

// ensureUserConfigFile creates the user-level config file with the default
// template when it does not exist, and reports whether it was created.
func ensureUserConfigFile(path string) (bool, error) {
	if _, err := os.Stat(path); err == nil {
		return false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("inspect user config %s: %w", path, err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return false, fmt.Errorf("create user config directory: %w", err)
	}
	if err := os.WriteFile(path, []byte(userConfigTemplate), 0o600); err != nil {
		return false, fmt.Errorf("write user config %s: %w", path, err)
	}
	return true, nil
}
