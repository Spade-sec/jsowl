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

// userConfigTemplate is written on first run. Every field stays commented out
// so the generated file never overrides anything by itself: it documents the
// defaults until the user uncomments a field, and project config.yml plus CLI
// flags always win over this file.
const userConfigTemplate = `# JsOwl 用户级配置文件（首次运行时自动生成，删除本文件后下次运行会重新生成）。
# 所有配置项默认处于注释状态：取消注释并修改后，对本机所有 jsowl 扫描生效。
# 优先级：命令行参数 > 当前目录 config.yml > 本文件 > 内置默认值。
# 各项含义与完整示例见 jsowl 仓库中的 config.example.yml。

# mode: auto

# request:
#   timeout: 15s
#   target_timeout: 5m
#   retry: 1
#   proxy: ""
#   user_agent: ""
#   headers: {}
#   cookies: {}

# browser:
#   path: ""
#   wait: 3s
#   idle: 800ms
#   idle_max: 5s
#   timeout: 45s
#   headless: true
#   no_sandbox: false
#   collector_script: ""
#   disable_injection: false
#   crawl_routes: false
#   max_routes: 0    # 0 = 不限制，只受 crawl_timeout 约束
#   crawl_timeout: 60s

# concurrency:
#   targets: 4
#   resources_per_target: 16

# limits:
#   max_depth: 5
#   max_resources: 0
#   max_body_size: 0    # 0 = 不限制，完整下载响应体

# scope:
#   allow_domains: []
#   restrict_domains: []
#   suffix_blacklist: []
#   fetch_external_scripts: true
#   probe_external_endpoints: false
#   skip_library_bundles: true
#   probe_source_maps: true
#   source_map_blacklist: []

# output:
#   directory: ./jsowl-report
#   json: true
#   html: true
#   download_js: true
#   js_directory: js

# 敏感信息规则默认位于 ~/.jsowl/rules.yaml（首次运行自动生成，可直接编辑，
# 修改 pattern / enabled: false / 追加规则后下次扫描生效）。
# 下面的 rules_file 用于改用其他规则文件（HaE 原生格式亦可），设置后
# rules.yaml 不再加载。相对路径以本文件所在目录（~/.jsowl）为基准。
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
	seed, err := analyze.BuiltinRulesYAML()
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
