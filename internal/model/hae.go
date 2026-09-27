package model

import (
	"fmt"
	"strings"
	"unicode"

	"go.yaml.in/yaml/v3"
)

// HaE-native rule files (github.com/gh0stkey/HaE) group rules as:
//
//	rules:
//	- group: 疑似漏洞
//	  rule:
//	  - name: GET 明文id
//	    loaded: true
//	    f_regex: (...)
//	    s_regex: ''
//	    format: '{0}'
//	    color: green
//	    scope: request line
//	    engine: nfa
//	    sensitive: false
//
// They are decoded leniently (unknown fields ignored) because the files come
// from an external ecosystem with shifting schemas; scope is accepted but
// meaningless here — JsOwl analyses fetched scripts, not proxied requests.

type haeRuleFile struct {
	Include  []string        `yaml:"include"`
	Disabled []string        `yaml:"disabled"`
	Rules    []haeGroupEntry `yaml:"rules"`
}

type haeGroupEntry struct {
	Group string    `yaml:"group"`
	Rule  []haeRule `yaml:"rule"`
}

type haeRule struct {
	Name      string    `yaml:"name"`
	Loaded    *bool     `yaml:"loaded"`
	FRegex    string    `yaml:"f_regex"`
	SRegex    string    `yaml:"s_regex"`
	Format    string    `yaml:"format"`
	Color     string    `yaml:"color"`
	Scope     yaml.Node `yaml:"scope"` // tolerated, unused
	Engine    string    `yaml:"engine"`
	Sensitive bool      `yaml:"sensitive"`
	// JsOwl extensions; everything else falls back to the color mapping.
	Severity string `yaml:"severity"`
	Category string `yaml:"category"`
}

// isHaERulesDocument reports whether a rules file uses the HaE schema (a
// top-level "rules" key) instead of the native include/disabled/custom one.
func isHaERulesDocument(document *yaml.Node) bool {
	if document.Kind != yaml.DocumentNode || len(document.Content) != 1 {
		return false
	}
	root := document.Content[0]
	if root.Kind != yaml.MappingNode {
		return false
	}
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == "rules" {
			return true
		}
	}
	return false
}

// parseHaERules converts a decoded HaE-format document into the internal
// rule list, generating deterministic IDs of the form hae.<group>.<name>.
func parseHaERules(document *yaml.Node) (RulesConfig, error) {
	var file haeRuleFile
	if err := document.Decode(&file); err != nil {
		return RulesConfig{}, fmt.Errorf("decode HaE rules: %w", err)
	}
	config := RulesConfig{
		Include:  file.Include,
		Disabled: file.Disabled,
		Custom:   make([]Rule, 0),
	}
	seen := make(map[string]int)
	for _, group := range file.Rules {
		for _, entry := range group.Rule {
			if entry.Loaded != nil && !*entry.Loaded {
				continue // HaE: unloaded rules are inactive
			}
			if entry.FRegex == "" {
				continue
			}
			config.Custom = append(config.Custom, Rule{
				ID:          haeRuleID(seen, group.Group, entry.Name),
				Name:        entry.Name,
				Category:    haeCategory(entry.Category),
				Severity:    haeSeverity(entry.Severity, entry.Color),
				Pattern:     entry.FRegex,
				SRegex:      entry.SRegex,
				Format:      entry.Format,
				Group:       0,
				Description: fmt.Sprintf("HaE 规则：%s / %s", group.Group, entry.Name),
				Enabled:     true,
				Engine:      entry.Engine,
				// HaE semantics: sensitive=false (the default) matches
				// case-insensitively.
				IgnoreCase: !entry.Sensitive,
			})
		}
	}
	return config, nil
}

// haeRuleID builds "hae.<group>.<name>", slugified and collision-suffixed,
// so `disabled` lists can address HaE rules without editing them.
func haeRuleID(seen map[string]int, group, name string) string {
	base := "hae." + haeSlug(group) + "." + haeSlug(name)
	count := seen[base]
	seen[base] = count + 1
	if count == 0 {
		return base
	}
	return fmt.Sprintf("%s-%d", base, count+1)
}

// haeSlug lowercases and replaces every non-letter run with a dash, keeping
// letters of any script so Chinese HaE rule names stay readable and unique.
func haeSlug(value string) string {
	var out strings.Builder
	lastDash := false
	for _, char := range strings.ToLower(value) {
		if unicode.IsLetter(char) || unicode.IsDigit(char) {
			out.WriteRune(char)
			lastDash = false
			continue
		}
		if !lastDash && out.Len() > 0 {
			out.WriteByte('-')
			lastDash = true
		}
	}
	slug := strings.Trim(out.String(), "-")
	if slug == "" {
		return "rule"
	}
	return slug
}

// haeCategory maps an explicit category override; HaE rules default to the
// sensitive-information category.
func haeCategory(explicit string) RuleCategory {
	switch strings.ToLower(strings.TrimSpace(explicit)) {
	case "url":
		return RuleCategoryURL
	default:
		return RuleCategorySensitive
	}
}

// haeSeverity honours an explicit severity override, else derives one from
// the HaE highlight color (which carries the author's urgency intent).
func haeSeverity(explicit, color string) Severity {
	if severity := Severity(strings.ToLower(strings.TrimSpace(explicit))); severity != "" {
		switch severity {
		case SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
			return severity
		}
	}
	switch strings.ToLower(strings.TrimSpace(color)) {
	case "red":
		return SeverityCritical
	case "orange", "pink":
		return SeverityHigh
	case "magenta", "yellow":
		return SeverityMedium
	case "green":
		return SeverityLow
	case "blue", "cyan":
		return SeverityInfo
	}
	return SeverityMedium
}
