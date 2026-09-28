package jsowl

import "github.com/youmulijiang/jsowl/internal/model"

// Rule defines one RE2-compatible extraction pattern.
type Rule = model.Rule

// RuleCategory identifies URL or sensitive-information rules.
type RuleCategory = model.RuleCategory

// Severity ranks a finding's security significance.
type Severity = model.Severity

const (
	RuleCategoryURL       = model.RuleCategoryURL
	RuleCategorySensitive = model.RuleCategorySensitive

	SeverityInfo     = model.SeverityInfo
	SeverityLow      = model.SeverityLow
	SeverityMedium   = model.SeverityMedium
	SeverityHigh     = model.SeverityHigh
	SeverityCritical = model.SeverityCritical
)
