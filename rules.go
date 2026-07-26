package jsowl

import "github.com/youmulijiang/jsowl/internal/model"

type Rule = model.Rule
type RuleCategory = model.RuleCategory
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
