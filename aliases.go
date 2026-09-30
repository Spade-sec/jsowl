package jsowl

import "github.com/youmulijiang/jsowl/internal/model"

// Rule defines one RE2-compatible extraction pattern.
type Rule = model.Rule

// RequestSpec is the normalized request shape of one endpoint.
type RequestSpec = model.RequestSpec

// ContextLine is one source-code context line attached to a finding.
type ContextLine = model.ContextLine

// Endpoint evidence ranks how strongly an API path is confirmed.
const (
	EvidenceRuntime = model.EvidenceRuntime // observed as a live browser request via CDP
	EvidenceFullURL = model.EvidenceFullURL // absolute URL recovered by AST analysis
	EvidenceStatic  = model.EvidenceStatic  // static-only evidence: regex or AST without a live probe
)

// RuleCategory identifies URL or sensitive-information rules.
type RuleCategory = model.RuleCategory

// Severity ranks a finding's security significance.
type Severity = model.Severity

const (
	RuleCategoryURL       = model.RuleCategoryURL
	RuleCategorySensitive = model.RuleCategorySensitive

	SeverityInfo     = model.SeverityInfo
	SeverityMedium   = model.SeverityMedium
	SeverityLow      = model.SeverityLow
	SeverityHigh     = model.SeverityHigh
	SeverityCritical = model.SeverityCritical
)
