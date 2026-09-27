package analyze

import "github.com/youmulijiang/jsowl/internal/model"

// TemplateEnricher is the reserved extension point for an optional AI layer
// over request reconstruction. It runs after the deterministic BuildTemplate
// pass and may only refine low-evidence parts of a template — literal values
// and AST-recovered keys always win over anything an enricher proposes.
//
// Expected enrichments (not implemented yet):
//   - infer keys for {{fuzz:body:{sym}}} placeholders by reading the
//     surrounding call context
//   - upgrade {{fuzz:}} tags to typed fuzz plans (enum boundaries, id-or
//     substitution, chain templates referencing upstream endpoints)
//   - confirm or correct Content-Type for payloads whose shape was ambiguous
//
// Implementations must be safe for concurrent use and must treat their output
// as advisory: mergeSpec-style evidence ranking downstream decides what ships.
type TemplateEnricher interface {
	// Enrich receives endpoints whose Template is already built and returns
	// the refined templates (same order; nil entries keep the original).
	Enrich(templates []*model.RequestTemplate, endpoints []*model.Endpoint) []*model.RequestTemplate
}

// DefaultEnricher is the no-op used until an AI implementation is plugged in.
type DefaultEnricher struct{}

// Enrich returns the templates unchanged.
func (DefaultEnricher) Enrich(templates []*model.RequestTemplate, _ []*model.Endpoint) []*model.RequestTemplate {
	return templates
}

// TaintEnricher is the reserved extension point for AI-assisted taint
// refinement. The deterministic kernel in discover only annotates origins it
// can prove syntactically (same-function callback chains, storage reads) and
// leaves the rest Kind=unknown; an enricher may refine those unknowns —
// e.g. by reading the packaged call context and connecting cross-function or
// cross-module flows — but every refined annotation keeps the advisory
// contract: taint never changes values, only the origin label.
type TaintEnricher interface {
	// EnrichTaint may replace Kind=unknown taints with refined origins and
	// must leave literal/recovered parameters untouched.
	EnrichTaint(result *model.Result) *model.Result
}

// DefaultTaintEnricher is the no-op used until an AI implementation exists.
type DefaultTaintEnricher struct{}

// EnrichTaint returns the result unchanged.
func (DefaultTaintEnricher) EnrichTaint(result *model.Result) *model.Result {
	return result
}

// FindingEnricher is the reserved extension point for AI-assisted sensitive
// finding triage: rating how exploitable each finding actually is, so the
// report separates real credentials from placeholder-looking junk.
type FindingEnricher interface {
	// EnrichFindings may attach model.AIAssessment to findings; it must not
	// modify values or drop findings.
	EnrichFindings(result *model.Result) *model.Result
}

// DefaultFindingEnricher is the no-op used until an AI implementation exists.
type DefaultFindingEnricher struct{}

// EnrichFindings returns the result unchanged.
func (DefaultFindingEnricher) EnrichFindings(result *model.Result) *model.Result {
	return result
}
