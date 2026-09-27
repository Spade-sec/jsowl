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
