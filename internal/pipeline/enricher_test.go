package pipeline

import (
	"testing"

	"github.com/youmulijiang/jsowl/internal/model"
)

type fakeEnricher struct{ called *bool }

func (f fakeEnricher) Enrich(templates []*model.RequestTemplate, _ []*model.Endpoint) []*model.RequestTemplate {
	*f.called = true
	return templates
}
func (f fakeEnricher) EnrichTaint(r *model.Result) *model.Result { *f.called = true; return r }
func (f fakeEnricher) EnrichFindings(r *model.Result) *model.Result {
	*f.called = true
	return r
}

func TestSetEnrichersInjection(t *testing.T) {
	called := false
	p := New(Options{})
	p.SetEnrichers(fakeEnricher{called: &called}, fakeEnricher{called: &called}, fakeEnricher{called: &called})
	// Directly verify the options were installed.
	if p.options.TemplateEnricher == nil || p.options.TaintEnricher == nil || p.options.FindingEnricher == nil {
		t.Fatal("SetEnrichers must install all three hooks")
	}
}
