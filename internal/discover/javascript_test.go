package discover

import (
	"testing"

	"github.com/youmulijiang/jsowl/internal/analyze"
)

func TestFromJavaScriptExtractsFindingsCandidatesAndSignals(t *testing.T) {
	engine, err := analyze.New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	source := mustParseURL(t, "https://example.test/assets/app.js")
	body := []byte(`
const token = 'eyJhbGciOiJIUzI1NiJ9.abcdefghijklmno.abcdefghijklmnop';
fetch('/api/users');
history.pushState({}, '', '/users');
const lazy = import('./users.js');
self.webpackChunkapp = self.webpackChunkapp || [];`)

	got := FromJavaScript(source, body, engine)

	assertCandidate(t, got.Candidates, "/api/users", KindEndpoint)
	if !hasFinding(got, "secret.jwt") {
		t.Fatal("JWT finding not returned")
	}
	if !got.SPA.DynamicImport || !got.SPA.HistoryRouting || !got.SPA.Webpack {
		t.Fatalf("SPA signals = %#v", got.SPA)
	}
}

func TestFromJavaScriptClassifiesStaticScriptCandidate(t *testing.T) {
	engine, err := analyze.New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	source := mustParseURL(t, "https://example.test/app.js")

	got := FromJavaScript(source, []byte(`const worker = "/assets/worker.js";`), engine)

	assertCandidate(t, got.Candidates, "/assets/worker.js", KindScript)
}

func hasFinding(result JSResult, ruleID string) bool {
	for _, finding := range result.Findings {
		if finding.RuleID == ruleID {
			return true
		}
	}
	return false
}
