package discover

import (
	"net/url"
	"reflect"
	"testing"

	"github.com/youmulijiang/jsowl/internal/analyze"
)

func testEngine(t *testing.T) *analyze.Engine {
	t.Helper()
	engine, err := analyze.New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

// TestFromJavaScriptDiscoveryMatchesFullCandidates pins the contract the
// download phase relies on: the URL-only pass must find exactly the same
// follow-up resources as the full pass. Context lines are deliberately not
// produced by the discovery pass — the deferred analysis pass adds them — so
// only the discovery-relevant fields are compared.
func TestFromJavaScriptDiscoveryMatchesFullCandidates(t *testing.T) {
	engine := testEngine(t)
	source, err := url.Parse("https://example.test/static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	bodies := []string{
		`import("/static/chunk-a.js");fetch("/api/users")`,
		`(function(){var a="/static/a.js";r.e=function(){return Promise.all([r.e("chunk-b"),r.e("chunk-c")])}})`,
		`require.config({paths:{app:"/static/app"}});define(["/static/mod.js"],function(){})`,
		`//# sourceMappingURL=app.js.map`,
		`var u="https://api.example.test/v1/items";var t="text/plain";`,
		`const s="中文";axios.get("/api/中文/users")`,
		`fetch("/api/a");fetch("/api/b");var x="/static/c.js"`,
		``,
		`not javascript at all {{{`,
	}
	for _, body := range bodies {
		full := FromJavaScript(source, []byte(body), engine)
		discovery := FromJavaScriptDiscovery(source, []byte(body), engine)

		if !reflect.DeepEqual(discovery.SPA, full.SPA) {
			t.Fatalf("SPA mismatch for %q:\nfull=%#v\ndiscovery=%#v", body, full.SPA, discovery.SPA)
		}
		if len(discovery.Findings) != 0 {
			t.Fatalf("discovery produced findings for %q: %#v", body, discovery.Findings)
		}
		if len(discovery.Hosts) != 0 || len(discovery.BasePaths) != 0 {
			t.Fatalf("discovery produced deferred-only results for %q", body)
		}

		fullKeys := candidateKeys(full.Candidates)
		discoveryKeys := candidateKeys(discovery.Candidates)
		if !reflect.DeepEqual(fullKeys, discoveryKeys) {
			t.Fatalf("candidate mismatch for %q:\nfull=%v\ndiscovery=%v",
				body, fullKeys, discoveryKeys)
		}
	}
}

type candidateKey struct {
	Raw, Kind, Method, RuleID, Source string
	Line, Column                      int
}

func candidateKeys(candidates []Candidate) []candidateKey {
	keys := make([]candidateKey, 0, len(candidates))
	for _, candidate := range candidates {
		keys = append(keys, candidateKey{
			Raw: candidate.Raw, Kind: string(candidate.Kind),
			Method: candidate.Method, RuleID: candidate.RuleID,
			Source: candidate.Source, Line: candidate.Line, Column: candidate.Column,
		})
	}
	return keys
}

func TestContainsFold(t *testing.T) {
	cases := []struct {
		haystack, needle string
		want             bool
	}{
		{"fetch('/api')", "fetch(", true},
		{"FETCH('/api')", "fetch(", true},
		{"history.pushState({},'', '/')", "history.pushstate", true},
		{"无 import( 但有大写 IMPORT(", "import(", true},
		{"abc", "import(", false},
		{"", "import(", false},
		{"短", "import(", false},
		{"mode:\"hash\"", "mode:\"hash\"", true},
		{"MODE: HASH", "mode:\"hash\"", false},
	}
	for _, testCase := range cases {
		if got := containsFold([]byte(testCase.haystack), []byte(testCase.needle)); got != testCase.want {
			t.Fatalf("containsFold(%q, %q) = %v, want %v",
				testCase.haystack, testCase.needle, got, testCase.want)
		}
	}
}
