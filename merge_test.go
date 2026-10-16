package jsowl

import "testing"

func apiFixture() *Result {
	return &Result{
		Target: "http://app.test/",
		Endpoints: []Endpoint{{
			Raw: "/api/users", URL: "http://app.test/api/users",
			Type: "api", Evidence: EvidenceStatic, Source: "ast", Method: "POST",
		}},
	}
}

// TestMergeResultsLetsRuntimeClassificationOutrankALink is the regression test
// for the browser stage's routes disappearing from the route report: the direct
// pass classifies a quoted "/app/dashboard" as a generic link, and the merge
// with the browser pass upgraded only the evidence, leaving the type behind.
func TestMergeResultsLetsRuntimeClassificationOutrankALink(t *testing.T) {
	primary := &Result{
		Target: "http://app.test/",
		Endpoints: []Endpoint{{
			Raw: "/app/dashboard", URL: "http://app.test/app/dashboard",
			SourceURL: "http://app.test/main.js", Line: 1,
			Type: "link", Evidence: EvidenceStatic, Source: "regex",
		}},
	}
	secondary := &Result{
		Endpoints: []Endpoint{{
			Raw: "http://app.test/app/dashboard", URL: "http://app.test/app/dashboard",
			Type: "route", Evidence: EvidenceRuntime, Source: "cdp-runtime",
		}},
	}
	merged := mergeResults(primary, secondary)
	if len(merged.Endpoints) != 1 {
		t.Fatalf("expected one merged endpoint, got %d", len(merged.Endpoints))
	}
	endpoint := merged.Endpoints[0]
	if endpoint.Type != "route" {
		t.Fatalf("runtime route left as %q; the route report filters on type", endpoint.Type)
	}
	if endpoint.Source != "cdp-runtime" {
		t.Fatalf("extractor = %q, want cdp-runtime", endpoint.Source)
	}
	if endpoint.Evidence != EvidenceRuntime {
		t.Fatalf("evidence = %q, want runtime", endpoint.Evidence)
	}
}

// TestMergeResultsKeepsStrongerStaticTypes guards the other direction: an
// upgrade must not replace a real classification with a weaker one.
func TestMergeResultsKeepsStrongerStaticTypes(t *testing.T) {
	merged := mergeResults(apiFixture(), &Result{
		Endpoints: []Endpoint{{
			URL: "http://app.test/api/users", Type: "api",
			Evidence: EvidenceRuntime, Source: "cdp", Method: "POST", StatusCode: 200,
		}},
	})
	endpoint := merged.Endpoints[0]
	if endpoint.Type != "api" {
		t.Fatalf("type = %q, want api", endpoint.Type)
	}
	if endpoint.Evidence != EvidenceRuntime || endpoint.StatusCode != 200 {
		t.Fatalf("runtime facts were not merged: %#v", endpoint)
	}
	// A runtime "link" observation never downgrades anything.
	downgraded := mergeResults(apiFixture(), &Result{
		Endpoints: []Endpoint{{
			URL: "http://app.test/api/users", Type: "link",
			Evidence: EvidenceRuntime, Source: "cdp",
		}},
	})
	if downgraded.Endpoints[0].Type != "api" {
		t.Fatalf("a runtime link downgraded an api endpoint to %q", downgraded.Endpoints[0].Type)
	}
}
