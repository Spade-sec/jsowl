package pipeline

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/youmulijiang/jsowl/internal/extract"
	"github.com/youmulijiang/jsowl/internal/model"
)

func TestCollectScanHostsClassifiesAndKeepsEvidence(t *testing.T) {
	result := &model.Result{
		Target: "https://app.example.com/",
		Resources: []model.Resource{
			{URL: "https://app.example.com/static/app.js", Type: model.ResourceTypeScript},
			{URL: "http://10.20.30.40:8080/metrics", Type: model.ResourceTypeAsset},
		},
		Endpoints: []model.Endpoint{
			{Raw: "/api/users", URL: "https://app.example.com/api/users", SourceURL: "https://app.example.com/static/app.js"},
			{Raw: "https://f/", URL: "https://f/", SourceURL: "https://app.example.com/static/app.js"},
			{Raw: "v1/report", URL: "v1/report?page=2", SourceURL: "https://app.example.com/static/app.js"},
		},
		Findings: []model.Finding{{
			RuleID: "hae.PII.邮箱地址", RuleName: "邮箱地址", Category: model.RuleCategorySensitive,
			Severity: model.SeverityMedium, Value: "ops@example.com",
			SourceURL: "https://app.example.com/static/app.js", Line: 3,
		}},
	}
	assets, notes := extract.CollectScanHosts(result, defaultHostExtractor())
	if len(notes) != 0 {
		t.Fatalf("unexpected diagnostics: %#v", notes)
	}
	kinds := map[string]model.HostKind{}
	for _, asset := range assets {
		kinds[asset.Value] = asset.Kind
		if asset.Origin != model.HostOriginScan {
			t.Fatalf("scan host origin = %q", asset.Origin)
		}
	}
	for value, want := range map[string]model.HostKind{
		"app.example.com": model.HostKindDomain,
		"f":               model.HostKindInternal,
		"10.20.30.40":     model.HostKindIPv4,
	} {
		if kinds[value] != want {
			t.Errorf("host %q kind = %q, want %q", value, kinds[value], want)
		}
	}
	// A relative reference has no host and must not invent one.
	for value := range kinds {
		if strings.Contains(value, "v1/report") {
			t.Errorf("a relative reference produced a host: %q", value)
		}
	}
	// Evidence records the role each URL played. One URL can play several
	// roles; identical URLs at the same position are one observation whose
	// note names every role, so nothing is dropped and nothing is counted
	// twice.
	var roleNotes []string
	for _, asset := range assets {
		for _, source := range asset.Sources {
			roleNotes = append(roleNotes, source.Note)
		}
	}
	joined := strings.Join(roleNotes, " ")
	for _, want := range []string{
		extract.HostRoleTarget, extract.HostRoleResource,
		extract.HostRoleEndpoint, extract.HostRoleEndpointFrom,
		extract.HostRoleFindingSource,
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("scan evidence role %q missing from %q", want, joined)
		}
	}
	// The order is a function of the data, not of map iteration.
	again, _ := extract.CollectScanHosts(result, defaultHostExtractor())
	for index := range assets {
		if assets[index].Value != again[index].Value || assets[index].Kind != again[index].Kind {
			t.Fatalf("host order is not deterministic at %d: %#v vs %#v", index, assets[index], again[index])
		}
	}
}

func TestFinalizeDerivesScanHostsIdempotently(t *testing.T) {
	result := &model.Result{
		Target: "https://app.example.com/",
		Endpoints: []model.Endpoint{
			{URL: "https://app.example.com/a", SourceURL: "https://app.example.com/app.js", Type: "api"},
		},
	}
	Finalize(result)
	first := len(result.ScanHosts)
	if first == 0 {
		t.Fatal("no scan hosts derived")
	}
	issues := len(result.Issues)
	Finalize(result)
	if len(result.ScanHosts) != first {
		t.Fatalf("scan hosts changed on the second finalize: %d -> %d", first, len(result.ScanHosts))
	}
	if len(result.Issues) != issues {
		t.Fatalf("diagnostics duplicated on the second finalize: %d -> %d", issues, len(result.Issues))
	}
}

func TestRecordHostNotesCollapsesDuplicates(t *testing.T) {
	result := &model.Result{}
	notes := []extract.Note{
		{Code: extract.NotePSLUnavailable, Message: "不可用", URL: "https://a/x.js"},
		{Code: extract.NotePSLUnavailable, Message: "不可用", URL: "https://b/y.js"},
		{Code: extract.NoteDynamicHost, Message: "动态表达式", URL: "https://a/x.js"},
	}
	recordHostNotes(result, notes)
	if len(result.Issues) != 2 {
		t.Fatalf("issues = %#v, want one per distinct diagnostic", result.Issues)
	}
	recordHostNotes(result, notes)
	if len(result.Issues) != 2 {
		t.Fatalf("repeating the notes duplicated them: %#v", result.Issues)
	}
	for _, issue := range result.Issues {
		if issue.Stage != "analyze" || issue.Message == "" {
			t.Fatalf("diagnostic issue = %#v", issue)
		}
	}
}

// TestRunDetailedExtractsHostsFromJavaScript scans a local site whose script
// carries host values in every supported shape, and checks the pipeline wires
// them into the result with evidence. Everything is served from a local test
// server: host extraction itself performs no DNS lookup and no probe.
func TestRunDetailedExtractsHostsFromJavaScript(t *testing.T) {
	script := `
// allowed origins: https://allow.example.com
const api = "https://api.example.com/v1/users";
const ws = "wss://socket.example.net/live";
const parts = "https://" + "concat." + "example.org/x";
const db = "mongodb://svc:pw@10.20.30.40:27017/orders";
const config = { baseURL: "g", host: "f" };
const relative = "/api/local";
`
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case strings.HasSuffix(request.URL.Path, ".js"):
			writer.Header().Set("Content-Type", "application/javascript")
			_, _ = writer.Write([]byte(script))
		default:
			writer.Header().Set("Content-Type", "text/html")
			_, _ = writer.Write([]byte(`<html><body><script src="/static/app.js"></script></body></html>`))
		}
	}))
	defer server.Close()

	config := model.DefaultConfig()
	config.Mode = model.ModeDirect
	config.Browser.Path = ""
	runner := newTestPipeline(t, config, server)
	result, _, err := runner.RunDetailed(context.Background(), model.Target{URL: server.URL},
		http.Header{}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	byValue := map[string]model.HostAsset{}
	for _, asset := range result.Hosts {
		byValue[asset.Value] = asset
	}
	for _, want := range []string{
		"api.example.com", "socket.example.net", "concat.example.org",
		"allow.example.com", "10.20.30.40", "f", "g",
	} {
		if _, ok := byValue[want]; !ok {
			t.Errorf("host %q missing from the scan result: %#v", want, result.Hosts)
		}
	}
	// The IP inside a connection string is an address asset, not a domain.
	if asset := byValue["10.20.30.40"]; asset.Kind != model.HostKindIPv4 {
		t.Errorf("connection-string address kind = %q", asset.Kind)
	}
	// Single-label values survive only because they came from a host context.
	if asset := byValue["f"]; asset.Kind != model.HostKindInternal {
		t.Errorf("bare host field kind = %q", asset.Kind)
	}
	// A relative path never becomes a host.
	for value := range byValue {
		if strings.Contains(value, "api/local") {
			t.Errorf("relative path became a host: %q", value)
		}
	}
	// Evidence is carried: at least one source with a position and a method.
	var withPosition, withMethod bool
	for _, asset := range result.Hosts {
		for _, source := range asset.Sources {
			if source.Line > 0 {
				withPosition = true
			}
			if source.Method != "" {
				withMethod = true
			}
		}
	}
	if !withPosition || !withMethod {
		t.Fatalf("host evidence lost its positions or methods: %#v", result.Hosts)
	}
	// The scan-associated population is present and separate.
	if len(result.ScanHosts) == 0 {
		t.Fatal("scan-associated hosts were not recorded")
	}
	for _, asset := range result.ScanHosts {
		if asset.Origin != model.HostOriginScan {
			t.Fatalf("scan host origin = %q", asset.Origin)
		}
	}
}

// TestHostExtractionNeedsNoResolution proves the extractor works on names that
// cannot resolve: nothing here is reachable, yet every value is classified.
func TestHostExtractionNeedsNoResolution(t *testing.T) {
	extractor := defaultHostExtractor()
	for raw, want := range map[string]model.HostKind{
		"https://definitely-not-a-real-host.example.com/api": model.HostKindDomain,
		"https://no-such-host.invalid/x":                     model.HostKindInternal,
		"http://192.0.2.55/x":                                model.HostKindIPv4,
	} {
		asset, ok := extractor.Classify(extract.Candidate{
			Raw: raw, Context: extract.ContextURL, Method: model.HostMethodURL,
		})
		if !ok {
			t.Fatalf("%q was not classified", raw)
		}
		if asset.Kind != want {
			t.Errorf("%q kind = %q, want %q", raw, asset.Kind, want)
		}
	}
}

// TestHostAssetsStayStableAcrossRuns guards the "concurrent aggregation must
// not change the report order" requirement: two scans of the same site must
// produce byte-identical host ordering.
func TestHostAssetsStayStableAcrossRuns(t *testing.T) {
	script := `
const hosts = ["https://b.example.com/1", "https://a.example.com/2", "https://c.example.net/3",
  "https://a.example.com/4", "http://10.0.0.9/x"];
`
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if strings.HasSuffix(request.URL.Path, ".js") {
			writer.Header().Set("Content-Type", "application/javascript")
			_, _ = writer.Write([]byte(script))
			return
		}
		writer.Header().Set("Content-Type", "text/html")
		_, _ = writer.Write([]byte(`<html><body><script src="/s/a.js"></script><script src="/s/b.js"></script><script src="/s/c.js"></script></body></html>`))
	}))
	defer server.Close()

	config := model.DefaultConfig()
	config.Mode = model.ModeDirect
	runner := newTestPipeline(t, config, server)

	var previous []string
	for attempt := 0; attempt < 3; attempt++ {
		result, _, err := runner.RunDetailed(context.Background(), model.Target{URL: server.URL},
			http.Header{}, nil, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		var order []string
		for _, asset := range result.Hosts {
			order = append(order, string(asset.Kind)+":"+asset.Value)
		}
		if len(order) == 0 {
			t.Fatal("no hosts found")
		}
		if previous != nil && strings.Join(previous, "|") != strings.Join(order, "|") {
			t.Fatalf("host order changed between runs:\n%v\n%v", previous, order)
		}
		previous = order
	}
}
