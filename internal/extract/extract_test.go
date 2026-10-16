package extract

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/youmulijiang/jsowl/internal/model"
)

// testExtractor builds an extractor with the embedded snapshot. No test in
// this package reaches the network: the snapshot ships with the binary and is
// written to a cache file before the splitter is created.
func testExtractor(t *testing.T) *Extractor {
	t.Helper()
	return NewExtractor(model.HostsConfig{})
}

func classifyOne(t *testing.T, raw string, context string) (model.HostAsset, bool) {
	t.Helper()
	extractor := testExtractor(t)
	return extractor.Classify(Candidate{Raw: raw, Context: context, Method: model.HostMethodASTLiteral})
}

func TestClassifyDomains(t *testing.T) {
	cases := []struct {
		name       string
		raw        string
		context    string
		wantKind   model.HostKind
		wantValue  string
		wantReg    string
		wantSuffix string
		wantSub    string
		wantStatus string
	}{
		{
			name: "plain domain", raw: "example.com", context: ContextLiteral,
			wantKind: model.HostKindDomain, wantValue: "example.com",
			wantReg: "example.com", wantSuffix: "com", wantStatus: model.SuffixRecognized,
		},
		{
			name: "public suffix hierarchy needs the full registrable domain",
			raw:  "api.example.co.uk", context: ContextLiteral,
			wantKind: model.HostKindDomain, wantValue: "api.example.co.uk",
			wantReg: "example.co.uk", wantSuffix: "co.uk", wantSub: "api",
			wantStatus: model.SuffixRecognized,
		},
		{
			name: "uppercase and one trailing root dot are normalized",
			raw:  "EXAMPLE.COM.", context: ContextLiteral,
			wantKind: model.HostKindDomain, wantValue: "example.com",
			wantReg: "example.com", wantSuffix: "com", wantStatus: model.SuffixRecognized,
		},
		{
			name: "unicode host becomes punycode with a punycode suffix",
			raw:  "例子.中国", context: ContextLiteral,
			wantKind: model.HostKindDomain, wantValue: "xn--fsqu00a.xn--fiqs8s",
			wantReg: "xn--fsqu00a.xn--fiqs8s", wantSuffix: "xn--fiqs8s",
			wantStatus: model.SuffixRecognized,
		},
		{
			name: "punycode spelling of the same host is the same asset",
			raw:  "xn--fsqu00a.xn--fiqs8s", context: ContextLiteral,
			wantKind: model.HostKindDomain, wantValue: "xn--fsqu00a.xn--fiqs8s",
			wantReg: "xn--fsqu00a.xn--fiqs8s", wantSuffix: "xn--fiqs8s",
			wantStatus: model.SuffixRecognized,
		},
		{
			name: "a public suffix alone is not a registrable domain",
			raw:  "co.uk", context: ContextLiteral,
			wantKind: model.HostKindInternal, wantValue: "co.uk",
			wantStatus: model.SuffixUnknown,
		},
		{
			name: "wildcard rule keeps the wildcard label in the suffix",
			raw:  "a.b.ck", context: ContextLiteral,
			wantKind: model.HostKindDomain, wantValue: "a.b.ck",
			// "b.ck" is the public suffix, so the whole value is the
			// registrable domain and there is no subdomain left.
			wantReg: "a.b.ck", wantSuffix: "b.ck",
			wantStatus: model.SuffixRecognized,
		},
		{
			name: "exception rule keeps the exception label in the registrable domain",
			raw:  "www.ck", context: ContextLiteral,
			wantKind: model.HostKindDomain, wantValue: "www.ck",
			wantReg: "www.ck", wantSuffix: "ck", wantStatus: model.SuffixRecognized,
		},
		{
			name: "private suffix from the PSL private section",
			raw:  "user.github.io", context: ContextLiteral,
			wantKind: model.HostKindDomain, wantValue: "user.github.io",
			wantReg: "user.github.io", wantSuffix: "github.io", wantStatus: model.SuffixRecognized,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			asset, ok := classifyOne(t, testCase.raw, testCase.context)
			if !ok {
				t.Fatalf("Classify(%q) rejected the value", testCase.raw)
			}
			if asset.Kind != testCase.wantKind {
				t.Fatalf("kind = %q, want %q", asset.Kind, testCase.wantKind)
			}
			if asset.Value != testCase.wantValue {
				t.Fatalf("value = %q, want %q", asset.Value, testCase.wantValue)
			}
			if asset.RegistrableDomain != testCase.wantReg {
				t.Fatalf("registrable = %q, want %q", asset.RegistrableDomain, testCase.wantReg)
			}
			if asset.PublicSuffix != testCase.wantSuffix {
				t.Fatalf("suffix = %q, want %q", asset.PublicSuffix, testCase.wantSuffix)
			}
			if asset.Subdomain != testCase.wantSub {
				t.Fatalf("subdomain = %q, want %q", asset.Subdomain, testCase.wantSub)
			}
			if asset.SuffixStatus != testCase.wantStatus {
				t.Fatalf("suffix status = %q, want %q", asset.SuffixStatus, testCase.wantStatus)
			}
			if asset.Sources[0].Raw != testCase.raw {
				t.Fatalf("evidence must keep the raw spelling, got %q", asset.Sources[0].Raw)
			}
		})
	}
}

func TestClassifyRejectsNonHosts(t *testing.T) {
	for _, raw := range []string{
		"f",                              // bare single label outside a host context
		"a.b",                            // member expression / no recognized suffix
		"main.js",                        // filename, not a domain
		"style.css",                      // filename, not a domain
		"/api/users",                     // relative path
		"api/users",                      // relative path
		"window.location",                // member expression
		"a..b.com",                       // empty label
		"-leading.com",                   // label starting with a hyphen
		"trailing-.com",                  // label ending with a hyphen
		strings.Repeat("a", 64) + ".com", // label longer than 63
		"under_score.com",                // underscore is not allowed
		"...",                            // only dots
		"",                               // empty
	} {
		if asset, ok := classifyOne(t, raw, ContextLiteral); ok {
			t.Errorf("Classify(%q) unexpectedly produced %s %q", raw, asset.Kind, asset.Value)
		}
	}
}

func TestClassifyInternalHosts(t *testing.T) {
	cases := []struct {
		name       string
		raw        string
		context    string
		wantValue  string
		wantStatus string
	}{
		{"bare f inside a URL", "https://f/", ContextURL, "f", model.SuffixUnknown},
		{"bare f as a host field", "f", ContextHostField, "f", model.SuffixUnknown},
		{"localhost", "localhost", ContextLiteral, "localhost", model.SuffixCustom},
		{"loopback alias", "127.0.0.1", ContextLiteral, "127.0.0.1", model.SuffixNotApplicable},
		{"dot test", "intranet.test", ContextLiteral, "intranet.test", model.SuffixCustom},
		{"dot local", "printer.local", ContextLiteral, "printer.local", model.SuffixCustom},
		{"host with a port", "svc.internalhost:8443", ContextHostField, "svc.internalhost:8443", model.SuffixUnknown},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			asset, ok := classifyOne(t, testCase.raw, testCase.context)
			if !ok {
				t.Fatalf("Classify(%q) rejected the value", testCase.raw)
			}
			if asset.Kind != model.HostKindInternal && asset.Kind != model.HostKindIPv4 {
				t.Fatalf("kind = %q, want internal_host or ipv4", asset.Kind)
			}
			if asset.SuffixStatus != testCase.wantStatus {
				t.Fatalf("suffix status = %q, want %q", asset.SuffixStatus, testCase.wantStatus)
			}
		})
	}
	// A bare value with a port keeps the port on the raw evidence but the
	// value itself is the portless host, so identity ignores the port.
	asset, ok := classifyOne(t, "svc.internalhost:8443", ContextHostField)
	if !ok {
		t.Fatal("host with port was rejected")
	}
	if asset.Value != "svc.internalhost" {
		t.Fatalf("value = %q, want the portless host", asset.Value)
	}
	if asset.Sources[0].Raw != "svc.internalhost:8443" {
		t.Fatalf("raw evidence lost the port: %q", asset.Sources[0].Raw)
	}
}

func TestClassifyCustomSuffixesFromConfig(t *testing.T) {
	extractor := NewExtractor(model.HostsConfig{InternalSuffixes: []string{"corp", ".lan."}})
	asset, ok := extractor.Classify(Candidate{
		Raw: "svc.corp", Context: ContextLiteral, Method: model.HostMethodASTLiteral,
	})
	if !ok {
		t.Fatal("configured suffix was not honored")
	}
	if asset.Kind != model.HostKindInternal || asset.SuffixStatus != model.SuffixCustom {
		t.Fatalf("configured suffix asset = %#v", asset)
	}
	// The shared PSL data is untouched: a public domain is still a domain.
	domain, ok := extractor.Classify(Candidate{
		Raw: "example.com", Context: ContextLiteral, Method: model.HostMethodASTLiteral,
	})
	if !ok || domain.Kind != model.HostKindDomain {
		t.Fatalf("public domain misclassified after config: %#v", domain)
	}
}

func TestClassifyIPAddresses(t *testing.T) {
	cases := []struct {
		raw        string
		context    string
		wantKind   model.HostKind
		wantValue  string
		attributes []string
	}{
		{"1.2.3.4", ContextLiteral, model.HostKindIPv4, "1.2.3.4", []string{model.HostAttrUnclassified}},
		{"10.0.0.1", ContextLiteral, model.HostKindIPv4, "10.0.0.1", []string{model.HostAttrPrivate}},
		{"127.0.0.1", ContextLiteral, model.HostKindIPv4, "127.0.0.1", []string{model.HostAttrLoopback}},
		{"169.254.10.20", ContextLiteral, model.HostKindIPv4, "169.254.10.20", []string{model.HostAttrLinkLocal}},
		{"224.0.0.1", ContextLiteral, model.HostKindIPv4, "224.0.0.1", []string{model.HostAttrMulticast}},
		{"0.0.0.0", ContextLiteral, model.HostKindIPv4, "0.0.0.0", []string{model.HostAttrUnspecified}},
		{"::1", ContextLiteral, model.HostKindIPv6, "::1", []string{model.HostAttrLoopback}},
		{"2001:db8::1", ContextLiteral, model.HostKindIPv6, "2001:db8::1", []string{model.HostAttrUnclassified}},
		{"fd00::1", ContextLiteral, model.HostKindIPv6, "fd00::1", []string{model.HostAttrPrivate}},
		{"fe80::1", ContextLiteral, model.HostKindIPv6, "fe80::1", []string{model.HostAttrLinkLocal}},
		// Brackets and a port come from URL spellings; the port is not identity.
		{"https://[2001:db8::1]:8443/api", ContextURL, model.HostKindIPv6, "2001:db8::1", []string{model.HostAttrUnclassified}},
		// IPv4-mapped IPv6 is reported as the IPv4 address it addresses.
		{"::ffff:1.2.3.4", ContextLiteral, model.HostKindIPv4, "1.2.3.4", []string{model.HostAttrUnclassified}},
		{"[::ffff:10.1.2.3]", ContextLiteral, model.HostKindIPv4, "10.1.2.3", []string{model.HostAttrPrivate}},
	}
	for _, testCase := range cases {
		t.Run(testCase.raw, func(t *testing.T) {
			asset, ok := classifyOne(t, testCase.raw, testCase.context)
			if !ok {
				t.Fatalf("Classify(%q) rejected the value", testCase.raw)
			}
			if asset.Kind != testCase.wantKind {
				t.Fatalf("kind = %q, want %q", asset.Kind, testCase.wantKind)
			}
			if asset.Value != testCase.wantValue {
				t.Fatalf("value = %q, want %q", asset.Value, testCase.wantValue)
			}
			if asset.SuffixStatus != model.SuffixNotApplicable {
				t.Fatalf("suffix status = %q, want not_applicable", asset.SuffixStatus)
			}
			if strings.Join(asset.Attributes, ",") != strings.Join(testCase.attributes, ",") {
				t.Fatalf("attributes = %v, want %v", asset.Attributes, testCase.attributes)
			}
		})
	}
}

func TestClassifyRejectsIPPiecesAndVersions(t *testing.T) {
	for _, raw := range []string{
		"999.1.2.3",   // out of range
		"1.2.3",       // incomplete IPv4
		"1.2.3.4.5",   // too many octets
		"1234",        // bare number
		"v1.2.3",      // version string
		"1.2.3.4.5.6", // dotted digits that are not an address
		"256.256.256.256",
		"::ffff:999.1.2.3",
	} {
		if asset, ok := classifyOne(t, raw, ContextLiteral); ok {
			t.Errorf("Classify(%q) unexpectedly produced %s %q", raw, asset.Kind, asset.Value)
		}
	}
	// A valid address embedded in a longer dotted run must not be carved out.
	if asset, ok := classifyOne(t, "999.1.2.3", ContextLiteral); ok {
		t.Fatalf("carved out %q from an invalid address", asset.Value)
	}
}

func TestIPv6ZoneIdentifierIsKeptOutOfIdentity(t *testing.T) {
	extractor := testExtractor(t)
	withZone, ok := extractor.Classify(Candidate{
		Raw: "fe80::1%eth0", Context: ContextLiteral, Method: model.HostMethodASTLiteral,
	})
	if !ok {
		t.Fatal("zoned address rejected")
	}
	if withZone.Value != "fe80::1" {
		t.Fatalf("value = %q, want the zoned address without its zone", withZone.Value)
	}
	if withZone.Zone != "eth0" {
		t.Fatalf("zone = %q, want eth0", withZone.Zone)
	}
	without, ok := extractor.Classify(Candidate{
		Raw: "fe80::1", Context: ContextLiteral, Method: model.HostMethodASTLiteral,
	})
	if !ok {
		t.Fatal("plain address rejected")
	}
	// Same dedup key: the zone is recorded but never splits an asset in two.
	if withZone.Value != without.Value {
		t.Fatalf("zone changed identity: %q vs %q", withZone.Value, without.Value)
	}
}

func TestAggregatorDeduplicatesAndKeepsEverySource(t *testing.T) {
	extractor := testExtractor(t)
	aggregator := NewAggregator(extractor, model.HostOriginContent)
	aggregator.Add(Candidate{
		Raw: "https://API.Example.com:8443/login", Context: ContextURL,
		Method: model.HostMethodASTLiteral, SourceURL: "https://a/app.js", Line: 10, Column: 4,
	})
	aggregator.Add(Candidate{
		Raw: "api.example.com", Context: ContextLiteral,
		Method: model.HostMethodASTLiteral, SourceURL: "https://a/chunk.js", Line: 3, Column: 2,
	})
	aggregator.Add(Candidate{
		Raw: "api.example.com", Context: ContextRegex,
		Method: model.HostMethodRegex, SourceURL: "https://a/app.js", Line: 40,
	})
	// The same observation twice is the same evidence.
	aggregator.Add(Candidate{
		Raw: "api.example.com", Context: ContextRegex,
		Method: model.HostMethodRegex, SourceURL: "https://a/app.js", Line: 40,
	})
	aggregator.Add(Candidate{
		Raw: "api.EXAMPLE.com.", Context: ContextLiteral,
		Method: model.HostMethodStaticExpression, SourceURL: "https://b/vendor.js", Line: 7, Vendor: true,
	})

	assets := aggregator.Assets()
	if len(assets) != 1 {
		t.Fatalf("expected one asset, got %d: %#v", len(assets), assets)
	}
	asset := assets[0]
	if asset.Value != "api.example.com" || asset.Kind != model.HostKindDomain {
		t.Fatalf("asset = %#v", asset)
	}
	if asset.RegistrableDomain != "example.com" || asset.Subdomain != "api" {
		t.Fatalf("hierarchy = %#v", asset)
	}
	if asset.Origin != model.HostOriginContent {
		t.Fatalf("origin = %q", asset.Origin)
	}
	if len(asset.Sources) != 4 {
		t.Fatalf("expected 4 distinct evidence entries, got %d: %#v", len(asset.Sources), asset.Sources)
	}
	if asset.Occurrences != 4 {
		t.Fatalf("occurrences = %d, want 4", asset.Occurrences)
	}
	if asset.Vendor {
		t.Fatal("a partially vendored asset must not be marked vendor-only")
	}
	methods := map[string]bool{}
	for _, source := range asset.Sources {
		methods[source.Method] = true
	}
	// Different extraction methods must survive the merge.
	for _, method := range []string{
		model.HostMethodURL, model.HostMethodASTLiteral,
		model.HostMethodRegex, model.HostMethodStaticExpression,
	} {
		if !methods[method] {
			t.Errorf("evidence method %q was lost during aggregation", method)
		}
	}
	// Evidence keeps the raw spelling, not the normalized value.
	var raws []string
	for _, source := range asset.Sources {
		raws = append(raws, source.Raw)
	}
	if !contains(raws, "https://API.Example.com:8443/login") {
		t.Fatalf("raw evidence was replaced by its normalization: %v", raws)
	}
}

func TestAggregatorSortsDeterministically(t *testing.T) {
	extractor := testExtractor(t)
	build := func(order []string) []string {
		aggregator := NewAggregator(extractor, model.HostOriginContent)
		for _, raw := range order {
			aggregator.Add(Candidate{Raw: raw, Context: ContextLiteral, Method: model.HostMethodASTLiteral})
		}
		var values []string
		for _, asset := range aggregator.Assets() {
			values = append(values, string(asset.Kind)+":"+asset.Value)
		}
		return values
	}
	first := build([]string{"b.example.com", "10.0.0.1", "a.example.com", "::1", "intranet.test"})
	second := build([]string{"::1", "intranet.test", "a.example.com", "10.0.0.1", "b.example.com"})
	if strings.Join(first, "|") != strings.Join(second, "|") {
		t.Fatalf("asset order depends on insertion order:\n%v\n%v", first, second)
	}
	want := []string{
		"domain:a.example.com", "domain:b.example.com",
		"ipv4:10.0.0.1", "ipv6:::1", "internal_host:intranet.test",
	}
	if strings.Join(first, "|") != strings.Join(want, "|") {
		t.Fatalf("order = %v, want %v", first, want)
	}
}

func TestAggregatorCapsEvidenceAndReportsIt(t *testing.T) {
	extractor := testExtractor(t)
	aggregator := NewAggregator(extractor, model.HostOriginContent)
	for line := 1; line <= MaxEvidencePerAsset+25; line++ {
		aggregator.Add(Candidate{
			Raw: "example.com", Context: ContextLiteral,
			Method: model.HostMethodRegex, SourceURL: "https://a/app.js", Line: line,
		})
	}
	assets := aggregator.Assets()
	if len(assets) != 1 {
		t.Fatalf("expected a single asset, got %d", len(assets))
	}
	if len(assets[0].Sources) != MaxEvidencePerAsset {
		t.Fatalf("evidence = %d, want the cap %d", len(assets[0].Sources), MaxEvidencePerAsset)
	}
	if assets[0].Occurrences != MaxEvidencePerAsset+25 {
		t.Fatalf("occurrences = %d, want the true count %d",
			assets[0].Occurrences, MaxEvidencePerAsset+25)
	}
	found := false
	for _, note := range aggregator.Notes() {
		if note.Code == NoteEvidenceCapped {
			found = true
			if !strings.Contains(note.Message, "25") {
				t.Fatalf("cap diagnostic must state the dropped amount: %q", note.Message)
			}
		}
	}
	if !found {
		t.Fatal("hitting the evidence cap must be reported, never silent")
	}
}

func TestAggregatorReportsPSLFailureWithoutDroppingCandidates(t *testing.T) {
	// A resolver that could not be initialized: classification keeps working,
	// the hierarchy is marked unresolved, and the diagnostic is recorded.
	extractor := &Extractor{resolverErr: ErrPSLUnavailable}
	aggregator := NewAggregator(extractor, model.HostOriginContent)
	aggregator.Add(Candidate{
		Raw: "api.example.com", Context: ContextLiteral, Method: model.HostMethodASTLiteral,
	})
	assets := aggregator.Assets()
	if len(assets) != 1 {
		t.Fatalf("validated candidate was dropped when the PSL was unavailable: %#v", assets)
	}
	if assets[0].SuffixStatus != model.SuffixUnresolved {
		t.Fatalf("suffix status = %q, want unresolved", assets[0].SuffixStatus)
	}
	if assets[0].RegistrableDomain != "" || assets[0].PublicSuffix != "" {
		t.Fatalf("no hierarchy may be invented without the PSL: %#v", assets[0])
	}
	var found bool
	for _, note := range aggregator.Notes() {
		if note.Code == NotePSLUnavailable {
			found = true
		}
	}
	if !found {
		t.Fatal("PSL failure must be reported as a diagnostic")
	}
}

func TestHostFromNetworkURL(t *testing.T) {
	cases := []struct {
		raw      string
		wantHost string
		wantOK   bool
	}{
		{"https://api.example.com/v1/users", "api.example.com", true},
		{"http://api.example.com:8080/x", "api.example.com", true},
		{"wss://socket.example.com/live", "socket.example.com", true},
		{"ws://socket.example.com:9000", "socket.example.com", true},
		{"//api.example.com/x", "api.example.com", true},
		{"https://user:pass@api.example.com/x", "api.example.com", true},
		{"https://api.example.com./x", "api.example.com.", true},
		{"https://[2001:db8::1]:443/x", "2001:db8::1", true},
		{"HTTPS://API.EXAMPLE.COM/X", "API.EXAMPLE.COM", true},
		// Not network URLs.
		{"/api/users", "", false},
		{"api/users", "", false},
		{"mailto:ops@example.com", "", false},
		{"data:text/html;base64,AAA", "", false},
		{"blob:https://example.com/uuid", "", false},
		{"javascript:alert(1)", "", false},
		{"ftp://files.example.com", "", false},
		{"file:///etc/passwd", "", false},
		{"example.com", "", false},
		{"", "", false},
		{"https://", "", false},
		{"https://host:99999/", "", false},
		{"https://host:abc/", "", false},
	}
	for _, testCase := range cases {
		host, ok := HostFromNetworkURL(testCase.raw)
		if ok != testCase.wantOK {
			t.Errorf("HostFromNetworkURL(%q) ok = %v, want %v", testCase.raw, ok, testCase.wantOK)
			continue
		}
		if ok && host != testCase.wantHost {
			t.Errorf("HostFromNetworkURL(%q) = %q, want %q", testCase.raw, host, testCase.wantHost)
		}
	}
}

func TestSnapshotFileIsWrittenOffline(t *testing.T) {
	normalized, info, err := normalizeSnapshot(pslSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	if info.Version == "" || info.Commit == "" {
		t.Fatalf("snapshot provenance missing: %#v", info)
	}
	if info.Converted == 0 {
		t.Fatal("no IDN rules were converted; the snapshot transform is not working")
	}
	if info.Skipped != 0 {
		t.Fatalf("snapshot conversion skipped %d rules", info.Skipped)
	}
	if !strings.Contains(string(normalized), "xn--fiqs8s") {
		t.Fatal("IDN suffix 中国 was not converted to punycode")
	}
	// The licence header travels with the copy that is written to disk.
	if !strings.Contains(string(normalized), "Mozilla Public") {
		t.Fatal("the snapshot's licence header was stripped")
	}

	directory := t.TempDir()
	path, err := ensureSnapshotFile(normalized, []string{directory})
	if err != nil {
		t.Fatal(err)
	}
	written, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(written) != string(normalized) {
		t.Fatal("cache file content differs from the normalized snapshot")
	}
	// A second call reuses the same file instead of rewriting it.
	again, err := ensureSnapshotFile(normalized, []string{directory})
	if err != nil {
		t.Fatal(err)
	}
	if again != path {
		t.Fatalf("cache path changed between calls: %q vs %q", again, path)
	}

	// An unwritable location yields an error instead of falling back to the
	// library's download path.
	blocked := filepath.Join(directory, "file-not-a-directory")
	if err := os.WriteFile(blocked, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureSnapshotFile(normalized, []string{filepath.Join(blocked, "psl")}); err == nil {
		t.Fatal("unwritable cache directory must fail rather than download")
	}
}

func TestSnapshotFileIsRepairedWhenCorrupted(t *testing.T) {
	normalized, _, err := normalizeSnapshot(pslSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "public_suffix_list-"+shortHash(normalized)+".dat")
	if err := os.WriteFile(path, []byte("// corrupted\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	repaired, err := ensureSnapshotFile(normalized, []string{directory})
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(repaired)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != string(normalized) {
		t.Fatal("corrupted cache file was not repaired")
	}
}

func TestDefaultResolverIsSharedAndReadOnly(t *testing.T) {
	first, err := DefaultResolver()
	if err != nil {
		t.Fatalf("resolver initialization failed: %v", err)
	}
	second, err := DefaultResolver()
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("DefaultResolver must return one shared instance")
	}
	version, commit := first.Version()
	if version == "" || commit == "" {
		t.Fatalf("PSL provenance missing: %q %q", version, commit)
	}
	split, ok := first.Split("api.example.co.uk")
	if !ok || split.Registrable != "example.co.uk" || split.Suffix != "co.uk" {
		t.Fatalf("split = %+v ok = %v", split, ok)
	}
	// Concurrent use of the shared instance must be safe (also exercised by
	// the race-detector runs).
	done := make(chan struct{})
	for worker := 0; worker < 8; worker++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for index := 0; index < 200; index++ {
				if _, ok := first.Split("api.example.co.uk"); !ok {
					t.Error("concurrent split failed")
					return
				}
			}
		}()
	}
	for worker := 0; worker < 8; worker++ {
		<-done
	}
}

func TestValidASCIIHostRules(t *testing.T) {
	valid := []string{"example.com", "a.b.c.example.co.uk", "xn--fsqu00a.xn--fiqs8s", "a-b.example.com"}
	for _, host := range valid {
		if !validASCIIHost(host) {
			t.Errorf("validASCIIHost(%q) = false", host)
		}
	}
	invalid := []string{
		"", ".", "a.", ".a", "a..b", "-a.com", "a-.com", "a_b.com",
		strings.Repeat("a", 64) + ".com",
		strings.Repeat("a.", 130) + "com",
		"a.b c", "A.com", "a/b.com",
	}
	for _, host := range invalid {
		if validASCIIHost(host) {
			t.Errorf("validASCIIHost(%q) = true", host)
		}
	}
}

func TestSplitHostPort(t *testing.T) {
	cases := map[string]string{
		"api.example.com:8443": "api.example.com",
		"api.example.com":      "api.example.com",
		"1.2.3.4:80":           "1.2.3.4",
		"[::1]:8080":           "::1",
		"::1":                  "::1",
		"host:abc":             "host:abc",
		"":                     "",
	}
	for input, want := range cases {
		if got := SplitHostPort(input); got != want {
			t.Errorf("SplitHostPort(%q) = %q, want %q", input, got, want)
		}
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// TestSnapshotNormalizationIgnoresLineEndings guards the crash this package hit
// on a CRLF checkout: the splitter library panics on a line that is whitespace
// only, and a CR left by CRLF line endings is enough to produce one.
func TestSnapshotNormalizationIgnoresLineEndings(t *testing.T) {
	for name, input := range map[string][]byte{
		"lf":   []byte("// comment\ncom\n\ncn\n*.ck\n"),
		"crlf": []byte("// comment\r\ncom\r\n\r\ncn\r\n*.ck\r\n"),
		"cr":   []byte("// comment\rcom\r\r\ncn\r*.ck\r"),
	} {
		normalized, _, err := normalizeSnapshot(input)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if strings.ContainsRune(string(normalized), '\r') {
			t.Fatalf("%s: normalized snapshot kept a CR byte: %q", name, normalized)
		}
		for _, line := range strings.Split(string(normalized), "\n") {
			if line != "" && strings.TrimSpace(line) == "" {
				t.Fatalf("%s: whitespace-only line survived normalization: %q", name, line)
			}
		}
	}
}

// TestSplitterRejectsMalformedSnapshotWithoutPanicking asserts the library's
// panic path is converted into a degraded resolver: a bad snapshot must never
// take the whole scan down.
func TestSplitterRejectsMalformedSnapshotWithoutPanicking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "public_suffix_list.dat")
	// A CRLF file whose blank lines are "\r": the exact shape that panicked.
	if err := os.WriteFile(path, []byte("// comment\r\ncom\r\n\r\ncn\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newSplitter(path); err == nil {
		t.Fatal("a snapshot the splitter cannot read must be reported as an error")
	} else if !errors.Is(err, ErrPSLUnavailable) {
		t.Fatalf("error = %v, want ErrPSLUnavailable", err)
	}
}
