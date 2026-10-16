package discover

import (
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/youmulijiang/jsowl/internal/extract"
	"github.com/youmulijiang/jsowl/internal/model"
)

func testSource(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

// hostValues classifies the candidates a JS body produced and returns the
// resulting host values, so a test can assert on the vocabulary the report
// actually shows.
func hostValues(t *testing.T, body string) []string {
	t.Helper()
	source := testSource(t, "https://app.example.com/static/app.js")
	analysis := AnalyzeJS(source, []byte(body))
	aggregator := extract.NewAggregator(extract.NewExtractor(model.HostsConfig{}), model.HostOriginContent)
	for _, candidate := range analysis.Hosts {
		aggregator.Add(candidate)
	}
	values := []string{}
	for _, asset := range aggregator.Assets() {
		values = append(values, asset.Value)
	}
	return values
}

func hasValue(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestAnalyzeJSFindsHostsInLiterals(t *testing.T) {
	values := hostValues(t, `
const a = "https://api.example.com/v1/users";
const b = "//cdn.example.net/lib.js";
const c = "ws://socket.example.org/live";
const d = "example.co.uk";
const e = "https://user:pass@secure.example.com/x";
const f = "https://[2001:db8::1]:8443/api";
const g = "10.20.30.40";
`)
	for _, want := range []string{
		"api.example.com", "cdn.example.net", "socket.example.org",
		"example.co.uk", "secure.example.com", "2001:db8::1", "10.20.30.40",
	} {
		if !hasValue(values, want) {
			t.Errorf("host %q not found in %v", want, values)
		}
	}
}

func TestAnalyzeJSRejectsNonHosts(t *testing.T) {
	values := hostValues(t, `
import "./main.js";
const css = "style.css";
const obj = window.location;
const relative = "/api/users";
const route = "#/orders";
const member = "a.b";
const identifier = "f";
const empty = "";
const data = "data:text/html;base64,AAAA";
`)
	if len(values) != 0 {
		t.Fatalf("non-hosts were classified as hosts: %v", values)
	}
}

// An explicit address literal is a supported source: the domain is reported
// and the evidence says it came from an email.
func TestAnalyzeJSReportsEmailDomainsWithTheirOrigin(t *testing.T) {
	source := testSource(t, "https://app.example.com/static/app.js")
	analysis := AnalyzeJS(source, []byte(`const contact = "mailto:ops@mail.example.com";`))
	aggregator := extract.NewAggregator(extract.NewExtractor(model.HostsConfig{}), model.HostOriginContent)
	for _, candidate := range analysis.Hosts {
		aggregator.Add(candidate)
	}
	assets := aggregator.Assets()
	if len(assets) == 0 {
		t.Fatal("the email domain was not reported")
	}
	var note string
	for _, asset := range assets {
		if asset.Value != "mail.example.com" {
			t.Fatalf("unexpected host from an email literal: %#v", assets)
		}
		note = asset.Sources[0].Note
	}
	if !strings.Contains(note, "email_domain") {
		t.Fatalf("email origin not recorded: %q", note)
	}
}

func TestAnalyzeJSDecodesEscapesAndTemplates(t *testing.T) {
	values := hostValues(t, `
const escaped = "https://api.example.com/v1";
const solidus = "https:\/\/slash.example.com\/v1";
const hexish = "https://hex\x2Eexample.com/v1";
const template = `+"`"+`https://static.example.com/v1`+"`"+`;
const parts = "https://" + "concat." + "example.com/x";
`)
	for _, want := range []string{"api.example.com", "slash.example.com", "hex.example.com", "static.example.com", "concat.example.com"} {
		if !hasValue(values, want) {
			t.Errorf("host %q not found in %v", want, values)
		}
	}
}

func TestAnalyzeJSStopsAtDynamicExpressions(t *testing.T) {
	source := testSource(t, "https://app.example.com/static/app.js")
	analysis := AnalyzeJS(source, []byte(`
const host = window.location.hostname;
const dynamic = `+"`"+`https://${host}/v1`+"`"+`;
const reassigned = "first.example.com";
const later = reassigned + "/v1";
fetch(dynamic);
`))
	// Not one host may be invented from a runtime value, and the fold must not
	// pick up the reassignable identifier either.
	for _, candidate := range analysis.Hosts {
		if candidate.Method == model.HostMethodStaticExpression {
			t.Fatalf("a dynamic expression produced a folded host: %#v", candidate)
		}
	}
	var sawDynamic bool
	for _, note := range analysis.Notes {
		if note.Code == extract.NoteDynamicHost {
			sawDynamic = true
		}
	}
	if !sawDynamic {
		t.Fatal("a dynamic host expression must be recorded as unresolved information")
	}
}

func TestAnalyzeJSHostFieldContextKeepsSingleLabels(t *testing.T) {
	source := testSource(t, "https://app.example.com/static/app.js")
	analysis := AnalyzeJS(source, []byte(`
const config = { host: "f", baseURL: "g:8443" };
const other = { name: "h" };
`))
	aggregator := extract.NewAggregator(extract.NewExtractor(model.HostsConfig{}), model.HostOriginContent)
	for _, candidate := range analysis.Hosts {
		aggregator.Add(candidate)
	}
	assets := aggregator.Assets()
	values := map[string]model.HostKind{}
	for _, asset := range assets {
		values[asset.Value] = asset.Kind
	}
	// A host field is an explicit host context, so a single-label value is kept
	// as an internal-host candidate (and the port is stripped).
	if values["f"] != model.HostKindInternal {
		t.Fatalf("host field value not kept as an internal host: %#v", values)
	}
	if values["g"] != model.HostKindInternal {
		t.Fatalf("host field value with a port not kept: %#v", values)
	}
	// A value under an unrelated key is not a host at all.
	if _, ok := values["h"]; ok {
		t.Fatalf("an unrelated field value was treated as a host: %#v", values)
	}
}

func TestAnalyzeJSRecoversHostsFromComments(t *testing.T) {
	source := testSource(t, "https://app.example.com/static/app.js")
	analysis := AnalyzeJS(source, []byte(`
// allowed origins: https://allow.example.com, https://alt.example.net
/* contact: ops@mail.example.org */
const x = 1;
`))
	aggregator := extract.NewAggregator(extract.NewExtractor(model.HostsConfig{}), model.HostOriginContent)
	for _, candidate := range analysis.Hosts {
		aggregator.Add(candidate)
	}
	assets := aggregator.Assets()
	found := map[string]string{}
	for _, asset := range assets {
		for _, source := range asset.Sources {
			found[asset.Value] = source.Note
		}
	}
	for _, want := range []string{"allow.example.com", "alt.example.net", "mail.example.org"} {
		if _, ok := found[want]; !ok {
			t.Fatalf("comment host %q not recovered from %v", want, found)
		}
	}
	// The comment origin is recorded, and an email domain says so explicitly.
	if note, ok := found["allow.example.com"]; !ok || note != "comment" {
		t.Fatalf("comment origin note = %q", note)
	}
	if note, ok := found["mail.example.org"]; !ok || note != "comment,email_domain" {
		t.Fatalf("email origin note = %q", note)
	}
}

func TestHostsFromTextBoundaries(t *testing.T) {
	body := []byte(`
version 1.2.3.4.5 and 999.1.2.3 must not yield addresses
but 192.0.2.10 and [2001:db8::5] and https://ok.example.com/x must
see main.js and style.css and a.b for non-hosts
`)
	candidates := HostsFromText(testSource(t, "https://app.example.com/plain.txt"), body)
	raws := []string{}
	for _, candidate := range candidates {
		raws = append(raws, candidate.Raw)
	}
	// The scanner itself must not carve a valid address out of a longer dotted
	// run: that is a candidate-level property.
	for _, unwanted := range []string{"99.1.2.3", "1.2.3.4"} {
		for _, raw := range raws {
			if raw == unwanted {
				t.Fatalf("fragment %q was extracted from %q", unwanted, body)
			}
		}
	}
	// Filenames and member expressions may be offered as candidates, but they
	// must never become host assets: classification is what rejects them.
	aggregator := extract.NewAggregator(extract.NewExtractor(model.HostsConfig{}), model.HostOriginContent)
	for _, candidate := range candidates {
		aggregator.Add(candidate)
	}
	values := []string{}
	for _, asset := range aggregator.Assets() {
		values = append(values, asset.Value)
	}
	for _, unwanted := range []string{"main.js", "style.css", "a.b", "99.1.2.3", "1.2.3.4"} {
		if hasValue(values, unwanted) {
			t.Fatalf("non-host %q was classified as an asset: %v", unwanted, values)
		}
	}
	// A full URL is offered as a candidate with the URL method, and its host
	// is classified from it.
	rawJoined := strings.Join(raws, " ")
	for _, want := range []string{"192.0.2.10", "2001:db8::5", "https://ok.example.com/x"} {
		if !containsSubstring(rawJoined, want) {
			t.Errorf("%q not recovered from text: %v", want, raws)
		}
	}
	if !hasValue(values, "ok.example.com") {
		t.Errorf("URL host not classified: %v", values)
	}
}

func TestHostsFromTextRespectsTheMatchCap(t *testing.T) {
	body := []byte("")
	for index := 0; index < extract.MaxRegexMatchesPerFile+200; index++ {
		body = append(body, []byte("https://host"+strconv.Itoa(index)+".example.com/x ")...)
	}
	candidates := HostsFromText(testSource(t, "https://app.example.com/big.txt"), body)
	if len(candidates) > extract.MaxRegexMatchesPerFile {
		t.Fatalf("candidate cap exceeded: %d", len(candidates))
	}
	if len(candidates) == 0 {
		t.Fatal("no candidates found at all")
	}
}

func TestAnalyzeJSFlagsUnparseableBodies(t *testing.T) {
	// A body the parser cannot turn into a tree still yields its hosts through
	// the bounded text scan, and says so.
	source := testSource(t, "https://app.example.com/static/junk.js")
	analysis := AnalyzeJS(source, []byte{0x00, 0x01, 0x02, 0xff, 0xfe})
	if len(analysis.Hosts) != 0 {
		t.Fatalf("binary junk produced hosts: %#v", analysis.Hosts)
	}
	analysis = AnalyzeJS(source, []byte("\x00\x01 https://fallback.example.com/x \x02"))
	aggregator := extract.NewAggregator(extract.NewExtractor(model.HostsConfig{}), model.HostOriginContent)
	for _, candidate := range analysis.Hosts {
		aggregator.Add(candidate)
	}
	found := false
	for _, asset := range aggregator.Assets() {
		if asset.Value == "fallback.example.com" {
			found = true
		}
	}
	// Either the AST recovered the literal or the fallback scan did; both are
	// acceptable, silence is not.
	if !found {
		t.Fatalf("host in an unparseable body was lost: %#v", analysis.Hosts)
	}
}

func TestAnalyzeJSKeepsOneObservationPerLocation(t *testing.T) {
	values := hostValues(t, `
const a = "https://api.example.com/v1";
const b = "https://api.example.com/v1";
`)
	if !hasValue(values, "api.example.com") {
		t.Fatalf("host not found: %v", values)
	}
	// Two distinct literals are two observations of the same host; the host
	// itself appears once.
	count := 0
	for _, value := range values {
		if value == "api.example.com" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("host appeared %d times in the asset list", count)
	}
}

func containsSubstring(haystack, needle string) bool {
	for index := 0; index+len(needle) <= len(haystack); index++ {
		if haystack[index:index+len(needle)] == needle {
			return true
		}
	}
	return false
}

// TestBasePathsFromAST covers the JS binding shape: axios.create({ baseURL:
// "/api" }), an apiPrefix assignment and a trailing slash.
func TestBasePathsFromAST(t *testing.T) {
	source := testSource(t, "https://app.example.com/static/app.js")
	analysis := AnalyzeJS(source, []byte(`
const api = axios.create({ baseURL: "/api" });
const client = axios.create({ base_url: "/v1/" });
let apiPrefix;
apiPrefix = "/api/internal";
const gateway = { baseURL: "https://gw.example.net" };
const unrelated = { name: "main.js" };
`))
	found := map[string]bool{}
	for _, name := range BasePathNames(analysis.BasePaths) {
		found[name] = true
	}
	for _, want := range []string{"/api", "/v1", "/api/internal"} {
		if !found[want] {
			t.Errorf("base path %q not recovered from the AST, got %v", want, found)
		}
	}
	// A URL is a host, not a path prefix, and an unrelated key is not a base.
	for _, unwanted := range []string{"https://gw.example.net", "https://gw.example.net/", "main.js"} {
		if found[unwanted] {
			t.Errorf("%q was mistaken for a base path", unwanted)
		}
	}
}

// TestBasePathsFromText covers the shape the AST cannot read: a config blob
// carrying "baseUrl": "/api" inside a string.
func TestBasePathsFromText(t *testing.T) {
	body := []byte(`const blob = '{"baseurl":"/legacy/api","other":1}';` +
		"\n" + `const json = { "apiPrefix": "/v2" };`)
	found := map[string]bool{}
	for _, candidate := range scanBasePathText(body, maxBasePathsPerFile) {
		found[candidate.Path] = true
		if candidate.Line == 0 || candidate.Column == 0 {
			t.Errorf("base path %q has no source position", candidate.Path)
		}
	}
	for _, want := range []string{"/legacy/api", "/v2"} {
		if !found[want] {
			t.Errorf("base path %q not recovered from the text pass, got %v", want, found)
		}
	}
}

func TestNormalizeBasePathRejectsNonPrefixes(t *testing.T) {
	for raw, want := range map[string]string{
		"/api":          "/api",
		"/api/":         "/api",
		"/api//v1":      "/api/v1",
		"/a/b/../c":     "/a/c",
		"api":           "",
		"/":             "",
		"":              "",
		"https://h/api": "",
		"/api?x=1":      "",
		"/api#frag":     "",
		"/по":           "",
		"/ap i":         "",
	} {
		got, ok := normalizeBasePath(raw)
		if want == "" {
			if ok {
				t.Errorf("normalizeBasePath(%q) = %q, want rejection", raw, got)
			}
			continue
		}
		if !ok || got != want {
			t.Errorf("normalizeBasePath(%q) = %q (%v), want %q", raw, got, ok, want)
		}
	}
}
