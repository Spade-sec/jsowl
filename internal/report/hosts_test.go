package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/youmulijiang/jsowl/internal/model"
)

// hostFixtureResult mixes the host shapes the domain statistics must tell
// apart: a real domain, a bare single-label host, an IP literal, a host with a
// port, a reserved-suffix name and a relative reference with no host at all.
func hostFixtureResult() *model.Result {
	return &model.Result{
		Target: "https://app.example.com/",
		Mode:   model.ModeAuto,
		Resources: []model.Resource{
			{URL: "https://app.example.com/static/app.js", Type: model.ResourceTypeScript, StatusCode: 200},
			{URL: "https://10.0.0.7/libs/vendor.js", Type: model.ResourceTypeScript, StatusCode: 200},
		},
		Endpoints: []model.Endpoint{
			{Raw: "/api/users", URL: "https://app.example.com/api/users", SourceURL: "https://app.example.com/static/app.js", Type: "api", Method: "GET"},
			{Raw: "https://f/", URL: "https://f/", SourceURL: "https://app.example.com/static/app.js", Type: "api"},
			{Raw: "/api/orders", URL: "https://app.example.com:8443/api/orders", SourceURL: "https://app.example.com/static/app.js", Type: "api", Method: "GET"},
			{Raw: "/metrics", URL: "http://10.0.0.7:9100/metrics", SourceURL: "https://app.example.com/static/app.js", Type: "api", Method: "GET"},
			{Raw: "v1/report", URL: "v1/report?page=2", SourceURL: "https://app.example.com/static/app.js", Type: "api"},
			{Raw: "/healthz", URL: "https://lab.internal.test/healthz", SourceURL: "https://app.example.com/static/app.js", Type: "api", Method: "GET"},
		},
		Findings: []model.Finding{{
			RuleID: "hae.PII.邮箱地址", RuleName: "邮箱地址",
			Category: model.RuleCategorySensitive, Severity: model.SeverityMedium,
			Value: "ops@example.com", SourceURL: "https://app.example.com/static/app.js",
			Line: 4, Column: 2,
		}},
	}
}

func metricByKey(t *testing.T, summary reportSummary, key string) metric {
	t.Helper()
	for _, entry := range summary.AttackMetrics {
		if entry.Key == key {
			return entry
		}
	}
	t.Fatalf("metric %q not found", key)
	return metric{}
}

func bucketByHost(summary reportSummary, host string) (domainBucket, bool) {
	for _, bucket := range summary.Domains {
		if bucket.Host == host {
			return bucket, true
		}
	}
	return domainBucket{}, false
}

// TestSummaryDomainCountExcludesNonDomains is the regression test for the bug
// where any non-empty URL host was counted as a domain: https://f/ produced a
// "domain", and an IP literal was counted alongside real domains.
func TestSummaryDomainCountExcludesNonDomains(t *testing.T) {
	summary := buildSummary(hostFixtureResult(), fixedClock())

	domains := metricByKey(t, summary, "domains")
	// Only app.example.com is a domain. "f" is an internal-host candidate, the
	// IP is an IPv4 asset, and the relative reference has no host at all.
	if domains.Value != 1 {
		t.Fatalf("domain metric = %d, want 1: %#v", domains.Value, summary.Domains)
	}
	for _, bucket := range summary.Domains {
		if bucket.Host == "f" {
			if bucket.Kind != string(model.HostKindInternal) {
				t.Fatalf(`"f" must not be a domain: %#v`, bucket)
			}
		}
		if bucket.Host == "10.0.0.7" && bucket.Kind != string(model.HostKindIPv4) {
			t.Fatalf("an IP literal must not be a domain: %#v", bucket)
		}
	}
	if _, ok := bucketByHost(summary, "f"); !ok {
		t.Fatal(`"f" disappeared instead of being reported as an internal host`)
	}
	if _, ok := bucketByHost(summary, "app.example.com"); !ok {
		t.Fatal("the real domain is missing from the ranking")
	}

	// A port never splits a host: both spellings of app.example.com collapse
	// into one bucket.
	bucket, _ := bucketByHost(summary, "app.example.com")
	if bucket.Endpoints != 2 {
		t.Fatalf("port changed host identity: %d endpoints in the bucket", bucket.Endpoints)
	}

	// The relative reference is grouped on its own and never attributed to the
	// target domain.
	unresolved, ok := bucketByHost(summary, unresolvedHost)
	if !ok {
		t.Fatal("the relative reference must be grouped as an unresolved host")
	}
	if unresolved.Kind != "unresolved" || unresolved.Endpoints != 1 {
		t.Fatalf("unresolved bucket = %#v", unresolved)
	}

	// Host classification never removes records: every endpoint and resource
	// still has a bucket.
	var endpointRows int
	for _, bucket := range summary.Domains {
		endpointRows += bucket.Endpoints
	}
	if endpointRows != len(hostFixtureResult().Endpoints) {
		t.Fatalf("endpoint rows in buckets = %d, want %d", endpointRows, len(hostFixtureResult().Endpoints))
	}
}

func TestSummaryReservedSuffixesAreInternalHosts(t *testing.T) {
	result := &model.Result{
		Target: "https://app.example.com/",
		Endpoints: []model.Endpoint{
			{Raw: "/a", URL: "https://lab.internal.test/a", Type: "api"},
			{Raw: "/b", URL: "https://printer.local/b", Type: "api"},
			{Raw: "/c", URL: "http://localhost/c", Type: "api"},
			{Raw: "/d", URL: "https://app.example.com/d", Type: "api"},
		},
	}
	summary := buildSummary(result, fixedClock())
	if got := metricByKey(t, summary, "domains").Value; got != 1 {
		t.Fatalf("domain metric = %d, want 1 (only the .com host)", got)
	}
	kinds := map[string]string{}
	for _, bucket := range summary.Domains {
		kinds[bucket.Host] = bucket.Kind
	}
	for host, want := range map[string]string{
		"lab.internal.test": string(model.HostKindInternal),
		"printer.local":     string(model.HostKindInternal),
		"localhost":         string(model.HostKindInternal),
		"app.example.com":   string(model.HostKindDomain),
	} {
		if kinds[host] != want {
			t.Errorf("host %q kind = %q, want %q", host, kinds[host], want)
		}
	}
	// The suffix policy is stated in the host summary notes so a reader is not
	// left guessing why a .test host is not in the domain list.
	notes := strings.Join(summary.Hosts.Notes, " ")
	for _, want := range []string{"公共后缀", "内部主机", "未做 DNS 查询"} {
		if !strings.Contains(notes, want) {
			t.Errorf("host notes must explain the counting rules, missing %q", want)
		}
	}
}

func TestSummaryHostMetricsSeparatePopulations(t *testing.T) {
	result := hostFixtureResult()
	result.Hosts = []model.HostAsset{
		{Kind: model.HostKindDomain, Value: "api.example.com", SuffixStatus: model.SuffixRecognized, Origin: model.HostOriginContent},
		{Kind: model.HostKindIPv4, Value: "203.0.113.9", SuffixStatus: model.SuffixNotApplicable, Origin: model.HostOriginContent},
		{Kind: model.HostKindInternal, Value: "cache.internal", SuffixStatus: model.SuffixUnknown, Origin: model.HostOriginContent},
	}
	summary := buildSummary(result, fixedClock())

	content, scanned := map[string]int{}, map[string]int{}
	for _, entry := range summary.Hosts.Metrics {
		content[entry.Kind] = entry.Content
		scanned[entry.Kind] = entry.Scan
	}
	if content[string(model.HostKindDomain)] != 1 ||
		content[string(model.HostKindIPv4)] != 1 ||
		content[string(model.HostKindInternal)] != 1 {
		t.Fatalf("content host metrics = %#v", summary.Hosts.Metrics)
	}
	if summary.Hosts.ContentTotal != 3 {
		t.Fatalf("content total = %d, want 3", summary.Hosts.ContentTotal)
	}
	// Scan-associated hosts are the scan's own reach, counted separately.
	if scanned[string(model.HostKindDomain)] != 1 || summary.Hosts.ScanTotal == 0 {
		t.Fatalf("scan host metrics = %#v", summary.Hosts)
	}
	// The domain metric follows the scan population, not the content one: a
	// domain merely mentioned in code does not inflate it.
	if got := metricByKey(t, summary, "domains").Value; got != scanned[string(model.HostKindDomain)] {
		t.Fatalf("domain metric %d != scan-associated domains %d", got, scanned[string(model.HostKindDomain)])
	}
	if summary.Hosts.PSLVersion == "" || summary.Hosts.PSLStatus != "ok" {
		t.Fatalf("PSL provenance missing from the report: %#v", summary.Hosts)
	}
	if strings.Contains(strings.Join(summary.Hosts.Notes, " "), "两类") == false {
		t.Fatal("the two populations must be explained in the notes")
	}
}

func TestSummaryDerivesScanHostsForResultsFromOlderVersions(t *testing.T) {
	// A report.json written before host extraction existed carries no
	// ScanHosts; the summary derives them instead of reporting zero hosts.
	result := hostFixtureResult()
	summary := buildSummary(result, fixedClock())
	if len(result.ScanHosts) == 0 {
		t.Fatal("scan hosts were not derived for a legacy result")
	}
	if summary.Hosts.ScanTotal != len(result.ScanHosts) {
		t.Fatalf("scan total = %d, want %d", summary.Hosts.ScanTotal, len(result.ScanHosts))
	}
	if got := metricByKey(t, summary, "domains").Value; got != 1 {
		t.Fatalf("derived domain metric = %d, want 1", got)
	}
}

func TestWriteHTMLCarriesHostAssetsAndRules(t *testing.T) {
	result := hostFixtureResult()
	result.Hosts = []model.HostAsset{{
		Kind: model.HostKindDomain, Value: "api.example.com",
		RegistrableDomain: "example.com", PublicSuffix: "com", Subdomain: "api",
		SuffixStatus: model.SuffixRecognized, Origin: model.HostOriginContent,
		Occurrences: 1,
		Sources: []model.HostEvidence{{
			SourceURL: "https://app.example.com/static/app.js", Raw: "https://API.example.com/v1",
			Line: 12, Column: 4, Method: model.HostMethodURL,
		}},
	}}
	path := filepath.Join(t.TempDir(), "report.html")
	if err := WriteHTML(path, result); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	page := string(data)
	for _, want := range []string{
		`"hosts"`,                // the host summary block
		"scanHosts:",             // the scan-associated population
		"api.example.com",        // a content-discovered asset
		"registrable_domain",     // the hierarchy survives into the page
		`"kind":"internal_host"`, // "f" is in the page as an internal host
		"extraction_method",      // evidence keeps how a host was recovered
		"suffix_status",          // and how its hierarchy was resolved
	} {
		if !strings.Contains(page, want) {
			t.Errorf("report missing %q", want)
		}
	}
}

// TestHostOutputsAgreeAcrossJSONTextAndReport checks the "one classification,
// several outputs" requirement: the JSON, the plain-text list and the report's
// own metrics must describe the same hosts.
func TestHostOutputsAgreeAcrossJSONTextAndReport(t *testing.T) {
	result := hostFixtureResult()
	result.Hosts = []model.HostAsset{{
		Kind: model.HostKindDomain, Value: "api.example.com",
		RegistrableDomain: "example.com", PublicSuffix: "com", Subdomain: "api",
		SuffixStatus: model.SuffixRecognized, Origin: model.HostOriginContent, Occurrences: 1,
		Sources: []model.HostEvidence{{
			SourceURL: "https://app.example.com/app.js", Raw: "https://api.example.com/v1",
			Line: 1, Column: 1, Method: model.HostMethodURL,
		}},
	}}
	// The derivation the pipeline's finalize performs before any writer runs.
	ensureScanHosts(result)

	directory := t.TempDir()
	if err := WriteJSON(filepath.Join(directory, "report.json"), result); err != nil {
		t.Fatal(err)
	}
	if err := WriteTextReports(directory, result); err != nil {
		t.Fatal(err)
	}
	if err := WriteHTML(filepath.Join(directory, "report.html"), result); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(filepath.Join(directory, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var decoded model.Result
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Hosts) != 1 || len(decoded.ScanHosts) == 0 {
		t.Fatalf("JSON lost the host populations: %d content / %d scan",
			len(decoded.Hosts), len(decoded.ScanHosts))
	}
	jsonDomains := map[string]bool{}
	for _, asset := range append(append([]model.HostAsset{}, decoded.Hosts...), decoded.ScanHosts...) {
		if asset.Kind == model.HostKindDomain {
			jsonDomains[asset.Value] = true
		}
	}

	text, err := os.ReadFile(filepath.Join(directory, "domain.txt"))
	if err != nil {
		t.Fatal(err)
	}
	textDomains := map[string]bool{}
	for _, line := range strings.Split(string(text), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		textDomains[line] = true
	}
	if len(textDomains) != len(jsonDomains) {
		t.Fatalf("domain.txt and report.json disagree: %v vs %v", textDomains, jsonDomains)
	}
	for domain := range jsonDomains {
		if !textDomains[domain] {
			t.Fatalf("domain %q is in the JSON but not in domain.txt", domain)
		}
	}

	summary := buildSummary(result, fixedClock())
	if summary.Hosts.ScanTotal != len(result.ScanHosts) {
		t.Fatalf("summary scan total = %d, want %d", summary.Hosts.ScanTotal, len(result.ScanHosts))
	}
	// The domain metric counts exactly the scan-associated hosts the JSON
	// classifies as domains: an IP, an internal host or a bare value is not
	// one of them.
	jsonDomainHosts := 0
	for _, asset := range decoded.ScanHosts {
		if asset.Kind == model.HostKindDomain {
			jsonDomainHosts++
		}
	}
	if got := metricByKey(t, summary, "domains").Value; got != jsonDomainHosts {
		t.Fatalf("domain metric = %d, JSON scan domains = %d", got, jsonDomainHosts)
	}
	if jsonDomainHosts == len(decoded.ScanHosts) {
		t.Fatal("the fixture no longer distinguishes domains from other hosts")
	}
}

// TestSplitHostReportRendersEveryKind checks the server-rendered host page:
// every host kind gets its own section with its hierarchy, status and first
// source, and the page states the counting rules and the extraction limits.
func TestSplitHostReportRendersEveryKind(t *testing.T) {
	result := hostFixtureResult()
	result.Hosts = []model.HostAsset{{
		Kind: model.HostKindDomain, Value: "api.example.com",
		RegistrableDomain: "example.com", PublicSuffix: "com", Subdomain: "api",
		SuffixStatus: model.SuffixRecognized, Origin: model.HostOriginContent, Occurrences: 2,
		Sources: []model.HostEvidence{
			{SourceURL: "https://app.example.com/app.js", Raw: "https://api.example.com/v1", Line: 12, Column: 4, Method: model.HostMethodURL},
			{SourceURL: "https://app.example.com/chunk.js", Raw: "api.example.com", Line: 3, Method: model.HostMethodASTLiteral, Note: "comment"},
		},
	}}
	directory := t.TempDir()
	if err := WriteSplitReports(directory, result); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(directory, "主机资产报告.html"))
	if err != nil {
		t.Fatalf("主机资产报告.html was not written: %v", err)
	}
	page := string(data)
	for _, want := range []string{
		"主机类型统计",
		"域名", "IPv4", "内部主机候选",
		"api.example.com", "example.com", "已识别后缀",
		"10.0.0.7", "私网",
		"f", "lab.internal.test", "保留/特殊用途",
		"无法解析出主机",
		"内容发现", "扫描关联",
		"两类重合主机",
		"不做 DNS 查询",
		"公共后缀列表快照",
		"URL 解析", "AST 字面量",
		"data-copy=\"api.example.com\"",
		"其余 1 条来源",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("host report missing %q", want)
		}
	}
	// No host kind may be presented without its counting rule.
	if !strings.Contains(page, "内部主机候选不计入域名统计") {
		t.Error("the host report must state that internal hosts are not domains")
	}
}

// TestSplitNavigationListsHostOutputs checks that every split page links to the
// host page and the three plain-text host lists, so no output is orphaned.
func TestSplitNavigationListsHostOutputs(t *testing.T) {
	result := hostFixtureResult()
	directory := t.TempDir()
	if err := WriteSplitReports(directory, result); err != nil {
		t.Fatal(err)
	}
	if err := WriteTextReports(directory, result); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"主机资产报告.html", "API报告.html", "资源报告.html"} {
		data, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			t.Fatal(err)
		}
		page := string(data)
		for _, want := range []string{
			"主机资产报告", "域名清单", "IP 清单", "内部主机",
			"domain.txt", "ip.txt", "internal_hosts.txt",
		} {
			if !strings.Contains(page, want) {
				t.Errorf("%s navigation missing %q", name, want)
			}
		}
	}
	// The main report links to the host page as well.
	if err := WriteHTML(filepath.Join(directory, "report.html"), result); err != nil {
		t.Fatal(err)
	}
	main, err := os.ReadFile(filepath.Join(directory, "report.html"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"主机资产报告.html", "domain.txt", "ip.txt", "internal_hosts.txt"} {
		if !strings.Contains(string(main), want) {
			t.Errorf("main report navigation missing %q", want)
		}
	}
}
