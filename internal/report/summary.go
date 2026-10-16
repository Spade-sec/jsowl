package report

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/youmulijiang/jsowl/internal/extract"
	"github.com/youmulijiang/jsowl/internal/model"
)

// This file is the single aggregation source for the whole report set: the
// interactive report embeds its output as JSON (charts, CSV export, print
// view), and the split reports reuse the same helpers. Aggregation never
// mutates the scan result, so the JSON/txt outputs keep the raw evidence.

// severityRank orders severities from most to least severe. Unrecognized
// severities (team rules may carry anything) sort after info so they are
// still listed instead of silently dropped.
var severityRank = map[string]int{
	string(model.SeverityCritical): 5,
	string(model.SeverityHigh):     4,
	string(model.SeverityMedium):   3,
	string(model.SeverityLow):      2,
	string(model.SeverityInfo):     1,
}

// reportSeverities is the display order shared by every severity view.
var reportSeverities = []string{
	string(model.SeverityCritical),
	string(model.SeverityHigh),
	string(model.SeverityMedium),
	string(model.SeverityLow),
	string(model.SeverityInfo),
}

func rankOf(severity string) int { return severityRank[severity] }

// severityLabel renders the Chinese risk label used across the report UI.
func severityLabel(severity string) string {
	switch severity {
	case string(model.SeverityCritical):
		return "严重"
	case string(model.SeverityHigh):
		return "高"
	case string(model.SeverityMedium):
		return "中"
	case string(model.SeverityLow):
		return "低"
	case string(model.SeverityInfo):
		return "信息"
	}
	if severity == "" {
		return "未知"
	}
	return severity
}

// categoryLabel renders the rule category.
func categoryLabel(category string) string {
	switch category {
	case string(model.RuleCategorySensitive):
		return "敏感信息"
	case string(model.RuleCategoryURL):
		return "URL"
	}
	if category == "" {
		return "未分类"
	}
	return category
}

// ruleGroup extracts the HaE group name embedded in a generated rule id
// ("hae.<group>.<rule>" → "<group>"). Custom rules whose id does not follow
// that shape get no group, and the report falls back to the category.
func ruleGroup(ruleID string) string {
	parts := strings.Split(ruleID, ".")
	if len(parts) >= 3 && parts[0] == "hae" {
		return parts[1]
	}
	return ""
}

// verifyByGroup carries the manual-verification next step for each rule
// group. These are structural: the group comes from the rule id, never from
// guessing at the matched value.
var verifyByGroup = map[string]string{
	"密钥凭证": "确认凭据是否真实有效，并在授权范围内用只读调用验证权限范围；不要执行越权写操作。",
	"PII":  "确认是否为真实个人信息、是否混入测试数据；如为真实数据，按合规要求记录暴露范围并限制报告流转。",
	"网络信息": "判断该地址或凭据在当前网络是否可达、是否泄露内网拓扑；仅在授权范围内做连通性验证。",
	"指纹暴露": "核对对应组件与版本，比对已知漏洞与默认口令；先确认可达性，再评估影响。",
	"URL":  "作为攻击面线索纳入端点清单，无需单独核查；优先关注带参数或写操作的接口。",
}

// verifyHint returns the human-verification next step for one finding. The
// hint is advice for a tester, never a vulnerability conclusion: every
// aggregated finding stays "待人工验证" until a person confirms it.
func verifyHint(ruleID, category string) string {
	if hint, ok := verifyByGroup[ruleGroup(ruleID)]; ok {
		return hint
	}
	if category == string(model.RuleCategorySensitive) {
		return "人工确认该值是否真实、是否有效、是否可在当前环境被利用；规则命中不等于漏洞。"
	}
	if category == string(model.RuleCategoryURL) {
		return "作为攻击面线索纳入端点清单，结合业务语义判断是否需要进一步测试。"
	}
	return "人工确认命中是否成立，再决定后续测试动作。"
}

// groupSource is one raw hit inside an aggregated finding: the evidence the
// aggregation must never lose.
type groupSource struct {
	URL string `json:"url"`
	// Domain keeps its name for compatibility but holds the classified host of
	// the source file: a domain, an IP literal or an internal-host candidate.
	Domain   string              `json:"domain"`
	HostKind string              `json:"host_kind,omitempty"`
	Line     int                 `json:"line"`
	Column   int                 `json:"column"`
	Context  []model.ContextLine `json:"context,omitempty"`
	AI       *model.AIAssessment `json:"ai,omitempty"`
	Vendor   bool                `json:"vendor,omitempty"`
}

// findingGroup is one aggregated finding. The aggregation key is
// rule + category + severity + value, so different values, different rules
// and different severities never merge.
type findingGroup struct {
	ID            string              `json:"id"`
	RuleID        string              `json:"ruleId"`
	RuleName      string              `json:"ruleName"`
	Group         string              `json:"group,omitempty"`
	Category      string              `json:"category"`
	CategoryLabel string              `json:"categoryLabel"`
	Severity      string              `json:"severity"`
	SeverityLabel string              `json:"severityLabel"`
	Value         string              `json:"value"`
	Summary       string              `json:"summary"`
	Hits          int                 `json:"hits"`
	Domains       []string            `json:"domains"`
	Sources       []groupSource       `json:"sources"`
	AI            *model.AIAssessment `json:"ai,omitempty"`
	AICount       int                 `json:"aiCount"`
	Vendor        bool                `json:"vendor,omitempty"`
	Verify        string              `json:"verify"`
	// Confirmation is always 待人工验证: JsOwl records rule hits and optional
	// AI ratings, never a human conclusion.
	Confirmation string `json:"confirmation"`
}

// hostMetric is one host kind counted in both populations. The two columns are
// never added together by the report: they answer different questions.
type hostMetric struct {
	Kind  string `json:"kind"`
	Label string `json:"label"`
	// Content counts hosts found inside analyzed content.
	Content int `json:"content"`
	// Scan counts hosts the scan itself touched.
	Scan int `json:"scan"`
}

// hostSummary carries the host population counts and their counting rules.
type hostSummary struct {
	Metrics      []hostMetric `json:"metrics"`
	ContentTotal int          `json:"contentTotal"`
	ScanTotal    int          `json:"scanTotal"`
	// Correlated counts hosts that appear in both populations. It is reported
	// so the two can be related without merging them.
	Correlated int      `json:"correlated"`
	PSLVersion string   `json:"pslVersion,omitempty"`
	PSLCommit  string   `json:"pslCommit,omitempty"`
	PSLStatus  string   `json:"pslStatus"`
	Notes      []string `json:"notes"`
}

// hostKinds lists the host kinds in report order.
var hostKinds = []model.HostKind{
	model.HostKindDomain,
	model.HostKindIPv4,
	model.HostKindIPv6,
	model.HostKindInternal,
}

// buildHostSummary counts both host populations. The two are kept apart: hosts
// found in content say what the code mentions, hosts the scan touched say what
// was actually reached, and a host can legitimately appear in both.
func buildHostSummary(result *model.Result, hosts *hostIndex) hostSummary {
	// A result produced before host extraction existed (an older report.json,
	// or a Result assembled by a library caller) carries no classified scan
	// hosts. They are derived here with the same shared extractor, so the
	// statistics stay correct instead of silently reporting zero.
	summary := hostSummary{
		ContentTotal: len(result.Hosts),
		ScanTotal:    len(result.ScanHosts),
	}
	content := map[model.HostKind]int{}
	scanned := map[model.HostKind]int{}
	for _, asset := range result.Hosts {
		content[asset.Kind]++
	}
	for _, asset := range result.ScanHosts {
		scanned[asset.Kind]++
	}
	for _, kind := range hostKinds {
		summary.Metrics = append(summary.Metrics, hostMetric{
			Kind:    string(kind),
			Label:   hostKindLabel(string(kind)),
			Content: content[kind],
			Scan:    scanned[kind],
		})
	}
	seen := make(map[string]struct{}, len(result.ScanHosts))
	for _, asset := range result.ScanHosts {
		seen[asset.Value] = struct{}{}
	}
	for _, asset := range result.Hosts {
		if _, both := seen[asset.Value]; both {
			summary.Correlated++
		}
	}

	info := extract.PSLSnapshotInfo()
	summary.PSLVersion = info.Version
	summary.PSLCommit = info.Commit
	summary.PSLStatus = "ok"
	for _, asset := range append(append([]model.HostAsset{}, result.Hosts...), result.ScanHosts...) {
		if asset.SuffixStatus == model.SuffixUnresolved {
			summary.PSLStatus = "unresolved"
			break
		}
	}
	summary.Notes = []string{
		"内容发现：出现在 JavaScript、内联脚本、文档与源码映射中的主机值（字符串字面量、静态拼接、URL 与注释）。" +
			"它只说明代码里提到了该主机。",
		"扫描关联：本次扫描实际访问或被引用到的对象所属主机（目标、资源、端点、发现来源）。",
		"两类使用同一套归一化与分类规则；同一主机同时出现在两类时分别计数，重复数为 " +
			fmt.Sprintf("%d", summary.Correlated) + "。",
		"域名只在公共后缀列表识别出后缀时成立；IP 按 netip 标准化，内部主机候选不进入域名统计。",
		"发现主机不等于可访问资产：本次未做 DNS 查询、未做连通性探测，也不代表存在漏洞。",
	}
	if summary.PSLStatus == "unresolved" {
		summary.Notes = append(summary.Notes,
			"公共后缀列表未能初始化，部分主机的域名层级标记为未解析（候选本身仍然保留）。")
	}
	return summary
}

// ensureScanHosts returns the scan-associated host list, deriving it with the
// shared extractor when the result does not carry one — a report.json written
// before host extraction existed, or a Result assembled by a library caller.
// The derived list is stored back on the result so every section, the text
// files and the HTML agree on one classification.
func ensureScanHosts(result *model.Result) []model.HostAsset {
	if len(result.ScanHosts) > 0 {
		return result.ScanHosts
	}
	derived, _ := extract.CollectScanHosts(result, hostClassifier())
	if len(derived) > 0 {
		result.ScanHosts = derived
	}
	return result.ScanHosts
}

// hostCount returns the count of one kind from the host summary metrics.
func hostCount(summary hostSummary, kind model.HostKind) int {
	for _, metric := range summary.Metrics {
		if metric.Kind == string(kind) {
			return metric.Scan
		}
	}
	return 0
}

// metric is one headline number with its counting rule attached, so the
// report can always say what a number means.
type metric struct {
	Key      string `json:"key"`
	Label    string `json:"label"`
	Value    int    `json:"value"`
	Sub      int    `json:"sub"`
	SubLabel string `json:"subLabel,omitempty"`
	Note     string `json:"note"`
}

// severityMetric is one risk level with both counting units.
type severityMetric struct {
	Severity string `json:"severity"`
	Label    string `json:"label"`
	Groups   int    `json:"groups"`
	Hits     int    `json:"hits"`
	// Hosts counts the distinct hosts the findings of this level were found
	// on, of every kind (domain, IP, internal host).
	Hosts int `json:"hosts"`
}

type countBucket struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	Count int    `json:"count"`
	// Severity is set only for buckets that carry a risk level (rule types,
	// severity rows) so charts can color them consistently.
	Severity string `json:"severity,omitempty"`
}

type domainBucket struct {
	Host  string `json:"host"`
	Label string `json:"label"`
	// Kind is the classified host kind (domain / ipv4 / ipv6 / internal_host)
	// or "unresolved" when a reference carried no host at all. The ranking is
	// grouped by it, so an IP or an internal host is never presented as part
	// of the domain ranking.
	Kind      string `json:"kind"`
	Endpoints int    `json:"endpoints"`
	Routes    int    `json:"routes"`
	Findings  int    `json:"findings"`
	Resources int    `json:"resources"`
}

type priorityItem struct {
	Rank     int    `json:"rank"`
	Level    string `json:"level"`
	GroupID  string `json:"groupId"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Hits     int    `json:"hits"`
	Next     string `json:"next"`
	Status   string `json:"status"`
}

type resourceSummary struct {
	Total  int           `json:"total"`
	Types  []countBucket `json:"types"`
	Status []countBucket `json:"status"`
	Saved  int           `json:"saved"`
	Notes  []string      `json:"notes"`
}

type issueSummary struct {
	Total     int           `json:"total"`
	Codes     []countBucket `json:"codes"`
	Stages    []countBucket `json:"stages"`
	Retryable int           `json:"retryable"`
}

// reportSummary is embedded into the interactive report as JSON.
type reportSummary struct {
	Target      string `json:"target"`
	TargetHost  string `json:"targetHost"`
	Mode        string `json:"mode"`
	ModeLabel   string `json:"modeLabel"`
	GeneratedAt string `json:"generatedAt"`
	StartedAt   string `json:"startedAt,omitempty"`
	FinishedAt  string `json:"finishedAt,omitempty"`
	Duration    string `json:"duration,omitempty"`
	HasScanTime bool   `json:"hasScanTime"`
	BrowserUsed bool   `json:"browserUsed"`
	BrowserNote string `json:"browserNote,omitempty"`
	UserAgent   string `json:"userAgent"`

	AttackMetrics   []metric         `json:"attackMetrics"`
	AttackNote      string           `json:"attackNote"`
	SeverityMetrics []severityMetric `json:"severityMetrics"`
	FindingTotal    metric           `json:"findingTotal"`
	Types           []countBucket    `json:"types"`
	Domains         []domainBucket   `json:"domains"`
	Methods         []countBucket    `json:"methods"`
	Resources       resourceSummary  `json:"resources"`
	Issues          issueSummary     `json:"issues"`
	Groups          []findingGroup   `json:"groups"`
	Key             []findingGroup   `json:"key"`
	Priority        []priorityItem   `json:"priority"`
	Hosts           hostSummary      `json:"hosts"`
	Params          []string         `json:"params"`
	GroupHits       int              `json:"groupHits"`
	HasAIAssessment bool             `json:"hasAiAssessment"`
	AICount         int              `json:"aiCount"`
}

// maxKeyFindings caps the overview list; the full set stays in the groups
// table and in the print appendix.
const maxKeyFindings = 8

// summaryNote is the shared counting rule for the mixed-unit metrics.
const (
	hitDefinition      = "原始命中：规则在源码中每一次匹配都单独计数。"
	groupDefinition    = "聚合发现：按 规则 + 分类 + 等级 + 完整值 合并后的条数。"
	uniqueEndpointNote = "唯一端点：按解析后的完整 URL 去重；括号内为去重前的记录行数。"
)

func buildSummary(result *model.Result, now time.Time) reportSummary {
	summary := reportSummary{
		Target:      result.Target,
		TargetHost:  hostOf(result.Target),
		Mode:        string(result.Mode),
		ModeLabel:   modeLabel(result.Mode),
		GeneratedAt: now.Format("2006-01-02 15:04:05"),
		UserAgent:   result.UserAgent,
		BrowserUsed: result.BrowserStatus.Used,
	}
	if !result.StartedAt.IsZero() {
		summary.HasScanTime = true
		summary.StartedAt = result.StartedAt.Format("2006-01-02 15:04:05")
	}
	if !result.FinishedAt.IsZero() {
		summary.HasScanTime = true
		summary.FinishedAt = result.FinishedAt.Format("2006-01-02 15:04:05")
		if !result.StartedAt.IsZero() && result.FinishedAt.After(result.StartedAt) {
			summary.Duration = result.FinishedAt.Sub(result.StartedAt).Round(time.Second).String()
		}
	}
	if result.BrowserStatus.Degraded {
		summary.BrowserNote = "浏览器阶段降级：" + result.BrowserStatus.Reason
	} else if result.BrowserStatus.Attempted && !result.BrowserStatus.Used {
		summary.BrowserNote = "浏览器阶段未启用，运行时请求未采集。"
	}

	// One index answers every host question in this report, fed by the
	// classification the scan already computed. Scan-associated hosts are
	// derived first when the result carries none, so the index and every
	// section below see the same population.
	ensureScanHosts(result)
	hosts := newHostIndex(append(
		append([]model.HostAsset{}, result.ScanHosts...), result.Hosts...,
	))
	summary.Hosts = buildHostSummary(result, hosts)

	groups := aggregateFindings(result.Findings, hosts)
	summary.Groups = groups
	summary.GroupHits = len(result.Findings)
	for _, group := range groups {
		if group.AI != nil {
			summary.HasAIAssessment = true
			summary.AICount += group.AICount
		}
	}

	endpoints, routes, domainNames := partitionEndpoints(result.Endpoints, hosts)
	summary.Domains = domainBuckets(endpoints, routes, result.Resources, groups, hosts)
	summary.Methods = methodBuckets(endpoints)
	summary.Types = typeBuckets(groups)
	summary.SeverityMetrics = severityMetrics(groups, result.Findings)
	summary.FindingTotal = metric{
		Key: "findings", Label: "发现总数", Value: len(groups), Sub: len(result.Findings),
		SubLabel: "原始命中", Note: groupDefinition + hitDefinition,
	}
	summary.AttackMetrics, summary.AttackNote = attackMetrics(
		result, endpoints, routes, domainNames, summary.Hosts,
	)
	summary.Resources = resourceSummaryOf(result.Resources)
	summary.Issues = issueSummaryOf(result.Issues)
	summary.Key = keyFindings(groups)
	summary.Priority = priorityList(groups)
	summary.Params = collectParameterNames(result)
	return summary
}

func modeLabel(mode model.Mode) string {
	switch mode {
	case model.ModeAuto:
		return "自动（CDP 优先，失败降级直连）"
	case model.ModeDirect:
		return "仅直连（不启动浏览器）"
	case model.ModeBrowser:
		return "仅浏览器（CDP）"
	}
	if mode == "" {
		return "未记录"
	}
	return string(mode)
}

// isRoute reports whether an endpoint is a front-end framework route rather
// than a backend API.
func isRoute(endpoint model.Endpoint) bool { return endpoint.Type == "route" }

// endpointKey is the resolved URL, falling back to the source reference when
// resolution produced nothing.
func endpointKey(endpoint model.Endpoint) string {
	if endpoint.URL != "" {
		return endpoint.URL
	}
	return endpoint.Raw
}

// unresolvedHost labels endpoints whose reference resolves to no host, and
// unresolvedMethod labels endpoints the source never gave a verb for. Neither
// is ever guessed: an unresolved path is not attributed to the target domain,
// and a missing method is not assumed to be GET.
const (
	unresolvedHost   = "（未解析主机）"
	unresolvedMethod = "未知"
)

// hostIndex answers "what kind of host is this value" from the classification
// the scan already computed. The report never re-implements host rules: it
// looks the canonical value up in the scan's own host list, and only a host
// the scan never touched (a source file it read but did not request) is
// classified on the spot, with the same shared extractor.
type hostIndex struct {
	kinds    map[string]string
	fallback *extract.Extractor
}

func newHostIndex(assets []model.HostAsset) *hostIndex {
	index := &hostIndex{kinds: make(map[string]string, len(assets))}
	for _, asset := range assets {
		index.kinds[asset.Value] = string(asset.Kind)
	}
	return index
}

// kind returns the host kind for a canonical value, or "" when the value is
// not a host the report can classify.
func (h *hostIndex) kind(value string) string {
	if h == nil || value == "" {
		return ""
	}
	if kind, ok := h.kinds[value]; ok {
		return kind
	}
	if h.fallback == nil {
		h.fallback = hostClassifier()
	}
	asset, ok := h.fallback.ClassifyHost(value, extract.Candidate{
		Method: model.HostMethodURL,
	})
	if !ok {
		h.kinds[value] = ""
		return ""
	}
	h.kinds[value] = string(asset.Kind)
	return string(asset.Kind)
}

// isDomain reports whether a canonical value is a public domain. Only these
// are counted as domains: an IP, an internal-host candidate or a bare "f" is
// not.
func (h *hostIndex) isDomain(value string) bool {
	return h.kind(value) == string(model.HostKindDomain)
}

var (
	hostClassifierOnce sync.Once
	hostClassifierPool *extract.Extractor
)

// hostClassifier is the extractor used for hosts the scan did not touch. It
// shares the process-wide Public Suffix List resolver.
func hostClassifier() *extract.Extractor {
	hostClassifierOnce.Do(func() {
		hostClassifierPool = extract.NewExtractor(model.HostsConfig{})
	})
	return hostClassifierPool
}

// hostOf resolves one reference to its canonical host value, accepting only
// network URLs and references that actually carry an authority. A relative
// path has no host and yields "", which is what keeps "f", an IP and a
// relative path out of the domain statistics.
func hostOf(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	host, ok := extract.HostFromNetworkURL(raw)
	if !ok {
		if strings.Contains(raw, "://") {
			// A non-network scheme (data:, blob:, mailto:) carries no host.
			return ""
		}
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Host == "" {
			return ""
		}
		host = parsed.Hostname()
	}
	normalized, ok := extract.NormalizeHost(host)
	if !ok {
		return ""
	}
	return normalized
}

// sourceHost resolves the host of a finding's source file, falling back to the
// unresolved sentinel so a relative source reference is never mistaken for a
// domain.
func sourceHost(raw string) string {
	if host := hostOf(raw); host != "" {
		return host
	}
	return unresolvedHost
}

// partitionEndpoints splits endpoints into API rows, route rows, and the
// deduplicated host list. The unresolved sentinel is not counted as a domain.
func partitionEndpoints(
	endpoints []model.Endpoint,
	index *hostIndex,
) (api, routes []model.Endpoint, domains []string) {
	seenHost := map[string]bool{}
	for _, endpoint := range endpoints {
		if isRoute(endpoint) {
			routes = append(routes, endpoint)
		} else {
			api = append(api, endpoint)
		}
		host := endpointHost(endpoint)
		if host == unresolvedHost {
			continue
		}
		// Only classified domains count here; an endpoint on an IP or an
		// internal host is reported in its own bucket and metric instead.
		if index.isDomain(host) {
			seenHost[host] = true
		}
	}
	domains = make([]string, 0, len(seenHost))
	for host := range seenHost {
		domains = append(domains, host)
	}
	sort.Strings(domains)
	return api, routes, domains
}

// endpointHost resolves the host an endpoint belongs to, sentinel included, so
// every endpoint lands in exactly one bucket. A relative reference resolves to
// the sentinel instead of being attributed to the target domain.
func endpointHost(endpoint model.Endpoint) string {
	if host := hostOf(endpointKey(endpoint)); host != "" {
		return host
	}
	return unresolvedHost
}

// domainBuckets ranks hosts by API endpoint count. Endpoints whose reference
// resolves to no host are grouped under a sentinel rather than being
// attributed to the target domain, which would invent a relationship.
func domainBuckets(
	endpoints, routes []model.Endpoint,
	resources []model.Resource,
	groups []findingGroup,
	hosts *hostIndex,
) []domainBucket {
	index := map[string]*domainBucket{}
	bucketOf := func(host string) *domainBucket {
		bucket, exists := index[host]
		if !exists {
			label := host
			kind := hosts.kind(host)
			switch {
			case host == unresolvedHost:
				label = unresolvedHost + "（无法解析为完整 URL）"
				kind = "unresolved"
			case kind == "":
				kind = "unresolved"
			case kind != string(model.HostKindDomain):
				label = host + "（" + hostKindLabel(kind) + "）"
			}
			bucket = &domainBucket{Host: host, Label: label, Kind: kind}
			index[host] = bucket
		}
		return bucket
	}
	for _, endpoint := range endpoints {
		bucketOf(endpointHost(endpoint)).Endpoints++
	}
	for _, route := range routes {
		bucketOf(endpointHost(route)).Routes++
	}
	for _, resource := range resources {
		if parsed, err := url.Parse(resource.URL); err == nil && parsed.Host != "" {
			bucketOf(parsed.Host).Resources++
		}
	}
	for _, group := range groups {
		for _, domain := range group.Domains {
			bucketOf(domain).Findings += group.Hits
		}
	}
	buckets := make([]domainBucket, 0, len(index))
	for _, bucket := range index {
		buckets = append(buckets, *bucket)
	}
	// Domains rank first (the ranking readers expect), then the other host
	// kinds in a fixed order, so a host kind can never appear as a domain
	// entry by accident.
	rank := map[string]int{
		string(model.HostKindDomain):   0,
		string(model.HostKindInternal): 1,
		string(model.HostKindIPv4):     2,
		string(model.HostKindIPv6):     3,
		"unresolved":                   4,
	}
	sort.SliceStable(buckets, func(i, j int) bool {
		if rank[buckets[i].Kind] != rank[buckets[j].Kind] {
			return rank[buckets[i].Kind] < rank[buckets[j].Kind]
		}
		if buckets[i].Endpoints != buckets[j].Endpoints {
			return buckets[i].Endpoints > buckets[j].Endpoints
		}
		if buckets[i].Findings != buckets[j].Findings {
			return buckets[i].Findings > buckets[j].Findings
		}
		return buckets[i].Host < buckets[j].Host
	})
	return buckets
}

// hostKindLabel renders a host kind for a bucket label.
func hostKindLabel(kind string) string {
	switch model.HostKind(kind) {
	case model.HostKindDomain:
		return "域名"
	case model.HostKindIPv4:
		return "IPv4"
	case model.HostKindIPv6:
		return "IPv6"
	case model.HostKindInternal:
		return "内部主机"
	}
	return "未分类主机"
}

// uniqueCount deduplicates endpoint rows by their resolved URL.
func uniqueCount(endpoints []model.Endpoint) int {
	seen := map[string]bool{}
	for _, endpoint := range endpoints {
		seen[endpointKey(endpoint)] = true
	}
	return len(seen)
}

func attackMetrics(
	result *model.Result,
	endpoints, routes []model.Endpoint,
	domainNames []string,
	hosts hostSummary,
) ([]metric, string) {
	scripts, chunks := 0, 0
	for _, resource := range result.Resources {
		switch resource.Type {
		case model.ResourceTypeScript:
			scripts++
		case model.ResourceTypeChunk:
			chunks++
		}
	}
	params := collectParameterNames(result)
	// The domain number is the classified one: only hosts whose suffix the
	// Public Suffix List recognized count as domains. An IP, an internal-host
	// candidate or a bare value such as "f" is reported on its own metric.
	metrics := []metric{
		{
			Key: "domains", Label: "域名", Value: hostCount(hosts, model.HostKindDomain),
			Sub: len(domainNames), SubLabel: "其中端点主机",
			Note: "本次扫描关联的域名数：目标、资源、端点与发现来源的主机名去重后，" +
				"按公共后缀判定为域名的部分。IP 与内部主机候选单独计数，无主机的相对路径不计入。",
		},
		{
			Key: "endpoints", Label: "API 端点", Value: uniqueCount(endpoints), Sub: len(endpoints),
			SubLabel: "记录行", Note: uniqueEndpointNote + "路由不计入本项。",
		},
		{
			Key: "scripts", Label: "脚本", Value: scripts + chunks, Sub: chunks,
			SubLabel: "其中 chunk", Note: "资源清单中 script 与 chunk 类型之和。",
		},
		{
			Key: "routes", Label: "路由", Value: uniqueCount(routes), Sub: len(routes),
			SubLabel: "记录行", Note: "endpoint.type = route 的前端路由，已按路径去重。",
		},
		{
			Key: "params", Label: "参数", Value: len(params),
			Note: "URL query、请求体、响应字段与 AST 提取结果去重后的参数名数量。",
		},
	}
	note := "攻击面按“出现过什么”统计，不代表已测试过的范围。"
	if len(endpoints) == 0 && len(routes) == 0 {
		note = "本次未采集到任何端点或路由，" + note
	}
	return metrics, note
}

// aggregateFindings merges raw hits into aggregated findings. Ordering (and
// therefore the G-numbers) is deterministic: severity, then hit count, then
// rule name, then value.
func aggregateFindings(findings []model.Finding, hosts *hostIndex) []findingGroup {
	type accumulator struct {
		group findingGroup
		seen  map[string]bool
	}
	byKey := map[string]*accumulator{}
	order := make([]string, 0, len(findings))
	for _, finding := range findings {
		key := strings.Join([]string{
			finding.RuleID, string(finding.Category), string(finding.Severity), finding.Value,
		}, "\x00")
		acc, exists := byKey[key]
		if !exists {
			acc = &accumulator{
				seen: map[string]bool{},
				group: findingGroup{
					RuleID:        finding.RuleID,
					RuleName:      finding.RuleName,
					Group:         ruleGroup(finding.RuleID),
					Category:      string(finding.Category),
					CategoryLabel: categoryLabel(string(finding.Category)),
					Severity:      string(finding.Severity),
					SeverityLabel: severityLabel(string(finding.Severity)),
					Value:         finding.Value,
					Summary:       summarizeValue(finding.Value),
					Verify:        verifyHint(finding.RuleID, string(finding.Category)),
					Confirmation:  "待人工验证",
				},
			}
			byKey[key] = acc
			order = append(order, key)
		}
		acc.group.Hits++
		if finding.Vendor {
			acc.group.Vendor = true
		}
		if finding.AI != nil {
			acc.group.AICount++
			// Keep the first non-empty assessment so aggregation never drops
			// the AI verdict; per-source ratings stay on the source entries.
			if acc.group.AI == nil {
				acc.group.AI = finding.AI
			}
		}
		// Every raw hit keeps its own evidence entry even when the location
		// repeats, so the hit count and the source list always agree.
		// The field keeps the name Domain for compatibility, but it now holds
		// the classified host of the source file: an IP or an internal host is
		// reported as such instead of being folded into the domain counts.
		domain := sourceHost(finding.SourceURL)
		source := groupSource{
			URL:      finding.SourceURL,
			Domain:   domain,
			HostKind: hosts.kind(domain),
			Line:     finding.Line,
			Column:   finding.Column,
			Context:  finding.ContextLines,
			AI:       finding.AI,
			Vendor:   finding.Vendor,
		}
		acc.group.Sources = append(acc.group.Sources, source)
	}

	groups := make([]findingGroup, 0, len(order))
	for _, key := range order {
		group := byKey[key].group
		sort.SliceStable(group.Sources, func(i, j int) bool {
			left, right := group.Sources[i], group.Sources[j]
			if left.URL != right.URL {
				return left.URL < right.URL
			}
			if left.Line != right.Line {
				return left.Line < right.Line
			}
			return left.Column < right.Column
		})
		seenDomain := map[string]bool{}
		for _, source := range group.Sources {
			if source.Domain == "" || seenDomain[source.Domain] {
				continue
			}
			seenDomain[source.Domain] = true
			group.Domains = append(group.Domains, source.Domain)
		}
		if group.Domains == nil {
			group.Domains = []string{}
		}
		groups = append(groups, group)
	}

	sort.SliceStable(groups, func(i, j int) bool {
		left, right := groups[i], groups[j]
		if rankOf(left.Severity) != rankOf(right.Severity) {
			return rankOf(left.Severity) > rankOf(right.Severity)
		}
		if left.Hits != right.Hits {
			return left.Hits > right.Hits
		}
		if left.RuleName != right.RuleName {
			return left.RuleName < right.RuleName
		}
		return left.Value < right.Value
	})
	for index := range groups {
		groups[index].ID = fmt.Sprintf("G%03d", index+1)
	}
	return groups
}

// summarizeValue condenses a matched value for list display. The full value
// stays available on the group and is what the detail panel and CSV export.
func summarizeValue(value string) string {
	const limit = 80
	runes := []rune(strings.ReplaceAll(value, "\n", " "))
	if len(runes) <= limit {
		return string(runes)
	}
	return string(runes[:limit]) + "…"
}

func severityMetrics(groups []findingGroup, findings []model.Finding) []severityMetric {
	groupCount := map[string]int{}
	groupHosts := map[string]map[string]bool{}
	for _, group := range groups {
		groupCount[group.Severity]++
		set := groupHosts[group.Severity]
		if set == nil {
			set = map[string]bool{}
			groupHosts[group.Severity] = set
		}
		for _, host := range group.Domains {
			set[host] = true
		}
	}
	hitCount := map[string]int{}
	for _, finding := range findings {
		hitCount[string(finding.Severity)]++
	}
	metrics := make([]severityMetric, 0, len(reportSeverities)+1)
	appendRow := func(severity string) {
		metrics = append(metrics, severityMetric{
			Severity: severity,
			Label:    severityLabel(severity),
			Groups:   groupCount[severity],
			Hits:     hitCount[severity],
			Hosts:    len(groupHosts[severity]),
		})
	}
	for _, severity := range reportSeverities {
		appendRow(severity)
	}
	// Unknown severities get one honest row instead of being folded into info.
	unknownGroups, unknownHits := 0, 0
	for severity, count := range groupCount {
		if _, known := severityRank[severity]; !known {
			unknownGroups += count
		}
	}
	for severity, count := range hitCount {
		if _, known := severityRank[severity]; !known {
			unknownHits += count
		}
	}
	if unknownGroups > 0 || unknownHits > 0 {
		metrics = append(metrics, severityMetric{
			Severity: "unknown", Label: severityLabel(""), Groups: unknownGroups, Hits: unknownHits,
		})
	}
	return metrics
}

// typeBuckets ranks rule types by hit volume; the type is the rule itself, so
// the chart never guesses a category from the matched value.
func typeBuckets(groups []findingGroup) []countBucket {
	counts := map[string]*countBucket{}
	for _, group := range groups {
		bucket := counts[group.RuleName]
		if bucket == nil {
			bucket = &countBucket{
				Key: group.RuleName, Label: group.RuleName, Severity: group.Severity,
			}
			counts[group.RuleName] = bucket
		}
		bucket.Count += group.Hits
		// The bucket keeps the most severe level it contains.
		if rankOf(group.Severity) > rankOf(bucket.Severity) {
			bucket.Severity = group.Severity
		}
	}
	buckets := make([]countBucket, 0, len(counts))
	for _, bucket := range counts {
		buckets = append(buckets, *bucket)
	}
	sort.SliceStable(buckets, func(i, j int) bool {
		if buckets[i].Count != buckets[j].Count {
			return buckets[i].Count > buckets[j].Count
		}
		return buckets[i].Key < buckets[j].Key
	})
	return buckets
}

// methodBuckets counts API endpoints per HTTP verb. An endpoint without a
// recorded method is reported as 未知 — never assumed to be GET.
func methodBuckets(endpoints []model.Endpoint) []countBucket {
	counts := map[string]int{}
	for _, endpoint := range endpoints {
		method := strings.ToUpper(strings.TrimSpace(endpoint.Method))
		if method == "" {
			method = unresolvedMethod
		}
		counts[method]++
	}
	buckets := make([]countBucket, 0, len(counts))
	for method, count := range counts {
		buckets = append(buckets, countBucket{Key: method, Label: method, Count: count})
	}
	sort.SliceStable(buckets, func(i, j int) bool {
		if buckets[i].Count != buckets[j].Count {
			return buckets[i].Count > buckets[j].Count
		}
		return buckets[i].Key < buckets[j].Key
	})
	return buckets
}

func resourceSummaryOf(resources []model.Resource) resourceSummary {
	summary := resourceSummary{Total: len(resources)}
	typeCounts := map[string]int{}
	statusCounts := map[string]int{}
	for _, resource := range resources {
		typeCounts[string(resource.Type)]++
		status := "无响应"
		if resource.StatusCode > 0 {
			status = fmt.Sprintf("%d", resource.StatusCode)
		}
		statusCounts[status]++
		if resource.LocalPath != "" {
			summary.Saved++
		}
	}
	summary.Types = sortedBuckets(typeCounts, nil)
	summary.Status = sortedBuckets(statusCounts, nil)
	summary.Notes = []string{
		"资源总数、类型与状态码均来自本次采集的资源清单。",
		"未计算“解析成功率”：结果中没有记录每个源文件对应的解析结论，缺少可靠分母时不做推算。",
	}
	if summary.Saved > 0 {
		summary.Notes = append(summary.Notes, fmt.Sprintf("其中 %d 个资源已保存到本地（存在本地路径）。", summary.Saved))
	}
	return summary
}

func issueSummaryOf(issues []model.Issue) issueSummary {
	summary := issueSummary{Total: len(issues)}
	codeCounts := map[string]int{}
	stageCounts := map[string]int{}
	for _, issue := range issues {
		code := issue.Code
		if code == "" {
			code = "未分类"
		}
		codeCounts[code]++
		stage := issue.Stage
		if stage == "" {
			stage = "未分类"
		}
		stageCounts[stage]++
		if issue.Retryable {
			summary.Retryable++
		}
	}
	summary.Codes = sortedBuckets(codeCounts, issueCodeLabels)
	summary.Stages = sortedBuckets(stageCounts, nil)
	return summary
}

// issueCodeLabels spells out the diagnostic codes the pipeline emits.
var issueCodeLabels = map[string]string{
	"resource_get_failed": "资源获取失败",
	"body_truncated":      "正文被截断",
	"js_not_saved":        "脚本未落盘",
	"js_save_failed":      "脚本落盘失败",
	"js_analysis_failed":  "脚本分析失败",
	// Host extraction diagnostics. They report a degraded extraction, never a
	// scan finding.
	extract.NotePSLUnavailable:   "公共后缀列表不可用",
	extract.NoteCandidatesCapped: "主机提取被截断",
	extract.NoteEvidenceCapped:   "主机证据被截断",
	extract.NoteAssetsCapped:     "主机数量超限",
	extract.NoteRegexCapped:      "正则候选被截断",
	extract.NoteDynamicHost:      "动态主机表达式",
	extract.NoteParseFallback:    "解析失败回退文本扫描",
}

func sortedBuckets(counts map[string]int, labels map[string]string) []countBucket {
	buckets := make([]countBucket, 0, len(counts))
	for key, count := range counts {
		label := key
		if labels != nil {
			if mapped, ok := labels[key]; ok {
				label = mapped
			}
		}
		buckets = append(buckets, countBucket{Key: key, Label: label, Count: count})
	}
	sort.SliceStable(buckets, func(i, j int) bool {
		if buckets[i].Count != buckets[j].Count {
			return buckets[i].Count > buckets[j].Count
		}
		return buckets[i].Key < buckets[j].Key
	})
	return buckets
}

// keyFindings returns the overview list: the most severe aggregated findings,
// capped. An empty list is returned as-is so the report can say plainly that
// nothing high was found.
func keyFindings(groups []findingGroup) []findingGroup {
	if len(groups) <= maxKeyFindings {
		return append([]findingGroup{}, groups...)
	}
	return append([]findingGroup{}, groups[:maxKeyFindings]...)
}

// priorityLevel maps a severity to a review priority. Priority ranks what to
// look at first; it is not a confirmation that anything is exploitable.
func priorityLevel(severity string) string {
	switch severity {
	case string(model.SeverityCritical), string(model.SeverityHigh):
		return "P1"
	case string(model.SeverityMedium):
		return "P2"
	}
	return "P3"
}

func priorityList(groups []findingGroup) []priorityItem {
	items := make([]priorityItem, 0, len(groups))
	for index, group := range groups {
		items = append(items, priorityItem{
			Rank:     index + 1,
			Level:    priorityLevel(group.Severity),
			GroupID:  group.ID,
			Title:    group.RuleName,
			Severity: group.Severity,
			Hits:     group.Hits,
			Next:     group.Verify,
			Status:   group.Confirmation,
		})
	}
	return items
}

// collectParameterNames returns every distinct parameter name the scan
// recovered, sorted. Both 参数.txt and the report summary use it, so the two
// never disagree.
func collectParameterNames(result *model.Result) []string {
	params := map[string]struct{}{}
	collect := func(raw string) {
		if raw == "" {
			return
		}
		parsed, err := url.Parse(raw)
		if err != nil {
			return
		}
		for key := range parsed.Query() {
			params[key] = struct{}{}
		}
	}
	for _, endpoint := range result.Endpoints {
		collect(endpoint.URL)
		for _, name := range endpoint.BodyParams {
			params[name] = struct{}{}
		}
		for _, name := range endpoint.ResponseParams {
			params[name] = struct{}{}
		}
	}
	for _, resource := range result.Resources {
		collect(resource.URL)
	}
	// Code-shape hits (object properties, destructuring, function params, ...)
	// join the list so the plain-text file feeds tools the full inventory.
	for _, hit := range result.Params {
		if hit.Name != "" {
			params[hit.Name] = struct{}{}
		}
	}
	names := make([]string, 0, len(params))
	for name := range params {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
