package extract

import (
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/idna"

	"github.com/youmulijiang/jsowl/internal/model"
)

// Extraction budgets and caps. They exist so a minified bundle full of URLs,
// or a page repeating one host ten thousand times, cannot grow the report
// without bound. Every cap that fires is reported as a diagnostic — nothing is
// dropped silently.
const (
	// MaxCandidateLen rejects absurdly long values before any parsing.
	MaxCandidateLen = 2048
	// MaxCandidatesPerFile caps how many candidates one analyzed file yields.
	MaxCandidatesPerFile = 1024
	// MaxEvidencePerAsset caps the evidence kept for one host; the occurrence
	// count still reflects everything seen.
	MaxEvidencePerAsset = 32
	// MaxAssetsPerTarget caps distinct hosts per target.
	MaxAssetsPerTarget = 8192
	// MaxRegexMatchesPerFile caps the regex fallback pass.
	MaxRegexMatchesPerFile = 512
	// MaxExtractionDuration bounds the wall-clock time one file's host
	// extraction may take. It is a safety valve for pathological inputs; the
	// node budget below is the deterministic bound that keeps reports
	// reproducible.
	MaxExtractionDuration = 300 * time.Millisecond
	// MaxExtractionNodes bounds how many AST nodes one file may visit.
	MaxExtractionNodes = 400_000
)

// Candidate contexts: where a value appeared. The context decides whether a
// single-label value may become an internal_host asset, which is what keeps a
// bare "f" out of the report while keeping the host of https://f/.
const (
	// ContextURL: parsed out of the authority of a network URL.
	ContextURL = "url"
	// ContextHostField: the value of a host-named field or config key
	// (host, hostname, baseURL, endpoint, ...).
	ContextHostField = "host_field"
	// ContextLiteral: any other string literal.
	ContextLiteral = "literal"
	// ContextRegex: found by the regex fallback pass.
	ContextRegex = "regex"
	// ContextEmail: the domain part of an email address.
	ContextEmail = "email"
)

// Candidate is one raw host-like value found in a source, before validation.
type Candidate struct {
	// Raw is the value exactly as it appeared (decoded string literal text,
	// URL, field value). It is preserved in the evidence as-is.
	Raw string
	// Context is one of the Context* values.
	Context string
	// Method is one of the model.HostMethod* values.
	Method string
	// Note explains the evidence when the method alone does not: "comment",
	// "dynamic_host", the scan role, ...
	Note string
	// AssociatedURL keeps the full URL the value was read from, when any.
	AssociatedURL string
	SourceURL     string
	// Line and Column are 1-based positions in SourceURL.
	Line   int
	Column int
	// ContextLines carries the surrounding source lines of the match.
	ContextLines []model.ContextLine
	// Vendor marks a candidate read from a third-party library bundle.
	Vendor bool
}

// Note is a diagnostic raised during extraction. Notes never carry scan
// findings; they record that the extraction degraded in a specific way.
type Note struct {
	Code    string
	Message string
	URL     string
}

// Diagnostic codes.
const (
	NotePSLUnavailable   = "host_psl_unavailable"
	NoteCandidatesCapped = "host_candidates_truncated"
	NoteEvidenceCapped   = "host_evidence_truncated"
	NoteAssetsCapped     = "host_assets_truncated"
	NoteRegexCapped      = "host_regex_truncated"
	NoteDynamicHost      = "host_dynamic_expression"
	NoteParseFallback    = "host_parse_fallback"
)

// Extractor classifies candidates into host assets with one shared suffix
// resolver. It is created once per scan, before concurrent work starts, and is
// read-only afterwards, so it can be shared by every analysis goroutine.
type Extractor struct {
	resolver      *Resolver
	resolverErr   error
	customSuffix  map[string]struct{}
	specialSuffix map[string]struct{}
}

// specialUseSuffixes are the reserved names RFC 6761 keeps out of the public
// DNS. A host under one of them is reported as an internal-host candidate; it
// is never counted as a public domain.
var specialUseSuffixes = map[string]struct{}{
	"test": {}, "local": {}, "localhost": {}, "invalid": {}, "example": {},
}

// NewExtractor builds an extractor from configuration. A Public Suffix List
// that cannot be initialized is not fatal: classification keeps working and
// domain hierarchies are reported as unresolved.
func NewExtractor(config model.HostsConfig) *Extractor {
	resolver, err := DefaultResolver()
	extractor := &Extractor{
		resolver:      resolver,
		resolverErr:   err,
		customSuffix:  map[string]struct{}{},
		specialSuffix: map[string]struct{}{},
	}
	for suffix := range specialUseSuffixes {
		extractor.specialSuffix[suffix] = struct{}{}
	}
	for _, raw := range config.InternalSuffixes {
		suffix := strings.Trim(strings.ToLower(strings.TrimSpace(raw)), ".")
		if suffix != "" {
			extractor.customSuffix[suffix] = struct{}{}
		}
	}
	return extractor
}

// PSLVersion returns the Public Suffix List version and commit, and the error
// that prevented initialization when there was one.
func (e *Extractor) PSLVersion() (version, commit string, err error) {
	if e == nil {
		return "", "", ErrPSLUnavailable
	}
	version, commit = e.resolver.Version()
	return version, commit, e.resolverErr
}

// Classify turns one candidate into a host asset. The boolean is false when
// the value is not a host at all (a relative path, a member expression, a
// filename, a bare single label outside a host context, ...), which is the
// normal outcome for most strings in a bundle.
func (e *Extractor) Classify(candidate Candidate) (model.HostAsset, bool) {
	if e == nil {
		return model.HostAsset{}, false
	}
	raw := strings.TrimSpace(candidate.Raw)
	if raw == "" || len(raw) > MaxCandidateLen {
		return model.HostAsset{}, false
	}
	candidate.Raw = raw

	if host, ok := HostFromNetworkURL(raw); ok {
		// The host was read out of a URL authority, which is its own evidence
		// method no matter what kind of expression the URL came from.
		candidate.Method = model.HostMethodURL
		return e.assetFromHost(host, candidate, true)
	}
	if candidate.Context == ContextEmail {
		// The caller may hand over the domain part of an address or the whole
		// address; both describe the same host.
		domain := raw
		if _, rest, found := strings.Cut(raw, "@"); found {
			domain = rest
		}
		if domain == "" {
			return model.HostAsset{}, false
		}
		return e.assetFromHost(domain, candidate, true)
	}
	// A bare value is only trusted as a host when the context says it is one
	// (a host-named field); everywhere else the format check has to carry it,
	// which is what rejects "main.js" and "window.location".
	explicit := candidate.Context == ContextHostField
	return e.assetFromHost(raw, candidate, explicit)
}

// ClassifyHost classifies a plain host name that came from an already parsed
// URL (a scanned resource, an endpoint, a finding source). It is the entry
// point the report and pipeline use for scan-associated hosts, so those hosts
// are classified by exactly the same rules as content-discovered ones.
func (e *Extractor) ClassifyHost(host string, candidate Candidate) (model.HostAsset, bool) {
	if e == nil {
		return model.HostAsset{}, false
	}
	candidate.Raw = strings.TrimSpace(host)
	if candidate.Method == "" {
		// The host came from an already parsed URL authority.
		candidate.Method = model.HostMethodURL
	}
	return e.assetFromHost(candidate.Raw, candidate, true)
}

// assetFromHost classifies one host value. explicit is true when the caller
// knows the value is a host (URL authority, host-named field, scan URL).
func (e *Extractor) assetFromHost(host string, candidate Candidate, explicit bool) (model.HostAsset, bool) {
	host = strings.TrimSpace(host)
	if host == "" || len(host) > MaxCandidateLen {
		return model.HostAsset{}, false
	}
	// A bare value may still carry a port ("api.example.com:8443"); the port
	// is not part of host identity and never reaches the dedup key.
	host = SplitHostPort(host)
	if asset, ok := ipAsset(host, candidate); ok {
		return asset, true
	}
	ascii, ok := normalizeHostASCII(host)
	if !ok {
		return model.HostAsset{}, false
	}
	labels := strings.Split(ascii, ".")
	if len(labels) == 1 {
		switch {
		case labels[0] == "localhost":
			return internalAsset(ascii, candidate, model.SuffixCustom, "reserved"), true
		case explicit:
			return internalAsset(ascii, candidate, model.SuffixUnknown, ""), true
		default:
			// A bare single label such as "f" is not a host. Keeping it would
			// put minifier identifiers and i18n keys into the host report.
			return model.HostAsset{}, false
		}
	}
	if suffix, matched := e.matchLocalSuffix(ascii); matched {
		status := model.SuffixCustom
		note := ""
		if _, special := e.specialSuffix[suffix]; special {
			note = "reserved"
		}
		return internalAsset(ascii, candidate, status, note), true
	}

	split, ok := e.resolver.Split(ascii)
	switch {
	case ok:
		asset := model.HostAsset{
			Kind:              model.HostKindDomain,
			Value:             ascii,
			RegistrableDomain: split.Registrable,
			PublicSuffix:      split.Suffix,
			Subdomain:         split.Subdomain,
			SuffixStatus:      model.SuffixRecognized,
		}
		return withEvidence(asset, candidate), true
	case split.SuffixOnly:
		// The value is a public suffix itself (co.uk): by definition not a
		// registrable domain, so it is reported as an internal-host candidate
		// with an explicit note rather than as a domain.
		return internalAsset(ascii, candidate, model.SuffixUnknown, "public_suffix_only"), true
	case e.resolverErr != nil || e.resolver == nil:
		// The Public Suffix List was unavailable: keep the validated candidate
		// and mark the hierarchy unresolved instead of inventing one.
		return internalAsset(ascii, candidate, model.SuffixUnresolved, ""), true
	case explicit:
		return internalAsset(ascii, candidate, model.SuffixUnknown, ""), true
	default:
		// "a.b" out of a bare literal: no recognized suffix and no host
		// context, so it is not a host.
		return model.HostAsset{}, false
	}
}

// matchLocalSuffix reports whether the host sits under a configured or
// special-use suffix. Matching is on the trailing label run, so "corp" covers
// both "corp" and "svc.corp".
func (e *Extractor) matchLocalSuffix(ascii string) (string, bool) {
	lowered := ascii
	for _, table := range []map[string]struct{}{e.specialSuffix, e.customSuffix} {
		for suffix := range table {
			if lowered == suffix || strings.HasSuffix(lowered, "."+suffix) {
				return suffix, true
			}
		}
	}
	return "", false
}

func internalAsset(host string, candidate Candidate, suffixStatus, note string) model.HostAsset {
	if note != "" {
		candidate.Note = joinNote(candidate.Note, note)
	}
	asset := model.HostAsset{
		Kind:         model.HostKindInternal,
		Value:        host,
		SuffixStatus: suffixStatus,
	}
	return withEvidence(asset, candidate)
}

func joinNote(existing, extra string) string {
	if existing == "" {
		return extra
	}
	return existing + "," + extra
}

func withEvidence(asset model.HostAsset, candidate Candidate) model.HostAsset {
	asset.Sources = []model.HostEvidence{{
		SourceURL:     candidate.SourceURL,
		Raw:           candidate.Raw,
		Line:          candidate.Line,
		Column:        candidate.Column,
		Method:        methodOrFallback(candidate),
		ContextLines:  candidate.ContextLines,
		AssociatedURL: candidate.AssociatedURL,
		Note:          candidate.Note,
		Vendor:        candidate.Vendor,
	}}
	asset.Occurrences = 1
	asset.Vendor = candidate.Vendor
	return asset
}

func methodOrFallback(candidate Candidate) string {
	if candidate.Method != "" {
		return candidate.Method
	}
	return model.HostMethodRegex
}

// NormalizeHost returns the canonical value a host is stored under: an
// address is parsed and canonicalized, a name is validated and converted to
// ASCII. Callers that already have a classified host (the report reading the
// scan's own host list) use it to look the value up instead of re-classifying,
// which keeps one set of host rules in the program.
func NormalizeHost(raw string) (string, bool) {
	value := SplitHostPort(strings.TrimSpace(raw))
	if value == "" || len(value) > MaxCandidateLen {
		return "", false
	}
	if address, _, ok := parseIPAddress(value); ok {
		return address.String(), true
	}
	return normalizeHostASCII(value)
}

// parseIPAddress validates one IP literal and returns it with its zone.
// IPv4-mapped IPv6 is unmapped so one address never has two spellings.
func parseIPAddress(value string) (netip.Addr, string, bool) {
	if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
		value = value[1 : len(value)-1]
	}
	value = strings.ReplaceAll(value, "%25", "%")
	address, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}, "", false
	}
	zone := address.Zone()
	if zone != "" {
		address = address.WithZone("")
	}
	if address.Is4In6() {
		address = address.Unmap()
	}
	return address, zone, true
}

// ipAsset classifies one value as an IP address. Addresses are validated and
// canonicalized with net/netip; a zone identifier is kept aside so it never
// becomes part of the dedup key.
func ipAsset(host string, candidate Candidate) (model.HostAsset, bool) {
	address, zone, ok := parseIPAddress(host)
	if !ok {
		return model.HostAsset{}, false
	}
	kind := model.HostKindIPv6
	if address.Is4() {
		kind = model.HostKindIPv4
	}
	asset := model.HostAsset{
		Kind:         kind,
		Value:        address.String(),
		SuffixStatus: model.SuffixNotApplicable,
		Attributes:   addressAttributes(address),
	}
	if kind == model.HostKindIPv6 {
		asset.Zone = zone
	}
	return withEvidence(asset, candidate), true
}

// addressAttributes lists the properties that apply. An address with none of
// them is labelled unclassified: being outside the private ranges does not by
// itself prove global routability, so no such claim is made.
func addressAttributes(address netip.Addr) []string {
	attributes := make([]string, 0, 3)
	if address.IsPrivate() {
		attributes = append(attributes, model.HostAttrPrivate)
	}
	if address.IsLoopback() {
		attributes = append(attributes, model.HostAttrLoopback)
	}
	if address.IsLinkLocalUnicast() {
		attributes = append(attributes, model.HostAttrLinkLocal)
	}
	if address.IsMulticast() {
		attributes = append(attributes, model.HostAttrMulticast)
	}
	if address.IsUnspecified() {
		attributes = append(attributes, model.HostAttrUnspecified)
	}
	if len(attributes) == 0 {
		attributes = append(attributes, model.HostAttrUnclassified)
	}
	return attributes
}

// networkSchemes are the schemes whose authority names a host.
var networkSchemes = map[string]struct{}{
	"http": {}, "https": {}, "ws": {}, "wss": {},
}

// HostFromNetworkURL returns the host of a network URL, if the value is one.
// Anything that is not an http(s)/ws(s) URL — a relative path, a mailto: or
// data: URI, a filename — is not a host and yields false.
func HostFromNetworkURL(raw string) (string, bool) {
	value := strings.TrimSpace(raw)
	if value == "" || len(value) > MaxCandidateLen {
		return "", false
	}
	if strings.ContainsAny(value, " \t\r\n") {
		return "", false
	}
	candidate := value
	protocolRelative := false
	if strings.HasPrefix(value, "//") {
		// A protocol-relative URL has no scheme of its own; https is used only
		// to give net/url an authority to parse. Nothing is requested.
		candidate = "https:" + value
		protocolRelative = true
	} else if !strings.Contains(value, "://") {
		return "", false
	}
	parsed, err := url.Parse(candidate)
	if err != nil {
		return "", false
	}
	if !protocolRelative {
		if _, ok := networkSchemes[strings.ToLower(parsed.Scheme)]; !ok {
			return "", false
		}
	}
	host := parsed.Hostname()
	if host == "" {
		return "", false
	}
	// net/url accepts authorties netip would reject ("host:99999"), so a port
	// that is present must be a real one. The port itself is not part of host
	// identity and is dropped here.
	if raw := parsed.Port(); raw != "" {
		if _, ok := validPort(raw); !ok {
			return "", false
		}
	} else if strings.Contains(parsed.Host, ":") && !strings.HasPrefix(parsed.Host, "[") {
		// "host:abc": net/url keeps the whole string in Host when the port is
		// not numeric, so the authority is malformed.
		return "", false
	}
	return host, true
}

// validPort accepts the decimal port range net/url does not enforce.
func validPort(port string) (uint32, bool) {
	if port == "" || len(port) > 5 {
		return 0, false
	}
	var value uint32
	for index := 0; index < len(port); index++ {
		char := port[index]
		if char < '0' || char > '9' {
			return 0, false
		}
		value = value*10 + uint32(char-'0')
	}
	if value > 65535 {
		return 0, false
	}
	return value, true
}

// hostProfile is the IDNA profile hosts are normalized with: case folding and
// UTS-46 mapping, IDNA2008 processing (no ß→ss folding), STD3 characters only,
// label validation, hyphen checks and DNS length verification.
var hostProfile = idna.New(
	idna.MapForLookup(),
	idna.Transitional(false),
	idna.StrictDomainName(true),
	idna.ValidateLabels(true),
	idna.VerifyDNSLength(true),
	idna.CheckHyphens(true),
	idna.CheckJoiners(true),
	idna.BidiRule(),
)

// normalizeHostASCII converts one host to its validated ASCII form. Unicode
// input is converted with the IDNA profile; the caller keeps the original
// spelling in the evidence.
func normalizeHostASCII(host string) (string, bool) {
	value := strings.TrimSpace(host)
	if value == "" || len(value) > MaxCandidateLen {
		return "", false
	}
	// One trailing root dot is legal and is removed; a second one leaves an
	// empty label, which validation rejects.
	if strings.HasSuffix(value, ".") {
		value = strings.TrimSuffix(value, ".")
	}
	if value == "" || strings.HasSuffix(value, ".") {
		return "", false
	}
	if strings.ContainsAny(value, "/\\@:?#[]") {
		return "", false
	}
	ascii, err := hostProfile.ToASCII(value)
	if err != nil {
		return "", false
	}
	ascii = strings.ToLower(ascii)
	if !validASCIIHost(ascii) {
		return "", false
	}
	return ascii, true
}

// validASCIIHost is the shared label validator: full length, per-label length,
// hyphen placement and character set. The IDNA profile already enforces these;
// keeping an explicit check makes the rules visible and independent of the
// profile's configuration.
func validASCIIHost(ascii string) bool {
	if ascii == "" || len(ascii) > 253 {
		return false
	}
	for _, label := range strings.Split(ascii, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for index := 0; index < len(label); index++ {
			char := label[index]
			switch {
			case char >= 'a' && char <= 'z':
			case char >= '0' && char <= '9':
			case char == '-':
			default:
				return false
			}
		}
	}
	return true
}

// SplitHostPort strips a trailing ":port" from a host value that may carry
// one. It exists for callers that received an authority rather than a bare
// host; the port never participates in host identity.
func SplitHostPort(authority string) string {
	value := strings.TrimSpace(authority)
	if value == "" {
		return ""
	}
	if addressPort, err := netip.ParseAddrPort(value); err == nil {
		return addressPort.Addr().String()
	}
	// A bare IPv6 literal ("::1", "2001:db8::1") carries several colons, and
	// its last group is never a port. Only a single colon can separate one.
	if strings.Count(value, ":") == 1 {
		index := strings.LastIndex(value, ":")
		if _, ok := validPort(value[index+1:]); ok {
			return value[:index]
		}
	}
	return value
}

// sortKindOrder fixes the asset ordering used by every report section.
var sortKindOrder = map[model.HostKind]int{
	model.HostKindDomain:   0,
	model.HostKindIPv4:     1,
	model.HostKindIPv6:     2,
	model.HostKindInternal: 3,
}

// SortAssets orders assets deterministically: by kind, then normalized value,
// then suffix status. Reports and the aggregator both use it, so concurrent
// analysis can never change the order a reader sees.
func SortAssets(assets []model.HostAsset) {
	sort.SliceStable(assets, func(i, j int) bool {
		left, right := assets[i], assets[j]
		if left.Kind != right.Kind {
			return sortKindOrder[left.Kind] < sortKindOrder[right.Kind]
		}
		if left.Value != right.Value {
			return left.Value < right.Value
		}
		return left.SuffixStatus < right.SuffixStatus
	})
	for index := range assets {
		sortEvidence(assets[index].Sources)
	}
}

func sortEvidence(sources []model.HostEvidence) {
	sort.SliceStable(sources, func(i, j int) bool {
		left, right := sources[i], sources[j]
		if left.SourceURL != right.SourceURL {
			return left.SourceURL < right.SourceURL
		}
		if left.Line != right.Line {
			return left.Line < right.Line
		}
		if left.Column != right.Column {
			return left.Column < right.Column
		}
		if left.Method != right.Method {
			return left.Method < right.Method
		}
		return left.Raw < right.Raw
	})
}
