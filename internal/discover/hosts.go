package discover

import (
	"net/url"
	"strconv"
	"strings"
	"time"

	sitter "github.com/tree-sitter/go-tree-sitter"

	"github.com/youmulijiang/jsowl/internal/extract"
	"github.com/youmulijiang/jsowl/internal/model"
)

// This file collects host candidates from the AST that APIFromAST already
// parsed. It walks the same tree — no file is parsed twice for host
// extraction — and reuses the walker's constant table, so a host assembled
// from literals resolves exactly the way a URL does elsewhere in the project.
//
// Nothing here evaluates target code: only literal text, static templates and
// concatenations whose every operand is already known are folded. A host built
// from a runtime value is recorded as an unresolved dynamic expression, never
// guessed.

// hostFieldNames are property/identifier names whose value is explicitly a
// host or a base URL. Only these make a bare single-label value a host: the
// name is a context hint, and the value still has to pass the shared
// validators afterwards.
var hostFieldNames = map[string]struct{}{
	"host": {}, "hostname": {}, "host_name": {}, "hostname_": {},
	"baseurl": {}, "base_url": {}, "apiurl": {}, "api_url": {},
	"serverurl": {}, "server_url": {}, "origin": {}, "domain": {},
	"endpoint": {}, "endpoint_url": {}, "authority": {}, "websocketurl": {},
	"wsurl": {}, "api_host": {}, "apihost": {}, "gateway": {},
}

// hostCandidateLimit caps one file's candidates; it mirrors the extractor's
// own cap so the collector stops before the aggregator has to.
const hostCandidateLimit = extract.MaxCandidatesPerFile

// HostCandidates is one file's host extraction result.
type HostCandidates struct {
	Candidates []extract.Candidate
	// BasePaths lists the interface prefixes the file declares (baseURL,
	// apiPrefix, ...); the pipeline tries relative references under them.
	BasePaths []BasePathCandidate
	Notes     []extract.Note
}

// collectHosts walks a parsed JavaScript tree and returns host candidates. It
// runs over the tree APIFromAST already parsed, so no file is parsed twice for
// host discovery.
func collectHosts(
	source *url.URL,
	body []byte,
	root *sitter.Node,
) HostCandidates {
	if root == nil {
		return HostCandidates{}
	}
	sourceURL := ""
	if source != nil {
		sourceURL = source.String()
	}
	collector := &hostCollector{
		sourceURL: sourceURL,
		body:      body,
		seen:      map[string]struct{}{},
		deadline:  time.Now().Add(extract.MaxExtractionDuration),
	}
	collector.walk(root, extract.ContextLiteral)
	if collector.nodes >= extract.MaxExtractionNodes {
		collector.notes = append(collector.notes, extract.Note{
			Code: extract.NoteCandidatesCapped,
			Message: "单文件 AST 节点数超过上限 " + strconv.Itoa(extract.MaxExtractionNodes) +
				"，主机提取已停止。",
			URL: sourceURL,
		})
	}
	if time.Now().After(collector.deadline) {
		collector.notes = append(collector.notes, extract.Note{
			Code:    extract.NoteCandidatesCapped,
			Message: "单文件主机提取超出时间上限，已停止。",
			URL:     sourceURL,
		})
	}
	return HostCandidates{
		Candidates: collector.candidates,
		BasePaths:  collector.basePaths,
		Notes:      collector.notes,
	}
}

type hostCollector struct {
	sourceURL  string
	body       []byte
	basePaths  []BasePathCandidate
	candidates []extract.Candidate
	notes      []extract.Note
	seen       map[string]struct{}
	// dynamic memoizes the dynamic-host note so one file reports it once.
	dynamic  bool
	nodes    int
	deadline time.Time
}

func (c *hostCollector) text(n *sitter.Node) string {
	if n == nil || n.StartByte() > n.EndByte() || n.EndByte() > uint(len(c.body)) {
		return ""
	}
	return string(c.body[n.StartByte():n.EndByte()])
}

func (c *hostCollector) walk(n *sitter.Node, context string) {
	if n == nil {
		return
	}
	c.nodes++
	if c.nodes > extract.MaxExtractionNodes || len(c.candidates) >= hostCandidateLimit {
		return
	}
	if c.nodes%2048 == 0 && time.Now().After(c.deadline) {
		return
	}
	switch n.Kind() {
	case "string":
		c.recordLiteral(n, context)
		return
	case "template_string":
		c.recordTemplate(n, context)
		return
	case "binary_expression":
		if folded, ok := c.staticString(n); ok {
			c.record(n, folded, context, model.HostMethodStaticExpression)
			return
		}
		c.noteDynamic(n)
		return
	case "comment":
		// Comments carry embedded hosts (allowed-origins lists, TODO URLs).
		// They are labelled so a reader can weigh them accordingly.
		c.recordRegexText(n)
		return
	case "pair":
		key := unwrap(n.ChildByFieldName("key"))
		value := unwrap(n.ChildByFieldName("value"))
		if key != nil && value != nil {
			name := c.propertyName(key)
			if isBasePathFieldName(name) && c.recordBasePath(value) {
				// A base path is an interface prefix, not a host: it is
				// recorded on its own and tried when references resolve.
				return
			}
			childContext := extract.ContextLiteral
			if isHostFieldName(name) || isBasePathFieldName(name) {
				childContext = extract.ContextHostField
			}
			c.walk(value, childContext)
			return
		}
	case "assignment_expression":
		left := unwrap(n.ChildByFieldName("left"))
		right := unwrap(n.ChildByFieldName("right"))
		if right != nil {
			name := c.assignedName(left)
			if isBasePathFieldName(name) && c.recordBasePath(right) {
				return
			}
			childContext := extract.ContextLiteral
			if isHostFieldName(name) || isBasePathFieldName(name) {
				childContext = extract.ContextHostField
			}
			c.walk(right, childContext)
			return
		}
	case "variable_declarator":
		name := unwrap(n.ChildByFieldName("name"))
		value := unwrap(n.ChildByFieldName("value"))
		if value != nil {
			nameText := ""
			if name != nil && kind(name) == "identifier" {
				nameText = c.text(name)
			}
			if isBasePathFieldName(nameText) && c.recordBasePath(value) {
				return
			}
			childContext := extract.ContextLiteral
			if isHostFieldName(nameText) || isBasePathFieldName(nameText) {
				childContext = extract.ContextHostField
			}
			c.walk(value, childContext)
			return
		}
	}
	for index := uint(0); index < n.NamedChildCount(); index++ {
		c.walk(n.NamedChild(index), extract.ContextLiteral)
	}
}

// recordTemplate handles a template string: a static one is a literal, while a
// template with substitutions is a runtime value. Only the dynamic case is
// noted, and only when its static text looks like a host, so a bundle full of
// URL building does not flood the diagnostics.
func (c *hostCollector) recordTemplate(n *sitter.Node, context string) {
	if !hasTemplateSubstitution(n) {
		c.record(n, c.templateText(n), context, model.HostMethodASTLiteral)
		return
	}
	static := c.templateText(n)
	if strings.Contains(static, "://") || looksLikeHostFragment(static) {
		c.noteDynamic(n)
	}
}

// templateText renders a static template string's text content, decoding its
// escape sequences the same way string literals are decoded.
func (c *hostCollector) templateText(n *sitter.Node) string {
	var out strings.Builder
	for index := uint(0); index < n.NamedChildCount(); index++ {
		child := n.NamedChild(index)
		switch child.Kind() {
		case "string_fragment":
			out.WriteString(c.text(child))
		case "escape_sequence":
			out.WriteString(decodeJSEscapes(c.text(child)))
		}
	}
	return out.String()
}

func (c *hostCollector) noteDynamic(n *sitter.Node) {
	if c.dynamic {
		return
	}
	c.dynamic = true
	c.notes = append(c.notes, extract.Note{
		Code:    extract.NoteDynamicHost,
		Message: "存在由运行时值拼装的主机表达式，未求值也未生成域名，仅记录该情况。",
		URL:     c.sourceURL,
	})
}

// recordLiteral handles one string literal. Its decoded value is offered as a
// candidate directly; a literal that also carries a host hint (a non-network
// scheme, an address shape, an embedded authority) is additionally scanned, so
// hosts inside connection strings and JSON blobs are recovered instead of
// being lost with the surrounding text. The hint check is a cheap byte scan,
// which keeps the fallback off the hot path for a minified bundle.
func (c *hostCollector) recordLiteral(n *sitter.Node, context string) {
	raw := decodeJSString(c.text(n))
	c.record(n, raw, context, model.HostMethodASTLiteral)
	if !literalHoldsHost(raw) {
		return
	}
	for _, candidate := range scanHostText(c.body, int(n.StartByte()), raw, c.sourceURL, "") {
		if len(c.candidates) >= hostCandidateLimit {
			return
		}
		key := candidate.Method + "\x00" + candidate.Raw + "\x00" +
			strconv.Itoa(candidate.Line) + "\x00" + strconv.Itoa(candidate.Column)
		if _, duplicate := c.seen[key]; duplicate {
			continue
		}
		c.seen[key] = struct{}{}
		c.candidates = append(c.candidates, candidate)
	}
}

// literalHoldsHost reports whether a literal is worth scanning. It looks for
// an authority ("://"), an address shape or an embedded user@host, which is
// where a non-URL string can still carry a host.
func literalHoldsHost(raw string) bool {
	if raw == "" || len(raw) > extract.MaxCandidateLen {
		return false
	}
	if strings.Contains(raw, "://") {
		return true
	}
	if strings.Contains(raw, "@") && strings.Contains(raw, ".") {
		return true
	}
	return holdsIPv4Shape(raw)
}

// holdsIPv4Shape looks for four dot-separated digit runs without regexing.
func holdsIPv4Shape(raw string) bool {
	digits, dots := 0, 0
	for index := 0; index < len(raw); index++ {
		char := raw[index]
		switch {
		case char >= '0' && char <= '9':
			digits++
		case char == '.':
			dots++
			if dots == 3 && digits >= 4 {
				return true
			}
		default:
			digits, dots = 0, 0
		}
	}
	return false
}

// record adds one candidate, keeping the raw spelling and its position. The
// same value at the same position from the same method is one observation.
func (c *hostCollector) record(n *sitter.Node, raw, context, method string) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > extract.MaxCandidateLen || len(c.candidates) >= hostCandidateLimit {
		return
	}
	line, column := int(n.StartPosition().Row)+1, int(n.StartPosition().Column)+1
	key := method + "\x00" + raw + "\x00" + strconv.Itoa(line) + "\x00" + strconv.Itoa(column)
	if _, duplicate := c.seen[key]; duplicate {
		return
	}
	c.seen[key] = struct{}{}
	c.candidates = append(c.candidates, extract.Candidate{
		Raw:          raw,
		Context:      context,
		Method:       method,
		SourceURL:    c.sourceURL,
		Line:         line,
		Column:       column,
		ContextLines: extractContext(c.body, int(n.StartByte()), contextSpanLines, raw),
	})
}

// staticString folds a concatenation whose every operand is a string literal
// or a static template. Identifiers are deliberately NOT folded: a name can be
// reassigned, or bound differently per branch, and the walker's constant table
// only holds the last value it saw. Folding it would invent a host the code
// may never use — the literal in the declaration is already recorded as
// evidence, so nothing is lost by stopping here.
func (c *hostCollector) staticString(n *sitter.Node) (string, bool) {
	operator := n.ChildByFieldName("operator")
	if operator == nil || c.text(operator) != "+" {
		return "", false
	}
	var out strings.Builder
	var walkOperand func(node *sitter.Node) bool
	walkOperand = func(node *sitter.Node) bool {
		node = unwrap(node)
		if node == nil {
			return false
		}
		switch node.Kind() {
		case "string":
			out.WriteString(decodeJSString(c.text(node)))
			return true
		case "template_string":
			if hasTemplateSubstitution(node) {
				return false
			}
			out.WriteString(c.templateText(node))
			return true
		case "binary_expression":
			return walkOperand(node.ChildByFieldName("left")) &&
				walkOperand(node.ChildByFieldName("right"))
		}
		return false
	}
	if !walkOperand(n) {
		return "", false
	}
	return out.String(), true
}

// recordRegexText runs the shared candidate scan over a text blob (a comment)
// and records what it finds, with positions resolved against the file body.
func (c *hostCollector) recordRegexText(n *sitter.Node) {
	if n == nil {
		return
	}
	for _, candidate := range scanHostText(
		c.body, int(n.StartByte()), c.text(n), c.sourceURL, "comment",
	) {
		if len(c.candidates) >= hostCandidateLimit {
			return
		}
		key := candidate.Method + "\x00" + candidate.Raw + "\x00" +
			strconv.Itoa(candidate.Line) + "\x00" + strconv.Itoa(candidate.Column)
		if _, duplicate := c.seen[key]; duplicate {
			continue
		}
		c.seen[key] = struct{}{}
		c.candidates = append(c.candidates, candidate)
	}
}

func (c *hostCollector) propertyName(n *sitter.Node) string {
	n = unwrap(n)
	if kind(n) == "string" {
		return decodeJSString(c.text(n))
	}
	switch kind(n) {
	case "identifier", "property_identifier", "shorthand_property_identifier",
		"shorthand_property_identifier_pattern":
		return c.text(n)
	}
	return ""
}

// assignedName resolves the field name of an assignment target: "host" for
// x.host = ... and for host = ....
func (c *hostCollector) assignedName(left *sitter.Node) string {
	left = unwrap(left)
	if left == nil {
		return ""
	}
	if left.Kind() == "member_expression" {
		return c.propertyName(left.ChildByFieldName("property"))
	}
	if left.Kind() == "identifier" {
		return c.text(left)
	}
	return ""
}

func isHostFieldName(name string) bool {
	if name == "" {
		return false
	}
	_, ok := hostFieldNames[strings.ToLower(name)]
	return ok
}

// looksLikeHostFragment reports whether static template text around a
// substitution could be part of a host, so dynamic notes stay meaningful.
func looksLikeHostFragment(static string) bool {
	trimmed := strings.TrimSpace(static)
	if trimmed == "" {
		return false
	}
	if strings.ContainsAny(trimmed, "/:?=") {
		return false
	}
	return strings.Contains(trimmed, ".")
}
