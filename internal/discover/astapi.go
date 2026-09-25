package discover

import (
	"bytes"
	"encoding/json"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	sitter "github.com/tree-sitter/go-tree-sitter"
	javascript "github.com/tree-sitter/tree-sitter-javascript/bindings/go"
	"github.com/youmulijiang/jsowl/internal/model"
)

// maxJSONFieldNames caps how many response field names one probe contributes.
const maxJSONFieldNames = 32

// maxJSONFieldDepth bounds how deep response field names are collected.
const maxJSONFieldDepth = 2

// JSONFieldNames returns the field names carried by a JSON body so they can be
// fuzzed. An array contributes the keys of its first object element, and
// nested objects contribute their own keys up to a small depth. Only names are
// kept, never values, so no response body is persisted.
func JSONFieldNames(body []byte) []string {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return nil
	}
	object := map[string]json.RawMessage{}
	switch trimmed[0] {
	case '{':
		if err := json.Unmarshal(trimmed, &object); err != nil {
			return nil
		}
	case '[':
		var list []map[string]json.RawMessage
		if err := json.Unmarshal(trimmed, &list); err != nil || len(list) == 0 {
			return nil
		}
		object = list[0]
	default:
		return nil
	}
	seen := make(map[string]struct{}, maxJSONFieldNames)
	collectJSONFieldNames(object, 0, seen)
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func collectJSONFieldNames(
	object map[string]json.RawMessage,
	depth int,
	seen map[string]struct{},
) {
	if depth > maxJSONFieldDepth || len(seen) >= maxJSONFieldNames {
		return
	}
	for name, raw := range object {
		seen[name] = struct{}{}
		if len(seen) >= maxJSONFieldNames {
			return
		}
		nested := bytes.TrimSpace(raw)
		if len(nested) == 0 {
			continue
		}
		switch nested[0] {
		case '{':
			var child map[string]json.RawMessage
			if json.Unmarshal(nested, &child) == nil {
				collectJSONFieldNames(child, depth+1, seen)
			}
		case '[':
			var list []map[string]json.RawMessage
			if json.Unmarshal(nested, &list) == nil && len(list) > 0 {
				collectJSONFieldNames(list[0], depth+1, seen)
			}
		}
	}
}

// maxBodyParams caps how many field names one request contributes.
const maxBodyParams = 32

type apiCall struct {
	Raw, Method, Evidence string
	Line, Column          int
	Context               []model.ContextLine
	BodyParams            []string
}

// APIFromAST parses JavaScript with Tree-sitter. Unlike the old parser, a
// local syntax error does not discard valid call sites elsewhere in the file.
func APIFromAST(source *url.URL, body []byte) []Candidate {
	parser := sitter.NewParser()
	defer parser.Close()
	if err := parser.SetLanguage(sitter.NewLanguage(javascript.Language())); err != nil {
		return nil
	}
	tree := parser.Parse(body, nil)
	if tree == nil {
		return nil
	}
	defer tree.Close()
	root := tree.RootNode()
	if root == nil || root.NamedChildCount() == 0 {
		return nil
	}
	w := &astWalker{constants: map[string]string{}, instanceBSE: map[string]string{}, source: body}
	w.walk(root)
	sort.SliceStable(w.calls, func(i, j int) bool {
		if w.calls[i].Line != w.calls[j].Line {
			return w.calls[i].Line < w.calls[j].Line
		}
		return w.calls[i].Raw < w.calls[j].Raw
	})
	seen := make(map[string]struct{}, len(w.calls))
	result := make([]Candidate, 0, len(w.calls))
	for _, call := range w.calls {
		key := call.Method + "\x00" + call.Raw
		if call.Raw == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, Candidate{
			Raw: call.Raw, Kind: KindEndpoint, Method: call.Method,
			Evidence: call.Evidence, Line: call.Line, Column: call.Column,
			ContextLines: call.Context, BodyParams: call.BodyParams, Source: "ast",
		})
	}
	return result
}

type astWalker struct {
	calls       []apiCall
	constants   map[string]string
	instanceBSE map[string]string
	source      []byte
}

func (w *astWalker) text(n *sitter.Node) string {
	if n == nil || n.StartByte() > n.EndByte() || n.EndByte() > uint(len(w.source)) {
		return ""
	}
	return string(w.source[n.StartByte():n.EndByte()])
}

func (w *astWalker) walk(n *sitter.Node) {
	if n == nil {
		return
	}
	switch n.Kind() {
	case "variable_declarator":
		w.bind(n.ChildByFieldName("name"), n.ChildByFieldName("value"))
	case "assignment_expression":
		w.bindAssignment(n.ChildByFieldName("left"), n.ChildByFieldName("right"))
	case "call_expression":
		w.visitCall(n)
	}
	// ERROR nodes are named nodes too. Walking through them is intentional:
	// valid descendants in malformed or truncated bundles remain recoverable.
	for i := uint(0); i < n.NamedChildCount(); i++ {
		w.walk(n.NamedChild(i))
	}
}

func (w *astWalker) bind(nameNode, value *sitter.Node) {
	nameNode, value = unwrap(nameNode), unwrap(value)
	if nameNode == nil || nameNode.Kind() != "identifier" || value == nil {
		return
	}
	name := w.text(nameNode)
	if base, ok := w.axiosCreateBase(value); ok {
		w.instanceBSE[name] = base
		return
	}
	if value.Kind() == "string" {
		w.constants[name] = decodeJSString(w.text(value))
	}
}

func (w *astWalker) bindAssignment(left, right *sitter.Node) {
	left, right = unwrap(left), unwrap(right)
	if left == nil || right == nil {
		return
	}
	if left.Kind() == "identifier" {
		name := w.text(left)
		if base, ok := w.axiosCreateBase(right); ok {
			w.instanceBSE[name] = base
		} else if right.Kind() == "string" {
			w.constants[name] = decodeJSString(w.text(right))
		}
	}
	if name, ok := w.baseURLTarget(left); ok {
		w.instanceBSE[name] = w.baseURLFromExpression(right)
	}
}

func (w *astWalker) visitCall(call *sitter.Node) {
	callee := unwrap(call.ChildByFieldName("function"))
	args := w.arguments(call)
	if callee == nil {
		return
	}
	method, urlArg, bodyArg := "", -1, -1
	var urlOverride *sitter.Node

	if object, property, ok := w.memberParts(callee); ok {
		receiver := w.outermostIdentifier(object)
		switch property {
		case "open":
			if len(args) >= 2 && kind(unwrap(args[0])) == "string" {
				method, urlArg = strings.ToUpper(decodeJSString(w.text(unwrap(args[0])))), 1
			}
		case "get", "post", "put", "patch", "delete", "head", "options", "getJSON",
			"Get", "Post", "Put", "Patch", "Delete", "Head":
			method, urlArg = strings.ToUpper(strings.TrimSuffix(property, "JSON")), 0
			write := method == "POST" || method == "PUT" || method == "PATCH" || method == "DELETE"
			if kind(object) == "call_expression" {
				head := unwrap(object.ChildByFieldName("function"))
				if kind(head) == "identifier" && w.text(head) == "wretch" {
					headArgs := w.arguments(object)
					if len(headArgs) > 0 {
						urlOverride, urlArg = headArgs[0], -1
					}
					if write {
						bodyArg = 0
					}
				}
			}
			if receiver == "ky" && len(args) > 1 {
				bodyArg = -4
			} else if write && bodyArg == -1 {
				bodyArg = 1
			} else if bodyArg == -1 && len(args) > 1 {
				// axios-style trailing config object: {params:{...}} carries
				// the query fields, {data:{...}} the body fields.
				bodyArg = -7
			}
		case "request", "ajax", "api":
			method, urlArg, bodyArg = w.objectCallArgs(args)
		case "fetch":
			method, urlArg = "GET", 0
			if len(args) > 1 {
				if m := w.optionsMethod(args[1]); m != "" {
					method = m
				}
				bodyArg = -3
			}
		}
		if isMiniProgram(receiver) && property == "request" {
			method, urlArg, bodyArg = w.objectCallArgs(args)
			if method == "" {
				method = "GET"
			}
		}
	} else if callee.Kind() == "identifier" {
		switch w.text(callee) {
		case "fetch":
			method, urlArg = "GET", 0
			if len(args) > 1 {
				if m := w.optionsMethod(args[1]); m != "" {
					method = m
				}
				bodyArg = -3
			}
		case "ajax", "api":
			method, urlArg, bodyArg = w.objectCallArgs(args)
		case "request":
			method, urlArg = "GET", 0
			if len(args) > 1 {
				if m := w.optionsMethod(args[1]); m != "" {
					method = m
				}
				bodyArg = -6
			}
		case "useSWR":
			method, urlArg = "GET", 0
		case "$fetch", "ofetch", "$ofetch", "ky":
			method, urlArg = "GET", 0
			if len(args) > 1 {
				if m := w.optionsMethod(args[1]); m != "" {
					method = m
				}
				bodyArg = -5
			}
		}
	}

	// A wrapper call hides the request shape behind a call expression, as in
	// Object(service["a"])({url:"/soap/x", method:"post"}): the callee is not
	// an identifier or a member expression, so no branch above matched. Fall
	// back to the object-literal form whenever the first argument is one.
	if urlArg < 0 && len(args) > 0 {
		if first := unwrap(args[0]); kind(first) == "object" &&
			w.objectValue(first, "url") != nil {
			method, urlArg, bodyArg = w.objectCallArgs(args)
		}
	}

	var urlNode *sitter.Node
	if urlOverride != nil {
		urlNode = urlOverride
	} else if urlArg >= 0 && urlArg < len(args) {
		urlNode = args[urlArg]
	} else {
		return
	}
	raw, evidence := w.resolveURLExpression(urlNode)
	if raw == "" {
		return
	}
	// A call like map.get("ArrowDown") matches the generic HTTP-verb branch;
	// only path-shaped values are real request targets.
	if !looksLikePath(raw) {
		return
	}
	point := callee.StartPosition()
	line, column := int(point.Row)+1, int(point.Column)+1
	ctx := extractContext(w.source, int(callee.StartByte()), contextSpanLines)
	params := w.bodyParameterNames(args, bodyArg)
	w.calls = append(w.calls, apiCall{raw, method, evidence, line, column, ctx, params})
	if object, _, ok := w.memberParts(callee); ok && evidence == model.EvidenceStatic {
		if base := w.instanceBSE[w.outermostIdentifier(object)]; base != "" {
			if joined := joinBaseURL(base, raw); joined != "" {
				w.calls = append(w.calls, apiCall{joined, method, model.EvidenceFullURL, line, column, ctx, params})
			}
		}
	}
}

func isMiniProgram(s string) bool {
	return s == "wx" || s == "uni" || s == "taro" || s == "Taro" || s == "my" || s == "tt"
}

func (w *astWalker) arguments(call *sitter.Node) []*sitter.Node {
	n := call.ChildByFieldName("arguments")
	if kind(n) != "arguments" {
		return nil
	}
	result := make([]*sitter.Node, 0, n.NamedChildCount())
	for i := uint(0); i < n.NamedChildCount(); i++ {
		result = append(result, n.NamedChild(i))
	}
	return result
}

// objectCallArgs handles request({url, method}) and $.ajax({url, type}).
func (w *astWalker) objectCallArgs(args []*sitter.Node) (string, int, int) {
	if len(args) == 0 {
		return "", -1, -2
	}
	first := unwrap(args[0])
	if kind(first) == "object" {
		urlIndex := -1
		if w.objectValue(first, "url") != nil {
			urlIndex = 0
		}
		method := ""
		for _, key := range []string{"method", "type"} {
			if value := unwrap(w.objectValue(first, key)); kind(value) == "string" {
				method = strings.ToUpper(decodeJSString(w.text(value)))
			}
		}
		return method, urlIndex, -2
	}
	if kind(first) == "string" || kind(first) == "template_string" {
		return "", 0, -2
	}
	return "", -1, -2
}

func (w *astWalker) resolveURLExpression(n *sitter.Node) (string, string) {
	n = unwrap(n)
	switch kind(n) {
	case "string":
		value := decodeJSString(w.text(n))
		return value, evidenceFor(value)
	case "identifier":
		if value, ok := w.constants[w.text(n)]; ok {
			return value, evidenceFor(value)
		}
	case "template_string":
		return w.templatePlaceholder(n), model.EvidenceStatic
	case "binary_expression":
		if w.text(n.ChildByFieldName("operator")) == "+" {
			if value, ok := w.foldConcat(n, 0); ok {
				return value, evidenceFor(value)
			}
		}
	case "object":
		if value := w.objectValue(n, "url"); value != nil {
			return w.resolveURLExpression(value)
		}
	}
	return "", ""
}

// bodyParameterNames lists the field names a request carries so they can be
// fuzzed. It accepts the request-body shapes of the common clients, plus
// axios-style "params" (query) objects, and reads JSON string literals
// because minified bundles often inline the payload that way.
func (w *astWalker) bodyParameterNames(args []*sitter.Node, bodyArg int) []string {
	candidates := make([]*sitter.Node, 0, 2)
	appendValue := func(object *sitter.Node, keys ...string) {
		for _, key := range keys {
			if value := w.objectValue(object, key); value != nil {
				candidates = append(candidates, value)
			}
		}
	}
	switch bodyArg {
	case -2:
		if len(args) > 0 {
			appendValue(unwrap(args[0]), "data", "params")
		}
	case -3:
		if len(args) > 1 {
			appendValue(unwrap(args[1]), "body")
		}
	case -4:
		if len(args) > 1 {
			appendValue(unwrap(args[1]), "json")
		}
	case -5:
		if len(args) > 1 {
			appendValue(unwrap(args[1]), "body", "json")
		}
	case -6:
		if len(args) > 1 {
			appendValue(unwrap(args[1]), "data", "params")
		}
	case -7:
		if len(args) > 1 {
			appendValue(unwrap(args[1]), "params", "data", "body", "json")
		}
	default:
		if bodyArg >= 0 && bodyArg < len(args) {
			candidates = append(candidates, args[bodyArg])
		}
	}

	names := make([]string, 0, 8)
	seen := make(map[string]struct{})
	for _, candidate := range candidates {
		body := unwrap(candidate)
		if kind(body) == "call_expression" &&
			w.isStringifyCall(body.ChildByFieldName("function")) {
			if wrapped := w.arguments(body); len(wrapped) > 0 {
				body = unwrap(wrapped[0])
			}
		}
		for _, name := range w.parameterNamesOf(body) {
			if _, duplicate := seen[name]; duplicate {
				continue
			}
			seen[name] = struct{}{}
			names = append(names, name)
		}
	}
	return names
}

// parameterNamesOf reads field names from an object literal or from a JSON
// string literal (the payload inlined as text); anything else yields nothing.
func (w *astWalker) parameterNamesOf(node *sitter.Node) []string {
	switch kind(node) {
	case "object":
		return w.objectPropertyNames(node)
	case "string":
		return jsonObjectKeys(decodeJSString(w.text(node)))
	case "template_string":
		return jsonObjectKeys(w.templatePlaceholder(node))
	}
	return nil
}

// jsonObjectKeys returns the top-level keys of a JSON object literal so a
// payload written as '{"a":1,"b":2}' still yields fuzzable field names.
func jsonObjectKeys(raw string) []string {
	trimmed := strings.TrimSpace(raw)
	if !strings.HasPrefix(trimmed, "{") ||
		!json.Valid([]byte(trimmed)) {
		return nil
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal([]byte(trimmed), &object); err != nil {
		return nil
	}
	names := make([]string, 0, len(object))
	for name := range object {
		names = append(names, name)
	}
	sort.Strings(names)
	if len(names) > maxBodyParams {
		names = names[:maxBodyParams]
	}
	return names
}

func (w *astWalker) isStringifyCall(n *sitter.Node) bool {
	object, property, ok := w.memberParts(unwrap(n))
	return ok && property == "stringify" && w.outermostIdentifier(object) == "JSON"
}

func (w *astWalker) objectPropertyNames(object *sitter.Node) []string {

	var names []string
	for i := uint(0); i < object.NamedChildCount() && len(names) < maxBodyParams; i++ {
		child, name := object.NamedChild(i), ""
		if child.Kind() == "pair" {
			name = w.propertyName(child.ChildByFieldName("key"))
		} else if child.Kind() == "shorthand_property_identifier" || child.Kind() == "shorthand_property_identifier_pattern" {
			name = w.text(child)
		}
		if name != "" {
			names = append(names, name)
		}
	}
	return names
}

func (w *astWalker) optionsMethod(n *sitter.Node) string {
	n = unwrap(n)
	if kind(n) != "object" {
		return ""
	}
	for _, key := range []string{"method", "type"} {
		if value := unwrap(w.objectValue(n, key)); kind(value) == "string" {
			return strings.ToUpper(decodeJSString(w.text(value)))
		}
	}
	return ""
}

func (w *astWalker) foldConcat(n *sitter.Node, depth int) (string, bool) {
	if depth > 8 {
		return "", false
	}
	n = unwrap(n)
	switch kind(n) {
	case "binary_expression":
		if w.text(n.ChildByFieldName("operator")) != "+" {
			return "", false
		}
		left, lok := w.foldConcat(n.ChildByFieldName("left"), depth+1)
		right, rok := w.foldConcat(n.ChildByFieldName("right"), depth+1)
		return left + right, lok && rok
	case "string":
		return decodeJSString(w.text(n)), true
	case "identifier":
		if value, ok := w.constants[w.text(n)]; ok {
			return value, true
		}
		return "{}", true
	}
	return "", false
}

func (w *astWalker) templatePlaceholder(n *sitter.Node) string {
	var result strings.Builder
	for i := uint(0); i < n.NamedChildCount(); i++ {
		child := n.NamedChild(i)
		switch child.Kind() {
		case "string_fragment":
			result.WriteString(w.text(child))
		case "escape_sequence":
			result.WriteString(decodeJSEscapes(w.text(child)))
		case "template_substitution":
			result.WriteString("{}")
		}
	}
	return result.String()
}

func evidenceFor(raw string) string {
	parsed, err := url.Parse(raw)
	if err == nil && (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Host != "" {
		return model.EvidenceFullURL
	}
	return model.EvidenceStatic
}

func (w *astWalker) axiosCreateBase(n *sitter.Node) (string, bool) {
	n = unwrap(n)
	if kind(n) != "call_expression" {
		return "", false
	}
	object, property, ok := w.memberParts(unwrap(n.ChildByFieldName("function")))
	if !ok || property != "create" || w.outermostIdentifier(object) != "axios" {
		return "", false
	}
	args := w.arguments(n)
	if len(args) == 0 || kind(unwrap(args[0])) != "object" {
		return "", false
	}
	value := w.objectValue(unwrap(args[0]), "baseURL")
	if value == nil {
		return "", false
	}
	return w.baseURLFromExpression(value), true
}

func (w *astWalker) baseURLTarget(n *sitter.Node) (string, bool) {
	object, property, ok := w.memberParts(unwrap(n))
	if !ok || property != "baseURL" {
		return "", false
	}
	name := w.outermostIdentifier(object)
	return name, name != ""
}

func (w *astWalker) baseURLFromExpression(n *sitter.Node) string {
	n = unwrap(n)
	switch kind(n) {
	case "string":
		return decodeJSString(w.text(n))
	case "identifier":
		return w.constants[w.text(n)]
	case "template_string":
		return w.templatePlaceholder(n)
	case "binary_expression":
		if w.text(n.ChildByFieldName("operator")) == "+" {
			left, right := w.baseURLFromExpression(n.ChildByFieldName("left")), w.baseURLFromExpression(n.ChildByFieldName("right"))
			if left != "" && right != "" {
				return left + right
			}
			return left
		}
	}
	return ""
}

func (w *astWalker) memberParts(n *sitter.Node) (*sitter.Node, string, bool) {
	n = unwrap(n)
	if kind(n) == "member_expression" {
		object, property := unwrap(n.ChildByFieldName("object")), n.ChildByFieldName("property")
		return object, w.text(property), object != nil && property != nil
	}
	if kind(n) == "subscript_expression" {
		object, index := unwrap(n.ChildByFieldName("object")), unwrap(n.ChildByFieldName("index"))
		if kind(index) == "string" {
			return object, decodeJSString(w.text(index)), object != nil
		}
	}
	return nil, "", false
}

func (w *astWalker) outermostIdentifier(n *sitter.Node) string {
	for n != nil {
		n = unwrap(n)
		switch kind(n) {
		case "identifier":
			return w.text(n)
		case "member_expression", "subscript_expression":
			n = n.ChildByFieldName("object")
		default:
			return ""
		}
	}
	return ""
}

func (w *astWalker) objectValue(object *sitter.Node, wanted string) *sitter.Node {
	if kind(object) != "object" {
		return nil
	}
	for i := uint(0); i < object.NamedChildCount(); i++ {
		pair := object.NamedChild(i)
		if pair.Kind() == "pair" && w.propertyName(pair.ChildByFieldName("key")) == wanted {
			return pair.ChildByFieldName("value")
		}
	}
	return nil
}

func (w *astWalker) propertyName(n *sitter.Node) string {
	n = unwrap(n)
	if kind(n) == "string" {
		return decodeJSString(w.text(n))
	}
	switch kind(n) {
	case "identifier", "property_identifier", "private_property_identifier", "shorthand_property_identifier", "shorthand_property_identifier_pattern":
		return w.text(n)
	}
	return ""
}

func kind(n *sitter.Node) string {
	if n == nil {
		return ""
	}
	return n.Kind()
}

func unwrap(n *sitter.Node) *sitter.Node {
	for kind(n) == "parenthesized_expression" && n.NamedChildCount() > 0 {
		n = n.NamedChild(0)
	}
	return n
}

func joinBaseURL(base, raw string) string {
	if raw == "" || strings.Contains(raw, "://") || strings.HasPrefix(raw, "//") {
		return ""
	}
	return strings.TrimRight(base, "/") + "/" + strings.TrimLeft(raw, "/")
}

// Tree-sitter preserves the source spelling of strings; decode ECMAScript
// escapes here so callers receive the same logical values as before.
func decodeJSString(raw string) string {
	if len(raw) >= 2 && (raw[0] == '\'' || raw[0] == '"') && raw[len(raw)-1] == raw[0] {
		raw = raw[1 : len(raw)-1]
	}
	return decodeJSEscapes(raw)
}

func decodeJSEscapes(raw string) string {
	var out strings.Builder
	for i := 0; i < len(raw); {
		if raw[i] != '\\' {
			r, size := utf8.DecodeRuneInString(raw[i:])
			if r == utf8.RuneError && size == 1 {
				out.WriteByte(raw[i])
				i++
			} else {
				out.WriteRune(r)
				i += size
			}
			continue
		}
		i++
		if i >= len(raw) {
			out.WriteByte('\\')
			break
		}
		switch raw[i] {
		case 'b':
			out.WriteByte('\b')
			i++
		case 'f':
			out.WriteByte('\f')
			i++
		case 'n':
			out.WriteByte('\n')
			i++
		case 'r':
			out.WriteByte('\r')
			i++
		case 't':
			out.WriteByte('\t')
			i++
		case 'v':
			out.WriteByte('\v')
			i++
		case '0':
			out.WriteByte(0)
			i++
		case '\n':
			i++
		case '\r':
			i++
			if i < len(raw) && raw[i] == '\n' {
				i++
			}
		case 'x':
			if value, next, ok := parseHex(raw, i+1, 2); ok {
				out.WriteRune(rune(value))
				i = next
			} else {
				out.WriteByte('x')
				i++
			}
		case 'u':
			value, next, ok := parseUnicode(raw, i)
			if !ok {
				out.WriteByte('u')
				i++
				continue
			}
			i = next
			if value >= 0xD800 && value <= 0xDBFF && i+2 <= len(raw) && raw[i:i+2] == "\\u" {
				if low, lowNext, ok := parseUnicode(raw, i+1); ok && low >= 0xDC00 && low <= 0xDFFF {
					out.WriteRune(utf16.DecodeRune(rune(value), rune(low)))
					i = lowNext
					continue
				}
			}
			if value <= utf8.MaxRune && !(value >= 0xD800 && value <= 0xDFFF) {
				out.WriteRune(rune(value))
			} else {
				out.WriteRune(utf8.RuneError)
			}
		default:
			out.WriteByte(raw[i])
			i++
		}
	}
	return out.String()
}

func parseUnicode(raw string, u int) (uint64, int, bool) {
	if u >= len(raw) || raw[u] != 'u' {
		return 0, u, false
	}
	if u+1 < len(raw) && raw[u+1] == '{' {
		rel := strings.IndexByte(raw[u+2:], '}')
		if rel < 0 {
			return 0, u, false
		}
		end := u + 2 + rel
		if end == u+2 {
			return 0, u, false
		}
		value, err := strconv.ParseUint(raw[u+2:end], 16, 32)
		return value, end + 1, err == nil && value <= utf8.MaxRune
	}
	return parseHex(raw, u+1, 4)
}

func parseHex(raw string, start, count int) (uint64, int, bool) {
	end := start + count
	if start < 0 || end > len(raw) {
		return 0, start, false
	}
	value, err := strconv.ParseUint(raw[start:end], 16, 32)
	return value, end, err == nil
}
