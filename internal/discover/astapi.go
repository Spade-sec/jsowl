package discover

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	sitter "github.com/tree-sitter/go-tree-sitter"
	javascript "github.com/tree-sitter/tree-sitter-javascript/bindings/go"

	"github.com/youmulijiang/jsowl/internal/extract"
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

// maxParamDepth bounds how deep nested object parameters are flattened.
const maxParamDepth = 2

type apiCall struct {
	Raw, Method, Evidence string
	Line, Column          int
	Context               []model.ContextLine
	BodyParams            []string
	Spec                  *model.RequestSpec
	// FuncStart is the enclosing function's start offset (0 at file scope);
	// heuristic and taint passes scope their lookups by it.
	FuncStart uint32
}

// dedupKey distinguishes two call sites that share method and path but carry
// different parameters or content types, so every fuzzable variant survives.
func (c apiCall) dedupKey() string {
	digest := ""
	if c.Spec != nil {
		digest = c.Spec.ContentType + "\x00" +
			strings.Join(specKeyParams(c.Spec.Query), ",") + "\x00" +
			strings.Join(specKeyParams(c.Spec.Body), ",")
	}
	return c.Method + "\x00" + c.Raw + "\x00" + digest
}

func specKeyParams(params []model.Param) []string {
	keys := make([]string, len(params))
	for i, param := range params {
		keys[i] = param.Key + "=" + param.Value
	}
	return keys
}

// JSAnalysis is everything one JavaScript parse yields: the API candidates and
// the host candidates, plus any extraction-limit diagnostics.
type JSAnalysis struct {
	Candidates []Candidate
	Hosts      []extract.Candidate
	// BasePaths lists the interface prefixes this file declares; the pipeline
	// tries relative references under each of them.
	BasePaths []BasePathCandidate
	Notes     []extract.Note
}

// ParsedScript owns one Tree-sitter parse of a JavaScript body. It lets the
// API extractor, the host extractor and the parameter collector share a single
// syntax tree instead of parsing the same file three times. The tree is valid
// only between ParseScript and Close; callers must finish walking it before
// closing and must not share it across goroutines.
type ParsedScript struct {
	Body  []byte
	tree  *sitter.Tree
	root  *sitter.Node
	lines *lineIndex
}

// ParseScript parses body once. A nil tree is reported as an error; an empty
// but valid tree is returned and handled by the extractors' text fallback.
func ParseScript(body []byte) (*ParsedScript, error) {
	parser := sitter.NewParser()
	defer parser.Close()
	if err := parser.SetLanguage(sitter.NewLanguage(javascript.Language())); err != nil {
		return nil, err
	}
	tree := parser.Parse(body, nil)
	if tree == nil {
		return nil, errors.New("parse JavaScript: no syntax tree")
	}
	return &ParsedScript{
		Body: body, tree: tree, root: tree.RootNode(), lines: newLineIndex(body),
	}, nil
}

// Close releases the syntax tree. It is safe to call more than once.
func (p *ParsedScript) Close() {
	if p == nil || p.tree == nil {
		return
	}
	p.tree.Close()
	p.tree = nil
	p.root = nil
}

func (p *ParsedScript) usable() bool {
	return p != nil && p.root != nil && p.root.NamedChildCount() > 0
}

// Analyze extracts API candidates and host candidates from the shared tree.
func (p *ParsedScript) Analyze(source *url.URL) JSAnalysis {
	if !p.usable() {
		return jsParseFallback(source, p.Body)
	}
	w := newASTWalkerWithLines(p.Body, p.lines)
	w.walk(p.root)
	w.resolveWrapperCallers(p.root)
	w.resolveAliasedCalls()
	w.resolveHeuristics()
	w.resolveTaint()
	hosts := collectHostsWithLines(source, p.Body, p.root, p.lines)
	return JSAnalysis{
		Candidates: apiCandidates(w),
		Hosts:      hosts.Candidates,
		BasePaths:  hosts.BasePaths,
		Notes:      hosts.Notes,
	}
}

// Params extracts parameter hits from the shared tree.
func (p *ParsedScript) Params(source *url.URL) []model.ParamHit {
	if !p.usable() {
		return nil
	}
	collector := &paramCollector{
		sourceURL: source, body: p.Body, lines: p.lines,
		seen: map[string]struct{}{},
	}
	collector.walk(p.root)
	return collector.hits
}

// AnalyzeBody parses once and runs both extractors over the same tree. It is
// the entry point every pipeline branch uses; the separately exported
// AnalyzeJS / ParamsFromAST remain compatible wrappers.
func AnalyzeBody(source *url.URL, body []byte) (JSAnalysis, []model.ParamHit) {
	parsed, err := ParseScript(body)
	if err != nil {
		// Matches the old behavior: a body that cannot be parsed contributes
		// nothing from either extractor.
		return JSAnalysis{}, nil
	}
	defer parsed.Close()
	return parsed.Analyze(source), parsed.Params(source)
}

// jsParseFallback handles a parse that produced no usable tree: hosts in the
// raw text are still recoverable, and the degradation is recorded once.
func jsParseFallback(source *url.URL, body []byte) JSAnalysis {
	sourceURL := ""
	if source != nil {
		sourceURL = source.String()
	}
	return JSAnalysis{
		Hosts:     HostsFromText(source, body),
		BasePaths: scanBasePathText(body, maxBasePathsPerFile),
		Notes: []extract.Note{{
			Code:    extract.NoteParseFallback,
			Message: "JavaScript 解析未产生可用语法树，主机提取退化为文本扫描。",
			URL:     sourceURL,
		}},
	}
}

// AnalyzeJS parses JavaScript with Tree-sitter once and returns both the API
// candidates and the host candidates found in the same tree, so no file is
// parsed twice.
func AnalyzeJS(source *url.URL, body []byte) JSAnalysis {
	parsed, err := ParseScript(body)
	if err != nil {
		return JSAnalysis{}
	}
	defer parsed.Close()
	return parsed.Analyze(source)
}

// APIFromAST parses JavaScript with Tree-sitter. Unlike the old parser, a
// local syntax error does not discard valid call sites elsewhere in the file.
func APIFromAST(source *url.URL, body []byte) []Candidate {
	return AnalyzeJS(source, body).Candidates
}

// newASTWalkerWithLines builds the request-oriented walker with its scope
// tables over an already-built line index.
func newASTWalkerWithLines(body []byte, lines *lineIndex) *astWalker {
	root := newEvalScope(nil, 0, true)
	return &astWalker{
		scopes:      []*evalScope{root},
		rootScope:   root,
		evalBudget:  maxEvalOps,
		appends:     map[string][]appendPair{},
		objectNodes: map[string][]objectBinding{},
		funcNodes:   map[uint32]*sitter.Node{},
		memberWrites: map[uint32]map[string][]appendPair{},
		moduleIDs:     map[uint32]string{},
		moduleParams:  map[uint32]moduleParams{},
		moduleImports: map[uint32]map[string]string{},
		moduleExports: map[string]map[string]string{},
		callTargets:   []map[string]int{{}},
		memberRoots:   []map[string]int{{}},
		delegates:     map[string]string{},
		wrappers:      map[string]wrappedCall{},
		source:        body,
		lines:         lines,
	}
}

// apiCandidates assembles the deduplicated, sorted candidate list a walker
// produced.
func apiCandidates(w *astWalker) []Candidate {
	sort.SliceStable(w.calls, func(i, j int) bool {
		if w.calls[i].Line != w.calls[j].Line {
			return w.calls[i].Line < w.calls[j].Line
		}
		return w.calls[i].Raw < w.calls[j].Raw
	})
	seen := make(map[string]struct{}, len(w.calls))
	result := make([]Candidate, 0, len(w.calls))
	for _, call := range w.calls {
		key := call.dedupKey()
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
			ContextLines: call.Context, BodyParams: call.BodyParams,
			Spec: call.Spec, Source: "ast",
		})
	}
	return result
}

type astWalker struct {
	calls []apiCall
	// scopes is the lexical-scope stack (innermost last): root file scope,
	// one scope per function and one per block. Scalar constants, object
	// constant tables and axios instance bases are all scope-bound, so a
	// same-named binding in an inner function can neither leak outward nor
	// shadow-pollute the enclosing scope's reads.
	scopes    []*evalScope
	rootScope *evalScope
	source    []byte
	// lines is the shared line index of source, so every recorded call site
	// reuses one layout instead of rebuilding it.
	lines *lineIndex
	// evalBudget bounds the total number of expression evaluations per file:
	// a hostile or enormous bundle degrades to placeholders instead of
	// stalling the scan.
	evalBudget int
	// appends collects the literal append("key", value) calls recorded per
	// builder variable during the walk. Order matters: the request call is
	// visited after the appends in source order, which holds for the usual
	// build-then-send shape; appends seen after the send are still collected
	// on a best-effort basis by a later resolve pass.
	appends map[string][]appendPair
	// objectNodes keeps object-literal binding sites (var form = {...}) so a
	// wrapper called with a variable can still resolve its fields. Bindings
	// are kept per function scope: the minifier reuses short names, so every
	// scope's version must survive.
	objectNodes map[string][]objectBinding
	// funcStack tracks enclosing function start offsets while walking, so
	// per-function scopes (member writes, bindings) stay isolated despite
	// the minifier reusing short names across the file.
	funcStack []uint32
	// funcNodes maps a function's start offset to its node, so a later pass
	// can search a call's enclosing function body again.
	funcNodes map[uint32]*sitter.Node
	// memberWrites collects o.key = value statements per function scope and
	// object name — the heuristic layer for payloads built incrementally
	// ("var o = {a:1}; o.b = 2; send(o)").
	memberWrites map[uint32]map[string][]appendPair
	// thenChains records .then/.done callbacks together with the request
	// call they chain from, so a placeholder parameter bound to the callback
	// parameter can be traced back to the upstream API.
	thenChains []thenChain
	// webpack module graph: moduleIDs maps a module function's start offset
	// to its module id ("ab8c":function(t,e,a){...}); moduleParams keeps the
	// (exports, require) parameter names per module; moduleImports maps
	// module scope → local var → imported module id; moduleExports maps
	// module id → export key → local function name. Together they let a
	// second pass resolve cross-module aliased calls like r["C"]({...}).
	moduleIDs     map[uint32]string
	moduleParams  map[uint32]moduleParams
	moduleImports map[uint32]map[string]string
	moduleExports map[string]map[string]string
	// aliasCalls records call sites whose callee is a (possibly Object-wrapped)
	// cross-module service reference, for resolution after the walk.
	aliasCalls []aliasCallSite
	// callTargets is a stack (one map per function scope) counting identifier
	// callees, so a function whose subtree calls exactly one other local
	// function can be recognized as a delegating wrapper (the async-generator
	// pattern A(t){return z.apply(...)} around the real request).
	callTargets []map[string]int
	// memberRoots is the parallel stack counting member-call root identifiers
	// (z.apply(...) roots at z) — used only when a scope has no identifier
	// callees, so A(t){return z.apply(this,arguments)} still yields the edge
	// A→z.
	memberRoots []map[string]int
	// delegates maps moduleID/funcName → the single local function it
	// delegates to; alias resolution follows these edges from an export's
	// local name down to the real request wrapper.
	delegates map[string]string
	// wrappers records wrapper functions delegating their parameter straight
	// into a request call (function P(t){...data:t...}): keyed by
	// moduleID/funcName — the minifier reuses single-letter names across the
	// bundle's 100+ modules, so the module scope must be part of the key.
	wrappers map[string]wrappedCall
}

// Analysis budgets. The evaluator is recursive and its candidate sets expand
// multiplicatively across branches, so every dimension is capped; exhausting
// a budget degrades conservatively (unknown value / dropped candidate) and
// never aborts the walk.
const (
	// maxEvalDepth bounds expression nesting per evaluation.
	maxEvalDepth = 24
	// maxEvalOptions caps how many branch candidates one value may carry;
	// a merge that would exceed it collapses to an unknown value.
	maxEvalOptions = 8
	// maxEvalOps bounds total evaluations per parsed file.
	maxEvalOps = 200000
	// maxObjectPairs caps one object constant's entry count.
	maxObjectPairs = 64
)

// jsOpt is one statically possible value of an expression.
type jsOpt struct {
	// text is the recovered string form. Unresolved fragments appear as "{}"
	// placeholders, or as "{name}" when the fragment is a named function
	// parameter (so a later pass can substitute a caller argument).
	text string
	// isNum marks a JavaScript number value; text is its ToString form used
	// only when the value is concatenated into a string.
	isNum bool
	// num is the numeric value when isNum.
	num float64
	// unknown marks a value that contains unresolved fragments and must not
	// be reported as an exact constant.
	unknown bool
}

// jsValue is the unified static-evaluation result: one expression may yield
// several options (branch merges). Zero options means "nothing known at all"
// — no structure, not even a placeholder.
type jsValue struct {
	opts []jsOpt
}

// jsUnknown reports a value with no recoverable structure.
func jsUnknown() jsValue { return jsValue{} }

// jsStr reports an exact string value.
func jsStr(text string) jsValue {
	return jsValue{opts: []jsOpt{{text: text}}}
}

// jsPlaceholder reports a value whose text carries unresolved fragments.
func jsPlaceholder(text string) jsValue {
	return jsValue{opts: []jsOpt{{text: text, unknown: true}}}
}

// jsNumber reports an exact numeric value.
func jsNumber(num float64) jsValue {
	return jsValue{opts: []jsOpt{{text: formatJSNumber(num), isNum: true, num: num}}}
}

// single returns the value's only option, or false when it has none or
// several (branch-merged) options.
func (v jsValue) single() (jsOpt, bool) {
	if len(v.opts) != 1 {
		return jsOpt{}, false
	}
	return v.opts[0], true
}

// exact reports whether the value resolves to exactly one known (non-numeric)
// string.
func (v jsValue) exactString() (string, bool) {
	opt, ok := v.single()
	if !ok || opt.unknown || opt.isNum {
		return "", false
	}
	return opt.text, true
}

// formatJSNumber renders a float64 the way JavaScript ToString would for the
// shapes static analysis actually sees: integers stay integral, everything
// else uses the shortest round-trip form.
func formatJSNumber(f float64) string {
	if f == math.Trunc(f) && !math.IsInf(f, 0) && math.Abs(f) < 1e15 {
		return strconv.FormatInt(int64(f), 10)
	}
	if math.IsNaN(f) {
		return "NaN"
	}
	if math.IsInf(f, 0) {
		return "Infinity"
	}
	return strconv.FormatFloat(f, 'g', -1, 64)
}

// evalScope is one lexical scope: the file root, a function, or a block.
// Bindings shadow strictly along the parent chain.
type evalScope struct {
	parent   *evalScope
	funcStart uint32 // 0 for the root scope
	isFunc   bool
	bindings map[string]*scopeBinding
}

// scopeBinding is one name's statically recovered facts. Every field is
// optional: a binding may be scalar-only, object-only, an axios instance
// base, a payload builder, or a declared parameter placeholder.
type scopeBinding struct {
	// opts holds the scalar's possible values. An EMPTY (non-nil) opts slice
	// marks a binding whose value was reassigned to something that cannot be
	// evaluated: the old constant is dead and reads degrade to "{}".
	opts []jsOpt
	// isParam marks a function parameter: reads yield "{name}" so a wrapper's
	// caller arguments can later be substituted for it.
	isParam bool
	// object is a constant object table (const routes = {users: "/u"}).
	object map[string]string
	// baseURL/baseKind recover an axios-style instance base.
	baseURL  string
	baseKind string
	// builder names the payload constructor bound to this name.
	builder string
}

func newEvalScope(parent *evalScope, funcStart uint32, isFunc bool) *evalScope {
	return &evalScope{parent: parent, funcStart: funcStart, isFunc: isFunc, bindings: map[string]*scopeBinding{}}
}

func (w *astWalker) pushScope(s *evalScope) { w.scopes = append(w.scopes, s) }

func (w *astWalker) popScope() { w.scopes = w.scopes[:len(w.scopes)-1] }

// currentScope returns the innermost scope; outside the walk (second passes)
// it degrades to the root scope so file-level bindings still resolve.
func (w *astWalker) currentScope() *evalScope {
	if len(w.scopes) == 0 {
		return w.rootScope
	}
	return w.scopes[len(w.scopes)-1]
}

// lookup resolves a name along the scope chain.
func (w *astWalker) lookup(name string) (*scopeBinding, *evalScope) {
	for s := w.currentScope(); s != nil; s = s.parent {
		if b, ok := s.bindings[name]; ok {
			return b, s
		}
	}
	return nil, nil
}

// functionScope returns the nearest function (or root) scope — the target for
// `var` declarations, which hoist out of blocks.
func (w *astWalker) functionScope() *evalScope {
	for s := w.currentScope(); s != nil; s = s.parent {
		if s.isFunc {
			return s
		}
	}
	return w.rootScope
}

// bindIn declares a fresh binding in the given scope.
func (w *astWalker) bindIn(scope *evalScope, name string) *scopeBinding {
	b := scope.bindings[name]
	if b == nil {
		b = &scopeBinding{}
		scope.bindings[name] = b
	}
	return b
}

// setScalar writes a scalar binding in the given scope. opts == nil keeps
// the binding (object/instance facts intact) but marks the scalar unknown.
func (w *astWalker) setScalarIn(scope *evalScope, name string, value jsValue) {
	b := w.bindIn(scope, name)
	b.opts = value.opts
}

// readScalar resolves a name to its scalar candidates. Known bindings return
// their options; parameters yield "{name}" placeholders; dead (invalidated)
// or undeclared names yield a single "{}" fragment so concatenations keep
// their known prefix/suffix structure.
func (w *astWalker) readScalar(name string) jsValue {
	b, _ := w.lookup(name)
	if b == nil {
		return jsPlaceholder("{}")
	}
	if b.isParam {
		return jsPlaceholder("{" + name + "}")
	}
	if len(b.opts) == 0 {
		return jsPlaceholder("{}")
	}
	return jsValue{opts: b.opts}
}

// assignmentIsConditional reports whether an assignment node sits inside a
// branch (if/else, loop, switch case, try/catch, ternary, short-circuit
// logical operator). Such writes are possible values, not certain ones: the
// binding merges candidates instead of overwriting. The climb stops at the
// top-level statement list of the file or of a function body — a bare block
// between here and there does not make the write conditional, but a branch
// body does.
func (w *astWalker) assignmentIsConditional(n *sitter.Node) bool {
	conditional := map[string]bool{
		"if_statement": true, "else_clause": true,
		"for_statement": true, "for_in_statement": true,
		"while_statement": true, "do_statement": true,
		"switch_case": true, "switch_default": true,
		"try_statement": true, "catch_clause": true, "finally_clause": true,
		"conditional_expression": true, "ternary_expression": true,
		"binary_expression": true,
	}
	for p := n.Parent(); p != nil; p = p.Parent() {
		if conditional[p.Kind()] {
			return true
		}
		parent := p.Parent()
		if parent == nil {
			return false
		}
		switch parent.Kind() {
		case "program", "function_declaration", "function", "function_expression",
			"generator_function_declaration", "generator_function", "arrow_function",
			"method_definition":
			return false
		}
	}
	return false
}

// writeTargetScope resolves the scope a scalar assignment should land in.
// A write from inside a function body to a binding outside that function
// returns nil: the body is analyzed at declaration time while its execution
// happens at call time in unknown order, so it must not mutate the outer
// binding's state. Writes inside the same function (including its blocks)
// land on the binding's own scope.
func (w *astWalker) writeTargetScope(name string) *evalScope {
	b, scope := w.lookup(name)
	if b == nil {
		return w.currentScope()
	}
	for s := w.currentScope(); s != nil && s != scope; s = s.parent {
		if s.isFunc {
			return nil
		}
	}
	return scope
}

// thenChain links a response callback's function start offset to the call
// whose response feeds it.
type thenChain struct {
	funcStart uint32
	upstream  *sitter.Node // the request call expression chained with .then
}

// moduleParams holds the webpack module signature names: the second
// parameter is the exports object, the third the require function.
type moduleParams struct {
	exports string
	require string
}

// aliasCallSite is one call whose callee is a cross-module service reference
// (r["C"](...) or the Object(r["C"])(...) wrapper form). scopes snapshots the
// enclosing function stack innermost-first: import bindings live at module
// scope, the call may sit several functions deeper.
type aliasCallSite struct {
	node   *sitter.Node
	scopes []uint32
}

type appendPair struct {
	key   string
	value *sitter.Node
}

// objectBinding is one object-literal binding of a name within one function
// scope (0 = file scope).
type objectBinding struct {
	funcStart uint32
	node      *sitter.Node
}

type wrappedCall struct {
	Raw, Method, Evidence string
	Line, Column          int
	// ModuleID scopes the wrapper's name: the same minified function name
	// exists in many webpack modules.
	ModuleID string
	// MemberPath is the property suffix when the wrapper forwards a MEMBER
	// of its parameter (function R(t){...data:t.ManageOrderParamDTO...}):
	// caller arguments must be navigated down this path to reach the object
	// whose keys are the real body fields.
	MemberPath string
	// HasPayload marks wrappers that forward their own parameter into the
	// request body (function P(t){...data:t...}) — only these produce
	// caller-side parameter variants. No-payload wrappers (function
	// load(){...GET without data...}) register too, but solely so promise
	// chains can resolve their URL.
	HasPayload bool
	// ParamNames lists the wrapper's declared parameters in order, and
	// URLParams the subset whose "{name}" placeholder appears in Raw — the
	// URL depends on the caller's argument, so a reliably-recognized direct
	// call substitutes the argument for the placeholder.
	ParamNames []string
	URLParams  []string
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
		w.recordModuleImport(n, unwrap(n.ChildByFieldName("name")), unwrap(n.ChildByFieldName("value")))
	case "assignment_expression":
		w.bindAssignment(n.ChildByFieldName("left"), n.ChildByFieldName("right"))
		w.recordMemberWrite(n)
		w.recordModuleImport(n, unwrap(n.ChildByFieldName("left")), unwrap(n.ChildByFieldName("right")))
	case "call_expression":
		w.visitCall(n)
	case "new_expression":
		w.visitNewExpression(n)
	case "function_declaration", "function", "function_expression",
		"generator_function_declaration", "generator_function", "arrow_function":
		// Per-function scopes: member writes, bindings and the eval scope
		// collected inside this subtree belong to this function only.
		start := uint32(n.StartByte())
		w.funcStack = append(w.funcStack, start)
		w.funcNodes[start] = n
		w.callTargets = append(w.callTargets, map[string]int{})
		w.memberRoots = append(w.memberRoots, map[string]int{})
		w.pushScope(newEvalScope(w.currentScope(), start, true))
		w.bindFunctionParams(n)
		w.detectWebpackModule(n, start)
		for i := uint(0); i < n.NamedChildCount(); i++ {
			w.walk(n.NamedChild(i))
		}
		w.recordDelegation(n, start)
		w.popScope()
		w.funcStack = w.funcStack[:len(w.funcStack)-1]
		w.callTargets = w.callTargets[:len(w.callTargets)-1]
		w.memberRoots = w.memberRoots[:len(w.memberRoots)-1]
		return
	case "statement_block":
		// Every block is a scope, so a `let`/`const` declared inside it can
		// shadow the enclosing binding without ever leaking back out.
		w.pushScope(newEvalScope(w.currentScope(), w.currentFunc(), false))
		for i := uint(0); i < n.NamedChildCount(); i++ {
			w.walk(n.NamedChild(i))
		}
		w.popScope()
		return
	}
	// ERROR nodes are named nodes too. Walking through them is intentional:
	// valid descendants in malformed or truncated bundles remain recoverable.
	for i := uint(0); i < n.NamedChildCount(); i++ {
		w.walk(n.NamedChild(i))
	}
}

// recordMemberWrite captures `o.key = value` statements — the heuristic
// layer's key sources for payloads assembled incrementally. Only literal
// property names count; computed keys are runtime decisions.
func (w *astWalker) recordMemberWrite(n *sitter.Node) {
	if len(w.funcStack) == 0 {
		return
	}
	left := unwrap(n.ChildByFieldName("left"))
	right := unwrap(n.ChildByFieldName("right"))
	if left == nil || left.Kind() != "member_expression" {
		return
	}
	object := unwrap(left.ChildByFieldName("object"))
	property := unwrap(left.ChildByFieldName("property"))
	if object == nil || object.Kind() != "identifier" || property == nil {
		return
	}
	if property.Kind() != "property_identifier" {
		return
	}
	funcStart := w.funcStack[len(w.funcStack)-1]
	scope := w.memberWrites[funcStart]
	if scope == nil {
		scope = map[string][]appendPair{}
		w.memberWrites[funcStart] = scope
	}
	name := w.text(object)
	scope[name] = append(scope[name], appendPair{key: w.text(property), value: right})
}

// detectWebpackModule recognises webpack module entries — the shape
// "moduleId":function(module, exports, require){...} — and records the
// module id plus its exports/require parameter names, so imports and
// exports inside this scope can be attributed.
func (w *astWalker) detectWebpackModule(fn *sitter.Node, start uint32) {
	parent := fn.Parent()
	if parent == nil || parent.Kind() != "pair" {
		return
	}
	keyNode := unwrap(parent.ChildByFieldName("key"))
	if keyNode == nil {
		return
	}
	// Module keys appear both quoted ("ab8c":) and bare (c24f:) depending
	// on whether the id is numeric.
	var moduleID string
	switch keyNode.Kind() {
	case "string":
		moduleID = decodeJSString(w.text(keyNode))
	case "property_identifier", "number":
		moduleID = w.text(keyNode)
	default:
		return
	}
	if moduleID == "" {
		return
	}
	w.moduleIDs[start] = moduleID
	var params moduleParams
	if signature := unwrap(fn.ChildByFieldName("parameters")); signature != nil && signature.NamedChildCount() >= 3 {
		params.exports = w.text(unwrap(signature.NamedChild(1)))
		params.require = w.text(unwrap(signature.NamedChild(2)))
	}
	w.moduleParams[start] = params
}

// recordModuleImport captures webpack require bindings inside a module —
// `var r = a("ab8c")` but also the minified sequence form
// `r = (a("x"),a("y"),a("c24f"))` where side-effect calls precede the real
// import and the LAST call is the binding value.
func (w *astWalker) recordModuleImport(n *sitter.Node, name, value *sitter.Node) {
	if len(w.funcStack) == 0 {
		return
	}
	funcStart := w.currentFunc()
	params, isModule := w.moduleParams[funcStart]
	if !isModule || params.require == "" {
		return
	}
	if name == nil || name.Kind() != "identifier" || value == nil {
		return
	}
	// Reduce the binding value to the effective require call: unwrap
	// parentheses; in a sequence the last expression is the value.
	value = unwrap(value)
	if value.Kind() == "sequence_expression" {
		children := value.NamedChildCount()
		if children == 0 {
			return
		}
		value = unwrap(value.NamedChild(children - 1))
	}
	if value == nil || value.Kind() != "call_expression" {
		return
	}
	callee := unwrap(value.ChildByFieldName("function"))
	if callee == nil || callee.Kind() != "identifier" || w.text(callee) != params.require {
		return
	}
	args := w.arguments(value)
	if len(args) == 0 || kind(unwrap(args[0])) != "string" {
		return
	}
	target := decodeJSString(w.text(unwrap(args[0])))
	if target == "" {
		return
	}
	if w.moduleImports[funcStart] == nil {
		w.moduleImports[funcStart] = map[string]string{}
	}
	w.moduleImports[funcStart][w.text(name)] = target
}

// maybeRecordAliasCall saves call sites whose callee is a cross-module
// service reference — r["C"](...), r.C(...), or the Object(r["C"])(...)
// wrapper form — for resolution once the module graph is complete.
func (w *astWalker) maybeRecordAliasCall(call, callee *sitter.Node) {
	if len(w.funcStack) == 0 {
		return
	}
	if _, _, _, ok := w.aliasRef(callee); ok {
		scopes := make([]uint32, len(w.funcStack))
		copy(scopes, w.funcStack)
		w.aliasCalls = append(w.aliasCalls, aliasCallSite{node: call, scopes: scopes})
	}
}

// aliasRef decomposes a callee into (localVar, exportKey, scopeFunc, ok)
// when it references an import: r["KEY"], r.KEY, or Object(r["KEY"]).
func (w *astWalker) aliasRef(callee *sitter.Node) (string, string, uint32, bool) {
	callee = unwrap(callee)
	if callee == nil {
		return "", "", 0, false
	}
	switch callee.Kind() {
	case "subscript_expression":
		object := unwrap(callee.ChildByFieldName("object"))
		property := unwrap(callee.ChildByFieldName("index"))
		if object == nil || object.Kind() != "identifier" || property == nil || property.Kind() != "string" {
			return "", "", 0, false
		}
		key := decodeJSString(w.text(property))
		if key == "" {
			return "", "", 0, false
		}
		return w.text(object), key, w.currentFunc(), true
	case "member_expression":
		object := unwrap(callee.ChildByFieldName("object"))
		property := unwrap(callee.ChildByFieldName("property"))
		if object == nil || object.Kind() != "identifier" || property == nil || property.Kind() != "property_identifier" {
			return "", "", 0, false
		}
		return w.text(object), w.text(property), w.currentFunc(), true
	case "call_expression":
		// Object(r["C"]) — unwrap the Object() wrapper and retry.
		inner := unwrap(callee.ChildByFieldName("function"))
		args := w.arguments(callee)
		if inner != nil && inner.Kind() == "identifier" && w.text(inner) == "Object" && len(args) == 1 {
			return w.aliasRef(unwrap(args[0]))
		}
	}
	return "", "", 0, false
}

// returnIdentifier extracts the local name a webpack export shim returns:
// function(){return C} → "C".
func (w *astWalker) returnIdentifier(fn *sitter.Node) string {
	var name string
	var search func(n *sitter.Node)
	search = func(n *sitter.Node) {
		if n == nil || name != "" {
			return
		}
		if n.Kind() == "return_statement" && n.NamedChildCount() > 0 {
			value := unwrap(n.NamedChild(0))
			if value != nil && value.Kind() == "identifier" {
				name = w.text(value)
			}
			return
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			search(n.NamedChild(i))
		}
	}
	search(fn)
	return name
}

// resolveAliasedCalls runs after the walk, when the module graph and wrapper
// table are complete: every recorded cross-module call whose target resolves
// to a payload-forwarding wrapper contributes the caller's argument literal
// — the service module's keys live here, one import hop away from the
// request. Callers whose argument cannot be reduced to an object literal
// instead donate their context lines to the placeholder record, feeding both
// the report and the AI evidence pack.
func (w *astWalker) resolveAliasedCalls() {
	for _, site := range w.aliasCalls {
		callee := unwrap(site.node.ChildByFieldName("function"))
		if callee == nil {
			continue
		}
		localVar, exportKey, _, ok := w.aliasRef(callee)
		if !ok {
			continue
		}
		targetModule := ""
		for _, scope := range site.scopes { // innermost → outermost
			if imported := w.moduleImports[scope][localVar]; imported != "" {
				targetModule = imported
				break
			}
		}
		if targetModule == "" {
			continue
		}
		localName := w.moduleExports[targetModule][exportKey]
		if localName == "" {
			continue
		}
		// The export's local may be a delegating async-generator wrapper;
		// follow the chain down to the real request wrapper.
		wrapped, ok := w.followDelegation(targetModule, localName)
		if !ok {
			continue
		}
		args := w.arguments(site.node)
		payload := w.resolveCallerPayload(wrapped, args, site.scopes)
		if payload != nil {
			w.recordCall(callee, wrapped.Raw, wrapped.Method, []*sitter.Node{payload}, 0)
		} else {
			w.appendCallerContext(wrapped, callee)
		}
	}
}

// resolveCallerPayload reduces a wrapper caller's first argument to an
// object-literal node, navigating the wrapper's member path when it forwards
// a field of an aggregate argument. nil when the argument is not (or not yet)
// statically resolvable.
func (w *astWalker) resolveCallerPayload(wrapped wrappedCall, args []*sitter.Node, callerScopes []uint32) *sitter.Node {
	if !wrapped.HasPayload || len(args) == 0 {
		return nil
	}
	first := unwrap(args[0])
	if kind(first) == "identifier" {
		// Binding scope must match one of the caller's enclosing functions
		// (or be file scope): the minifier reuses names across functions.
		for _, binding := range w.objectNodes[w.text(first)] {
			for _, scope := range callerScopes {
				if binding.funcStart == scope || binding.funcStart == 0 {
					first = binding.node
					break
				}
			}
		}
	}
	if kind(first) != "object" {
		return nil
	}
	if wrapped.MemberPath != "" {
		if navigated := w.navigateMemberPath(first, wrapped.MemberPath); navigated != nil {
			return navigated
		}
		return nil
	}
	return first
}

// appendCallerContext donates a cross-module caller's source line to the
// placeholder record of the wrapped request, so the report and the AI
// evidence pack can see where the payload object is actually built.
func (w *astWalker) appendCallerContext(wrapped wrappedCall, callee *sitter.Node) {
	ctx := w.lines.extract(int(callee.StartByte()), contextSpanLines, wrapped.Raw)
	for i := len(w.calls) - 1; i >= 0; i-- {
		record := &w.calls[i]
		if record.Raw != wrapped.Raw || record.Spec == nil {
			continue
		}
		hasPlaceholder := false
		for _, param := range record.Spec.Body {
			if param.Key == "" && param.Evidence == model.EvidencePlaceholder {
				hasPlaceholder = true
				break
			}
		}
		if !hasPlaceholder {
			continue
		}
		for _, contextLine := range ctx {
			duplicate := false
			for _, existing := range record.Context {
				if existing.LineNumber == contextLine.LineNumber && existing.Content == contextLine.Content {
					duplicate = true
					break
				}
			}
			if !duplicate {
				record.Context = append(record.Context, contextLine)
			}
		}
		return
	}
}

// recordDelegation records a delegation edge when the finished function's
// subtree calls exactly one other local function — the minified
// async-generator wrapper pattern (function A(t){...z...P(e)...}) that sits
// between a webpack export and the real request wrapper.
func (w *astWalker) recordDelegation(fn *sitter.Node, start uint32) {
	if len(w.callTargets) == 0 {
		return
	}
	targets := w.callTargets[len(w.callTargets)-1]
	nameNode := fn.ChildByFieldName("name")
	if nameNode == nil {
		return
	}
	fnName := w.text(nameNode)
	var target string
	if len(targets) == 1 {
		for candidate := range targets {
			if candidate != fnName {
				target = candidate
			}
		}
	} else if len(targets) == 0 {
		// No identifier callees: a lone member call (z.apply(this, ...))
		// still names the delegate through its root identifier.
		roots := w.memberRoots[len(w.memberRoots)-1]
		if len(roots) == 1 {
			for candidate := range roots {
				if candidate != fnName {
					target = candidate
				}
			}
		}
	}
	if target == "" {
		return
	}
	moduleID := w.moduleScopeOfNode(fn)
	if moduleID == "" {
		// Fall back to the enclosing scope chain (the function may sit inside
		// a variable-bound generator whose module is an ancestor).
		for i := len(w.funcStack) - 1; i >= 0; i-- {
			if id := w.moduleIDs[w.funcStack[i]]; id != "" {
				moduleID = id
				break
			}
		}
	}
	if moduleID == "" {
		return
	}
	w.delegates[moduleID+"/"+fnName] = target
}

// followDelegation walks delegation edges from an export's local name until a
// registered wrapper (or the hop limit) is reached.
func (w *astWalker) followDelegation(moduleID, localName string) (wrappedCall, bool) {
	visited := map[string]bool{}
	current := localName
	for hop := 0; hop < 6; hop++ {
		key := moduleID + "/" + current
		if visited[key] {
			break
		}
		visited[key] = true
		if wrapped, ok := w.wrappers[key]; ok {
			return wrapped, true
		}
		next, ok := w.delegates[key]
		if !ok {
			break
		}
		current = next
	}
	return wrappedCall{}, false
}

// countIdentifierCallees counts distinct identifier callees in a subtree
// (excluding the Object wrapper call), for single-target delegation edges.
func (w *astWalker) countIdentifierCallees(root *sitter.Node) map[string]int {
	targets := map[string]int{}
	var search func(n *sitter.Node)
	search = func(n *sitter.Node) {
		if n == nil {
			return
		}
		if n.Kind() == "call_expression" {
			if callee := unwrap(n.ChildByFieldName("function")); callee != nil && callee.Kind() == "identifier" {
				name := w.text(callee)
				if name != "Object" {
					targets[name]++
				}
			}
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			search(n.NamedChild(i))
		}
	}
	search(root)
	return targets
}

// currentModuleID resolves the module id of the current function scope.
func (w *astWalker) currentModuleID() string {
	for i := len(w.funcStack) - 1; i >= 0; i-- {
		if id := w.moduleIDs[w.funcStack[i]]; id != "" {
			return id
		}
	}
	return ""
}

// currentFunc returns the start offset of the enclosing function, or 0 at
// file scope.
func (w *astWalker) currentFunc() uint32 {
	if len(w.funcStack) == 0 {
		return 0
	}
	return w.funcStack[len(w.funcStack)-1]
}

// bindFunctionParams pre-binds a function's declared parameters in its fresh
// scope, so any use inside the body resolves to the parameter placeholder
// "{name}" instead of an outer same-named constant (parameter shadowing).
// Destructuring, default-value and rest parameters stay unknown fragments.
func (w *astWalker) bindFunctionParams(fn *sitter.Node) {
	parameters := unwrap(fn.ChildByFieldName("parameters"))
	if parameters == nil {
		return
	}
	scope := w.currentScope()
	bindOne := func(n *sitter.Node) {
		n = unwrap(n)
		if n != nil && n.Kind() == "identifier" {
			b := w.bindIn(scope, w.text(n))
			b.isParam = true
		}
	}
	if parameters.Kind() == "identifier" {
		// Arrow function with a single unparenthesized parameter.
		bindOne(parameters)
		return
	}
	for i := uint(0); i < parameters.NamedChildCount(); i++ {
		bindOne(parameters.NamedChild(i))
	}
}

func (w *astWalker) bind(nameNode, value *sitter.Node) {
	nameNode, value = unwrap(nameNode), unwrap(value)
	if nameNode == nil || nameNode.Kind() != "identifier" || value == nil {
		return
	}
	name := w.text(nameNode)
	if base, baseKind, ok := w.axiosCreateBase(value); ok {
		b := w.bindIn(w.currentScope(), name)
		b.baseURL, b.baseKind = base, baseKind
		return
	}
	if value.Kind() == "object" {
		w.objectNodes[name] = append(w.objectNodes[name],
			objectBinding{funcStart: w.currentFunc(), node: value})
	}
	// `var` hoists to the nearest function scope; `let`/`const` stay in the
	// current block scope.
	scope := w.currentScope()
	if declarator := nameNode.Parent(); declarator != nil && kind(unwrap(declarator.Parent())) == "variable_declaration" {
		scope = w.functionScope()
	}
	w.bindValueIn(scope, name, value)
}

// bindValue records a declaration value for later constant propagation. All
// shapes share the one evaluator: plain strings, alias identifiers,
// concatenations, templates with known substitutions, ternary branches and
// folded URL constructor calls. An object literal of resolvable pairs also
// becomes a constant table, and URLSearchParams/FormData bindings register
// their append chains.
func (w *astWalker) bindValue(name string, value *sitter.Node) {
	w.bindValueIn(w.currentScope(), name, value)
}

func (w *astWalker) bindValueIn(scope *evalScope, name string, value *sitter.Node) {
	b := w.bindIn(scope, name)
	if value.Kind() == "new_expression" {
		// Payload builders: a variable bound to URLSearchParams or FormData
		// carries its field keys in later .append("key", value) calls.
		if constructor := unwrap(value.ChildByFieldName("constructor")); constructor != nil {
			switch w.text(constructor) {
			case "URLSearchParams", "FormData":
				b.builder = w.text(constructor)
			}
		}
	}
	v := w.evalExpr(value, w.currentScope(), 0)
	b.opts = v.opts
	if value.Kind() == "object" {
		w.bindObjectTable(b, value)
	}
}

// bindObjectTable records an object literal's resolvable key/value pairs as a
// constant table, so `routes.users` and `routes["orders"]` resolve like any
// other expression. Values must reduce to exactly one known string; anything
// dynamic stays out of the table rather than being guessed.
func (w *astWalker) bindObjectTable(b *scopeBinding, value *sitter.Node) {
	table := make(map[string]string)
	for i := uint(0); i < value.NamedChildCount() && len(table) < maxObjectPairs; i++ {
		pair := value.NamedChild(i)
		if pair.Kind() != "pair" {
			continue
		}
		keyNode := pair.ChildByFieldName("key")
		if kind(unwrap(keyNode)) == "computed_property_name" {
			continue
		}
		key := w.propertyName(keyNode)
		text, ok := w.evalExpr(pair.ChildByFieldName("value"), w.currentScope(), 0).exactString()
		if key == "" || !ok {
			continue
		}
		table[key] = text
	}
	if len(table) > 0 {
		b.object = table
	}
}

func (w *astWalker) bindAssignment(left, right *sitter.Node) {
	left, right = unwrap(left), unwrap(right)
	if left == nil || right == nil {
		return
	}
	if left.Kind() == "identifier" {
		name := w.text(left)
		if base, baseKind, ok := w.axiosCreateBase(right); ok {
			if target := w.writeTargetScope(name); target != nil {
				b := w.bindIn(target, name)
				b.baseURL, b.baseKind = base, baseKind
			}
		} else if target := w.writeTargetScope(name); target != nil {
			v := w.evalExpr(right, w.currentScope(), 0)
			if w.assignmentIsConditional(left) {
				// A branch write is a possible value, not a certain one:
				// merge it with what the binding already holds. When the
				// merge cannot be represented within the candidate budget,
				// the value degrades to unknown instead of picking a winner.
				w.mergeBranchWrite(target, name, v)
			} else {
				// Straight-line write: the new value replaces the old one,
				// and an unevaluable right side invalidates the old constant
				// so stale history is never reused.
				w.setScalarIn(target, name, v)
			}
		}
	}
	if name, ok := w.baseURLTarget(left); ok {
		base, baseKind := w.baseURLFromExpression(right)
		if base != "" {
			b, _ := w.lookup(name)
			if b == nil {
				b = w.bindIn(w.currentScope(), name)
			}
			b.baseURL, b.baseKind = base, baseKind
		}
	}
}

// mergeBranchWrite unions a conditional assignment's candidates into the
// binding's existing value set. A side with no evaluable value (an unknown
// prior value, or an unknown branch assignment) contributes a "{}" option so
// the uncertainty survives the merge.
func (w *astWalker) mergeBranchWrite(scope *evalScope, name string, v jsValue) {
	b := w.bindIn(scope, name)
	merged := make([]jsOpt, 0, len(b.opts)+len(v.opts)+1)
	if len(b.opts) > 0 {
		merged = append(merged, b.opts...)
	} else {
		merged = append(merged, jsOpt{text: "{}", unknown: true})
	}
	if len(v.opts) > 0 {
		merged = append(merged, v.opts...)
	} else {
		merged = append(merged, jsOpt{text: "{}", unknown: true})
	}
	b.opts = capped(jsValue{opts: merged}).opts
}

// capped bounds a value's candidate set: a merge that exceeds the budget
// degrades to a fully unknown value rather than reporting an arbitrary
// subset as the truth.
func capped(v jsValue) jsValue {
	if len(v.opts) <= maxEvalOptions {
		return v
	}
	return jsUnknown()
}

func (w *astWalker) visitCall(call *sitter.Node) {
	callee := unwrap(call.ChildByFieldName("function"))
	args := w.arguments(call)
	if callee == nil {
		return
	}
	method, urlArg, bodyArg := "", -1, -1
	var urlOverride *sitter.Node
	w.maybeRecordAliasCall(call, callee)
	if callee.Kind() == "identifier" && len(w.callTargets) > 0 {
		name := w.text(callee)
		if name != "Object" {
			w.callTargets[len(w.callTargets)-1][name]++
		}
	}
	if callee.Kind() == "member_expression" && len(w.memberRoots) > 0 {
		if root := unwrap(callee.ChildByFieldName("object")); root != nil && root.Kind() == "identifier" {
			w.memberRoots[len(w.memberRoots)-1][w.text(root)]++
		}
	}

	if object, property, ok := w.memberParts(callee); ok {
		receiver := w.outermostIdentifier(object)
		// Builder append chains: e.append("key", value) on a variable bound
		// to URLSearchParams/FormData records one request field. Only literal
		// keys count — a computed key is a runtime decision, not a field name.
		if property == "append" && kind(unwrap(object)) == "identifier" && w.builderFor(w.text(unwrap(object))) != "" {
			if len(args) >= 1 && kind(unwrap(args[0])) == "string" {
				key := decodeJSString(w.text(unwrap(args[0])))
				var value *sitter.Node
				if len(args) >= 2 {
					value = args[1]
				}
				name := w.text(unwrap(object))
				w.appends[name] = append(w.appends[name], appendPair{key: key, value: value})
			}
		}
		// Webpack export registration: a.d(e, "KEY", function(){return local})
		// inside a module scope builds the module's export table.
		if property == "d" && len(args) >= 3 {
			// webpack semantics: require.d(exports, "KEY", getter) — the
			// callee's object is the require function parameter.
			if moduleID := w.moduleIDs[w.currentFunc()]; moduleID != "" {
				if params, ok := w.moduleParams[w.currentFunc()]; ok &&
					kind(unwrap(object)) == "identifier" && w.text(unwrap(object)) == params.require {
					keyNode := unwrap(args[1])
					fnNode := unwrap(args[2])
					if keyNode != nil && keyNode.Kind() == "string" && fnNode != nil {
						if local := w.returnIdentifier(fnNode); local != "" {
							if w.moduleExports[moduleID] == nil {
								w.moduleExports[moduleID] = map[string]string{}
							}
							w.moduleExports[moduleID][decodeJSString(w.text(keyNode))] = local
						}
					}
				}
			}
		}
		// Promise chains: obj.then(function(res){...}) links the callback's
		// function scope to the upstream request call, so a request issued
		// inside the callback can be traced back to that upstream API.
		if (property == "then" || property == "done" || property == "always") && len(args) > 0 {
			for _, arg := range args {
				arg = unwrap(arg)
				if kind(arg) == "function" || kind(arg) == "function_expression" ||
					kind(arg) == "arrow_function" || kind(arg) == "generator_function" {
					w.thenChains = append(w.thenChains, thenChain{
						funcStart: uint32(arg.StartByte()),
						upstream:  call,
					})
					break
				}
			}
		}
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
	// Both branches of a conditional URL are plausible request targets, so
	// the resolved values are reported as separate candidates.
	for _, raw := range w.resolveURLExpressions(urlNode) {
		w.recordCall(callee, raw, method, args, bodyArg)
	}
}

// instanceBase returns the axios-style base URL recovered for a receiver
// name, resolved through the scope chain (root scope outside the walk).
func (w *astWalker) instanceBase(receiver string) (string, string) {
	if receiver == "" {
		return "", ""
	}
	if b, _ := w.lookup(receiver); b != nil {
		return b.baseURL, b.baseKind
	}
	return "", ""
}

// builderFor returns the payload constructor ("URLSearchParams"/"FormData")
// a name was bound to, resolved through the scope chain.
func (w *astWalker) builderFor(name string) string {
	if b, _ := w.lookup(name); b != nil {
		return b.builder
	}
	return ""
}

// recordCall turns one resolved URL value into a recorded API call with
// evidence, context and the request spec derived from the call arguments.
func (w *astWalker) recordCall(
	callee *sitter.Node,
	raw string,
	method string,
	args []*sitter.Node,
	bodyArg int,
) {
	evidence := evidenceFor(raw)
	// A call like map.get("ArrowDown") matches the generic HTTP-verb branch;
	// only path-shaped values are real request targets.
	if !looksLikePath(raw) {
		return
	}
	point := callee.StartPosition()
	line, column := int(point.Row)+1, int(point.Column)+1
	ctx := w.lines.extract(int(callee.StartByte()), contextSpanLines, raw)
	spec := w.buildSpec(args, bodyArg)
	// Stamp the recovered base URL before either candidate is recorded: both
	// the raw path and the joined full URL should carry it for the report.
	if object, _, ok := w.memberParts(callee); ok && evidence == model.EvidenceStatic {
		receiver := w.outermostIdentifier(object)
		if base, baseKind := w.instanceBase(receiver); base != "" {
			if spec == nil {
				// Even a bare call deserves a spec: the recovered base URL
				// with its confidence is information on its own.
				spec = &model.RequestSpec{}
			}
			if spec.BaseURL == "" {
				spec.BaseURL = base
				spec.BaseURLKind = baseKind
			}
		}
	}
	params := spec.ParamKeys()
	w.calls = append(w.calls, apiCall{raw, method, evidence, line, column, ctx, params, spec, w.currentFunc()})
	// The same call may be the body of a wrapper delegating its own
	// parameter (function P(t){...data:t...}); recording that mapping lets a
	// second pass resolve caller-side argument literals into field keys.
	w.recordWrapper(callee, raw, method, args, bodyArg, line, column)
	if object, _, ok := w.memberParts(callee); ok && evidence == model.EvidenceStatic {
		receiver := w.outermostIdentifier(object)
		if base, _ := w.instanceBase(receiver); base != "" {
			if joined := joinBaseURL(base, raw); joined != "" {
				w.calls = append(w.calls, apiCall{joined, method, model.EvidenceFullURL, line, column, ctx, params, spec, w.currentFunc()})
			}
		}
	}
}

// recordWrapper marks the enclosing named function as a request wrapper when
// the call's payload is exactly one of that function's declared parameters —
// the service-layer shape `function P(t){ return request({url, data:t}) }`.
// Anonymous or single-letter lowercase functions (minified locals such as
// `t(e)`) are skipped: their names collide across the bundle and would
// resolve unrelated call sites.
func (w *astWalker) recordWrapper(callee *sitter.Node, raw, method string, args []*sitter.Node, bodyArg int, line, column int) {
	fn, fnName := w.enclosingNamedFunction(callee)
	if fn == nil {
		return
	}
	moduleID := w.moduleScopeOfNode(fn)
	key := moduleID + "/" + fnName
	if _, exists := w.wrappers[key]; exists {
		return
	}
	wrapped := wrappedCall{Raw: raw, Method: method, Line: line, Column: column, ModuleID: moduleID}
	wrapped.ParamNames = w.declaredParamNames(fn)
	wrapped.URLParams = w.urlParamsIn(raw, wrapped.ParamNames)
	payloads := w.payloadNodesFor(args, bodyArg)
	if len(payloads) == 0 {
		// No payload slot: still a nameable request wrapper, but callers
		// cannot contribute parameters to it.
		w.wrappers[key] = wrapped
		return
	}
	for _, payload := range payloads {
		node := unwrap(payload.node)
		// Two forwardable shapes: data:t (identifier) and
		// data:t.SomeDTO (member rooted at the parameter — service
		// functions often pick one DTO field out of an aggregate arg).
		sym, memberPath := "", ""
		switch kind(node) {
		case "identifier":
			sym = w.text(node)
		case "member_expression":
			root := unwrap(node.ChildByFieldName("object"))
			if root == nil || root.Kind() != "identifier" {
				continue
			}
			sym = w.text(root)
			memberPath = w.memberPathOf(node)
		default:
			continue
		}
		if !w.declaredParam(fn, sym) {
			continue
		}
		wrapped.HasPayload = true
		wrapped.MemberPath = memberPath
		w.wrappers[key] = wrapped
		return
	}
	// No payload forwarding confirmed — still register the wrapper so
	// promise chains and URL-parameter substitution can resolve through it.
	w.wrappers[key] = wrapped
}

// declaredParamNames lists a function's plain identifier parameters in
// declaration order.
func (w *astWalker) declaredParamNames(fn *sitter.Node) []string {
	parameters := unwrap(fn.ChildByFieldName("parameters"))
	if parameters == nil {
		return nil
	}
	if parameters.Kind() == "identifier" {
		return []string{w.text(parameters)}
	}
	var names []string
	for i := uint(0); i < parameters.NamedChildCount(); i++ {
		if param := unwrap(parameters.NamedChild(i)); param != nil && param.Kind() == "identifier" {
			names = append(names, w.text(param))
		}
	}
	return names
}

// urlParamsIn returns the placeholder names of the form "{name}" that appear
// in raw and match one of the given parameter names.
func (w *astWalker) urlParamsIn(raw string, paramNames []string) []string {
	if raw == "" || len(paramNames) == 0 {
		return nil
	}
	var out []string
	for _, name := range paramNames {
		if name != "" && strings.Contains(raw, "{"+name+"}") {
			out = append(out, name)
		}
	}
	return out
}

// moduleScopeOfNode climbs from a node to the nearest enclosing webpack
// module's id ("" when the node lives outside any detected module).
func (w *astWalker) moduleScopeOfNode(node *sitter.Node) string {
	for p := node; p != nil; p = p.Parent() {
		if id := w.moduleIDs[uint32(p.StartByte())]; id != "" {
			return id
		}
	}
	return ""
}

// memberPathOf flattens a member/subscript chain into dot-separated literal
// property names ("ManageOrderParamDTO", "a.b"); any computed segment
// disqualifies the path.
func (w *astWalker) memberPathOf(node *sitter.Node) string {
	var parts []string
	cur := unwrap(node)
	for cur != nil {
		switch cur.Kind() {
		case "member_expression":
			property := unwrap(cur.ChildByFieldName("property"))
			if property == nil {
				return ""
			}
			if property.Kind() == "property_identifier" {
				parts = append([]string{w.text(property)}, parts...)
			} else if property.Kind() == "string" {
				parts = append([]string{decodeJSString(w.text(property))}, parts...)
			} else {
				return ""
			}
			cur = unwrap(cur.ChildByFieldName("object"))
		case "identifier":
			return strings.Join(parts, ".")
		default:
			return ""
		}
	}
	return strings.Join(parts, ".")
}

// navigateMemberPath walks an object-literal node down a dot path, returning
// the value node of the final segment (nil when any segment is missing or
// computed).
func (w *astWalker) navigateMemberPath(object *sitter.Node, path string) *sitter.Node {
	cur := unwrap(object)
	for _, segment := range strings.Split(path, ".") {
		if segment == "" || cur == nil || cur.Kind() != "object" {
			return nil
		}
		var next *sitter.Node
		for i := uint(0); i < cur.NamedChildCount(); i++ {
			pair := cur.NamedChild(i)
			if pair.Kind() != "pair" {
				continue
			}
			if w.propertyName(pair.ChildByFieldName("key")) == segment {
				next = unwrap(pair.ChildByFieldName("value"))
				break
			}
		}
		cur = next
	}
	return cur
}

// enclosingNamedFunction climbs from a node to the nearest named function
// declaration. Anonymous functions return nil — they cannot be invoked by
// name, so their parameter mapping is unreachable from caller sites.
func (w *astWalker) enclosingNamedFunction(from *sitter.Node) (*sitter.Node, string) {
	for p := from.Parent(); p != nil; p = p.Parent() {
		switch p.Kind() {
		case "function_declaration", "function", "generator_function_declaration", "generator_function":
			nameNode := p.ChildByFieldName("name")
			if nameNode == nil {
				return nil, ""
			}
			name := w.text(nameNode)
			if len(name) == 1 && name[0] >= 'a' && name[0] <= 'z' {
				return nil, ""
			}
			return p, name
		case "program":
			return nil, ""
		}
	}
	return nil, ""
}

// declaredParam reports whether name is one of the function's declared
// parameters.
func (w *astWalker) declaredParam(fn *sitter.Node, name string) bool {
	parameters := unwrap(fn.ChildByFieldName("parameters"))
	if parameters == nil {
		return false
	}
	for i := uint(0); i < parameters.NamedChildCount(); i++ {
		if kind(unwrap(parameters.NamedChild(i))) == "identifier" &&
			w.text(unwrap(parameters.NamedChild(i))) == name {
			return true
		}
	}
	return false
}

// payloadNodesFor lists the payload candidates a call contributes, mirroring
// the argument conventions buildSpec applies per client library.
func (w *astWalker) payloadNodesFor(args []*sitter.Node, bodyArg int) []payloadNode {
	var nodes []payloadNode
	add := func(object *sitter.Node, key string) {
		if value := w.objectValue(unwrap(object), key); value != nil {
			nodes = append(nodes, payloadNode{value, key})
		}
	}
	switch bodyArg {
	case -2:
		if len(args) > 0 {
			add(args[0], "params")
			add(args[0], "data")
		}
	case -3:
		if len(args) > 1 {
			add(args[1], "body")
		}
	case -4:
		if len(args) > 1 {
			add(args[1], "json")
		}
	case -5:
		if len(args) > 1 {
			add(args[1], "body")
			add(args[1], "json")
		}
	case -6, -7:
		if len(args) > 1 {
			add(args[1], "params")
			add(args[1], "data")
			add(args[1], "body")
			add(args[1], "json")
		}
	default:
		if bodyArg >= 0 && bodyArg < len(args) {
			nodes = append(nodes, payloadNode{args[bodyArg], "data"})
		}
	}
	return nodes
}

// resolveWrapperCallers runs a second pass over the tree: every call to a
// recorded wrapper contributes what its caller can pin down — an object
// literal argument resolves the wrapped request's body fields, and an exact
// argument substitutes a URL parameter placeholder ({base}) left by the
// wrapper's own call site. Both recoveries stay limited to direct calls with
// statically resolvable arguments; nothing is executed.
func (w *astWalker) resolveWrapperCallers(n *sitter.Node) {
	if n == nil {
		return
	}
	if kind(n) == "call_expression" {
		callee := unwrap(n.ChildByFieldName("function"))
		if callee != nil && callee.Kind() == "identifier" {
			wrapped, ok := w.wrappers[w.moduleScopeOfNode(callee)+"/"+w.text(callee)]
			if ok {
				args := w.arguments(n)
				if wrapped.HasPayload && len(args) > 0 {
					first := unwrap(args[0])
					// A variable argument resolves through its binding site:
					// var form = {...}; dt(form) still recovers the fields.
					if kind(first) == "identifier" {
						if bindings := w.objectNodes[w.text(first)]; len(bindings) > 0 {
							first = bindings[len(bindings)-1].node
						}
					}
					if kind(first) == "object" {
						resolved := []*sitter.Node{first}
						w.recordCall(callee, wrapped.Raw, wrapped.Method, resolved, 0)
					}
				}
				if len(wrapped.URLParams) > 0 && len(args) > 0 {
					w.recordWrapperURLPropagation(callee, wrapped, args)
				}
			}
		}
	}
	for i := uint(0); i < n.NamedChildCount(); i++ {
		w.resolveWrapperCallers(n.NamedChild(i))
	}
}

// recordWrapperURLPropagation substitutes a wrapper caller's exact argument
// values for the URL placeholders left by the wrapper's own request call:
// function load(base){fetch(base+"/users")} + load("/tenant") recovers
// /tenant/users. Arguments that do not reduce to exactly one known value are
// left unsubstituted — the dynamic template stays the only candidate.
func (w *astWalker) recordWrapperURLPropagation(callee *sitter.Node, wrapped wrappedCall, args []*sitter.Node) {
	raw := wrapped.Raw
	substituted := false
	for i, name := range wrapped.ParamNames {
		if i >= len(args) || !containsString(wrapped.URLParams, name) {
			continue
		}
		value := w.evalExpr(args[i], w.rootScope, 0)
		text, ok := value.exactString()
		if !ok {
			continue
		}
		raw = strings.ReplaceAll(raw, "{"+name+"}", text)
		substituted = true
	}
	if !substituted || raw == wrapped.Raw {
		return
	}
	w.recordCall(callee, raw, wrapped.Method, nil, -1)
}

func containsString(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}

// resolveHeuristics is the recall layer for payloads assembled incrementally:
// for every call whose body is a keyless runtime placeholder, it collects the
// keys written to that object within the same function (object-literal
// binding plus `o.key = value` member writes) and records a second candidate
// carrying the real field keys. Keys found here are genuine source literals —
// only their VALUES stay placeholders — so they keep their value-level
// evidence while the variant itself is marked inferred by the caller pass.
func (w *astWalker) resolveHeuristics() {
	var extra []apiCall
	for _, call := range w.calls {
		if call.Spec == nil {
			continue
		}
		for _, param := range call.Spec.Body {
			if param.Key != "" || param.Evidence != model.EvidencePlaceholder {
				continue
			}
			keys := w.heuristicKeys(call.FuncStart, strings.Trim(param.Value, "{}"))
			if len(keys) == 0 {
				continue
			}
			spec := *call.Spec
			spec.Body = appendParams(nil, keys)
			variant := call
			variant.Spec = &spec
			extra = append(extra, variant)
			break // one heuristic variant per call site
		}
	}
	w.calls = append(w.calls, extra...)
}

// heuristicKeys gathers a payload object's field keys from one function
// scope: the binding's own object literal (when bound in the same function,
// or at file scope where a single binding cannot collide) plus every
// member write recorded for it.
func (w *astWalker) heuristicKeys(funcStart uint32, sym string) []model.Param {
	var params []model.Param
	for _, binding := range w.objectNodes[sym] {
		// Same-scope bindings always count; file-scope bindings (module-level
		// const tables) are safe for any caller. Other scopes are other
		// functions' objects — the minifier reuses names, so they must not.
		if binding.funcStart == funcStart || binding.funcStart == 0 {
			params = appendParams(params, w.objectPairs(binding.node, "", 0))
		}
	}
	for _, pair := range w.memberWrites[funcStart][sym] {
		if pair.key == "" {
			continue
		}
		value, evidence := "", model.EvidencePlaceholder
		if pair.value != nil {
			value, evidence = w.valueOf(pair.value)
			if value == "" {
				if symbol := w.payloadSymbol(pair.value); symbol != "" {
					value = "{" + symbol + "}"
				}
			}
		}
		params = appendParams(params,
			[]model.Param{{Key: pair.key, Value: value, Evidence: evidence}})
	}
	return params
}

// resolveTaint attaches local backward-taint annotations to keyless
// placeholder parameters: where does this runtime object flow in from? The
// trace is deliberately bounded — same function, a few binding hops — and
// anything it cannot pin down honestly stays Kind=unknown.
func (w *astWalker) resolveTaint() {
	for ci := range w.calls {
		spec := w.calls[ci].Spec
		if spec == nil {
			continue
		}
		for pi := range spec.Body {
			param := &spec.Body[pi]
			if param.Key != "" || param.Evidence != model.EvidencePlaceholder || param.Taint != nil {
				continue
			}
			param.Taint = w.traceTaint(&w.calls[ci], strings.Trim(param.Value, "{}"))
		}
	}
}

// traceTaint walks bindings backward from a placeholder symbol. Recognized
// origins: a callback parameter whose callback chains from a request
// (.then(function(res){...})) marks the upstream API; a binding to
// localStorage/sessionStorage or router params marks storage/route sources;
// plain identifier/member chains are followed up to three hops.
func (w *astWalker) traceTaint(call *apiCall, sym string) *model.Taint {
	visited := map[string]bool{}
	current := sym
	hops := 0
	for hops <= 3 {
		if visited[current] {
			break
		}
		visited[current] = true
		funcNode := w.funcNodes[call.FuncStart]
		if funcNode == nil {
			break
		}
		root, rest := splitRoot(current)
		if w.declaredParam(funcNode, root) {
			if chain, ok := w.thenByFunc(call.FuncStart); ok {
				upstream := w.requestURLFromCallNode(chain.upstream)
				if upstream != "" {
					return &model.Taint{
						Kind: model.TaintUpstream, Symbol: current,
						Upstream: upstream, UpstreamField: rest, Hops: hops + 1,
					}
				}
			}
			// A callback parameter without a recognized chain origin.
			return &model.Taint{Kind: model.TaintUnknown, Symbol: current, Hops: hops + 1}
		}
		bound := w.findBinding(funcNode, current)
		if bound == nil {
			break
		}
		text := w.text(unwrap(bound))
		switch {
		case strings.Contains(text, "localStorage.getItem"), strings.Contains(text, "sessionStorage.getItem"):
			return &model.Taint{Kind: model.TaintStorage, Symbol: current, Hops: hops + 1}
		case strings.Contains(text, "$route.params"), strings.Contains(text, "$route.query"),
			strings.Contains(text, "route.params"), strings.Contains(text, "route.query"):
			return &model.Taint{Kind: model.TaintRoute, Symbol: current, Hops: hops + 1}
		}
		// Follow plain identifier/member chains one more hop.
		kindBound := kind(unwrap(bound))
		if kindBound == "identifier" || kindBound == "member_expression" || kindBound == "subscript_expression" {
			current = w.text(unwrap(bound))
			hops++
			continue
		}
		break
	}
	return &model.Taint{Kind: model.TaintUnknown, Symbol: sym, Hops: hops}
}

// splitRoot splits "res.data.rows" into root identifier "res" and the rest.
func splitRoot(sym string) (string, string) {
	if idx := strings.Index(sym, "."); idx > 0 {
		return sym[:idx], sym[idx+1:]
	}
	return sym, ""
}

// thenByFunc finds the promise chain registered for a callback function.
func (w *astWalker) thenByFunc(funcStart uint32) (thenChain, bool) {
	for _, chain := range w.thenChains {
		if chain.funcStart == funcStart {
			return chain, true
		}
	}
	return thenChain{}, false
}

// requestURLFromCallNode recovers the URL of a recorded request call node
// after the walk: wrapper indirection, axios-style verb calls, and
// object-style calls all resolve through the same conventions visitCall
// used inline. Empty when the shape is unrecognized.
func (w *astWalker) requestURLFromCallNode(n *sitter.Node) string {
	n = unwrap(n)
	if n == nil || n.Kind() != "call_expression" {
		return ""
	}
	callee := unwrap(n.ChildByFieldName("function"))
	if callee == nil {
		return ""
	}
	// Promise chains: descend through .then/.done wrappers to the request
	// call they are chained onto.
	if object, property, ok := w.memberParts(callee); ok &&
		(property == "then" || property == "done" || property == "always") {
		if chained := w.requestURLFromCallNode(unwrap(object)); chained != "" {
			return chained
		}
	}
	args := w.arguments(n)
	if callee.Kind() == "identifier" {
		if wrapped, ok := w.wrappers[w.moduleScopeOfNode(callee)+"/"+w.text(callee)]; ok {
			return wrapped.Raw
		}
	}
	if object, property, ok := w.memberParts(callee); ok {
		switch property {
		case "get", "post", "put", "patch", "delete", "head", "options", "request":
			if len(args) > 0 {
				for _, candidate := range w.resolveURLExpressions(args[0]) {
					if candidate != "" {
						return candidate
					}
				}
			}
		}
		_ = object
	}
	if len(args) > 0 {
		if first := unwrap(args[0]); first.Kind() == "object" {
			if urlNode := w.objectValue(first, "url"); urlNode != nil {
				for _, candidate := range w.resolveURLExpressions(urlNode) {
					if candidate != "" {
						return candidate
					}
				}
			}
		}
	}
	return ""
}

// findBinding locates the node that binds sym inside a function subtree:
// a variable declarator or an assignment whose left side is the identifier.
func (w *astWalker) findBinding(fn *sitter.Node, sym string) *sitter.Node {
	var found *sitter.Node
	var search func(n *sitter.Node)
	search = func(n *sitter.Node) {
		if n == nil || found != nil {
			return
		}
		switch n.Kind() {
		case "variable_declarator":
			name := unwrap(n.ChildByFieldName("name"))
			if name != nil && name.Kind() == "identifier" && w.text(name) == sym {
				found = n.ChildByFieldName("value")
				return
			}
		case "assignment_expression":
			left := unwrap(n.ChildByFieldName("left"))
			if left != nil && left.Kind() == "identifier" && w.text(left) == sym {
				found = n.ChildByFieldName("right")
				return
			}
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			search(n.NamedChild(i))
		}
	}
	search(fn)
	return found
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

// evalExpr is the single static-evaluation entry every shape funnels
// through: variable initializers, assignments, request URLs, template
// interpolation, object property reads, axios baseURL and the URL
// constructor. It returns every statically possible value (branch merges),
// degrades unknown fragments to "{}" placeholders while keeping known
// prefix/suffix structure, and never guesses past what the source pins down.
func (w *astWalker) evalExpr(n *sitter.Node, scope *evalScope, depth int) jsValue {
	if depth > maxEvalDepth {
		return jsUnknown()
	}
	w.evalBudget--
	if w.evalBudget < 0 {
		return jsUnknown()
	}
	n = unwrap(n)
	if n == nil {
		return jsUnknown()
	}
	switch kind(n) {
	case "string":
		return jsStr(decodeJSString(w.text(n)))
	case "number":
		return jsNumberOpt(w.text(n))
	case "true", "false", "null", "undefined":
		return jsStr(w.text(n))
	case "identifier", "shorthand_property_identifier",
		"shorthand_property_identifier_pattern":
		return w.readScalar(w.text(n))
	case "template_string":
		return w.evalTemplate(n, scope, depth)
	case "binary_expression":
		return w.evalBinary(n, scope, depth)
	case "conditional_expression", "ternary_expression":
		// Both branches are statically plausible; the merged candidate set is
		// capped and degrades to unknown when it would overflow.
		merged := unionValues(
			w.evalExpr(n.ChildByFieldName("consequence"), scope, depth+1),
			w.evalExpr(n.ChildByFieldName("alternative"), scope, depth+1),
		)
		return capped(merged)
	case "member_expression":
		return w.evalMember(n, scope, depth)
	case "subscript_expression":
		return w.evalSubscript(n, scope, depth)
	case "call_expression":
		return w.evalCall(n, scope, depth)
	case "new_expression":
		return w.foldURLValue(n, scope, depth)
	case "object":
		// A config object used directly as a URL resolves its url member.
		if value := w.objectValue(n, "url"); value != nil {
			return w.evalExpr(value, scope, depth+1)
		}
	}
	return jsUnknown()
}

// jsNumberOpt parses a numeric literal the way JavaScript would: decimal,
// hex, binary and octal spellings all fold; anything else stays unknown.
func jsNumberOpt(raw string) jsValue {
	if value, err := strconv.ParseInt(raw, 0, 64); err == nil {
		return jsNumber(float64(value))
	}
	if value, err := strconv.ParseFloat(raw, 64); err == nil {
		return jsNumber(value)
	}
	return jsPlaceholder("{}")
}

// optText renders one option for string concatenation.
func optText(opt jsOpt) string {
	if opt.isNum {
		return formatJSNumber(opt.num)
	}
	return opt.text
}

// evalTemplate folds a template literal, resolving each substitution through
// the same evaluator. Known substitutions inline their value; unknown ones
// keep the "{}" placeholder between the known fragments.
func (w *astWalker) evalTemplate(n *sitter.Node, scope *evalScope, depth int) jsValue {
	parts := make([]jsValue, 0, n.NamedChildCount())
	for i := uint(0); i < n.NamedChildCount(); i++ {
		child := n.NamedChild(i)
		switch child.Kind() {
		case "string_fragment":
			parts = append(parts, jsStr(w.text(child)))
		case "escape_sequence":
			parts = append(parts, jsStr(decodeJSEscapes(w.text(child))))
		case "template_substitution":
			inner := child.ChildByFieldName("expression")
			if inner == nil && child.NamedChildCount() > 0 {
				inner = child.NamedChild(0)
			}
			parts = append(parts, w.evalExpr(inner, scope, depth+1))
		}
	}
	return w.joinParts(parts)
}

// joinParts concatenates a list of evaluated parts, expanding the cartesian
// product when any part carries branch candidates.
func (w *astWalker) joinParts(parts []jsValue) jsValue {
	out := []jsOpt{{}}
	for _, part := range parts {
		part = capped(part)
		next := make([]jsOpt, 0, len(out))
		for _, left := range out {
			rights := part.opts
			if len(rights) == 0 {
				rights = []jsOpt{{text: "{}", unknown: true}}
			}
			for _, right := range rights {
				text := optText(left) + optText(right)
				next = append(next, jsOpt{
					text:    text,
					unknown: left.unknown || right.unknown,
				})
			}
		}
		if len(next) > maxEvalOptions {
			return jsUnknown()
		}
		out = next
	}
	return jsValue{opts: out}
}

// evalBinary folds binary expressions. "+" follows JavaScript semantics:
// two numbers add numerically, anything else concatenates as strings.
// The short-circuit operators are value-merges: either side is possible.
func (w *astWalker) evalBinary(n *sitter.Node, scope *evalScope, depth int) jsValue {
	operator := w.text(n.ChildByFieldName("operator"))
	left := w.evalExpr(n.ChildByFieldName("left"), scope, depth+1)
	right := w.evalExpr(n.ChildByFieldName("right"), scope, depth+1)
	switch operator {
	case "+":
		return w.concatValues(left, right)
	case "&&", "||", "??":
		return capped(unionValues(left, right))
	}
	return jsUnknown()
}

// concatValues applies JavaScript "+" to two evaluated sides: number+number
// is numeric addition, every other combination concatenates its ToString
// forms, and a side with no evaluable structure contributes "{}".
func (w *astWalker) concatValues(left, right jsValue) jsValue {
	left, right = capped(left), capped(right)
	lrights := left.opts
	if len(lrights) == 0 {
		lrights = []jsOpt{{text: "{}", unknown: true}}
	}
	rrights := right.opts
	if len(rrights) == 0 {
		rrights = []jsOpt{{text: "{}", unknown: true}}
	}
	if len(lrights)*len(rrights) > maxEvalOptions {
		return jsUnknown()
	}
	out := make([]jsOpt, 0, len(lrights)*len(rrights))
	for _, l := range lrights {
		for _, r := range rrights {
			if l.isNum && r.isNum && !l.unknown && !r.unknown {
				out = append(out, jsOpt{
					text:  formatJSNumber(l.num + r.num),
					isNum: true, num: l.num + r.num,
				})
				continue
			}
			out = append(out, jsOpt{
				text:    optText(l) + optText(r),
				unknown: l.unknown || r.unknown,
			})
		}
	}
	return capped(jsValue{opts: out})
}

// unionValues merges two values' candidate sets, deduplicating by value.
func unionValues(l, r jsValue) jsValue {
	out := make([]jsOpt, 0, len(l.opts)+len(r.opts))
	seen := map[jsOpt]bool{}
	for _, opt := range append(append([]jsOpt{}, l.opts...), r.opts...) {
		if !seen[opt] {
			seen[opt] = true
			out = append(out, opt)
		}
	}
	return jsValue{opts: out}
}

// evalMember resolves property access: constant object tables first, then a
// scalar binding whose trailing property cannot change its string value
// (`const u = new URL(...); fetch(u.href)`), then `.href` on a folded URL
// constructor call. Anything else stays unknown.
func (w *astWalker) evalMember(n *sitter.Node, scope *evalScope, depth int) jsValue {
	object := unwrap(n.ChildByFieldName("object"))
	property := w.text(n.ChildByFieldName("property"))
	if object == nil {
		return jsUnknown()
	}
	if kind(object) == "identifier" {
		if b, _ := w.lookup(w.text(object)); b != nil {
			if len(b.opts) > 0 {
				return jsValue{opts: b.opts}
			}
			if b.object != nil {
				if value, ok := b.object[property]; ok {
					return jsStr(value)
				}
				return jsUnknown()
			}
		}
		return jsUnknown()
	}
	// new URL(...).href: fold the construction and hand back the full URL.
	if kind(object) == "new_expression" && property == "href" {
		if _, ok := w.constructorName(object); ok {
			return w.foldURLValue(object, scope, depth+1)
		}
	}
	return jsUnknown()
}

// evalSubscript resolves `routes["users"]`-style access over a constant
// object table; a string index that misses the table stays unknown.
func (w *astWalker) evalSubscript(n *sitter.Node, scope *evalScope, depth int) jsValue {
	object := unwrap(n.ChildByFieldName("object"))
	index := unwrap(n.ChildByFieldName("index"))
	if object == nil || index == nil || kind(object) != "identifier" {
		return jsUnknown()
	}
	if kind(index) != "string" {
		return jsUnknown()
	}
	b, _ := w.lookup(w.text(object))
	if b == nil || b.object == nil {
		return jsUnknown()
	}
	if value, ok := b.object[decodeJSString(w.text(index))]; ok {
		return jsStr(value)
	}
	return jsUnknown()
}

// evalCall folds the built-in calls static analysis can evaluate honestly:
// string concat aliases (concat/join), first-hit replace vs replaceAll,
// atob, and encodeURIComponent/decodeURIComponent. Any other function's
// return value stays unknown — never a fabricated constant.
func (w *astWalker) evalCall(n *sitter.Node, scope *evalScope, depth int) jsValue {
	function := unwrap(n.ChildByFieldName("function"))
	if function == nil {
		return jsUnknown()
	}
	arguments := w.arguments(n)
	// Bare atob("...") has an identifier callee that memberParts cannot
	// describe, so it is handled before the member dispatch.
	if kind(function) == "identifier" {
		name := w.text(function)
		switch name {
		case "atob":
			if len(arguments) != 1 {
				return jsUnknown()
			}
			return w.evalBase64Decode(arguments[0], scope, depth)
		case "encodeURIComponent", "decodeURIComponent":
			if len(arguments) != 1 {
				return jsUnknown()
			}
			return w.evalURIEscape(name, arguments[0], scope, depth)
		}
		return jsUnknown()
	}
	object, property, ok := w.memberParts(function)
	if !ok {
		return jsUnknown()
	}
	switch property {
	case "concat":
		parts := []jsValue{w.evalExpr(object, scope, depth+1)}
		for _, arg := range arguments {
			parts = append(parts, w.evalExpr(arg, scope, depth+1))
		}
		return w.joinParts(parts)
	case "join":
		if kind(unwrap(object)) != "array" {
			return jsUnknown()
		}
		separator := ","
		if len(arguments) == 1 {
			sep, ok := w.evalExpr(arguments[0], scope, depth+1).exactString()
			if !ok {
				return jsUnknown()
			}
			separator = sep
		}
		elements := unwrap(object)
		parts := make([]jsValue, 0, elements.NamedChildCount())
		for i := uint(0); i < elements.NamedChildCount(); i++ {
			parts = append(parts, w.evalExpr(elements.NamedChild(i), scope, depth+1))
		}
		return w.joinWithSeparator(parts, separator)
	case "replace", "replaceAll":
		return w.evalReplace(property, object, arguments, scope, depth)
	case "atob":
		// window.atob: same decoding as the bare global spelling.
		if len(arguments) != 1 || kind(object) != "identifier" || w.text(object) != "window" {
			return jsUnknown()
		}
		return w.evalBase64Decode(arguments[0], scope, depth)
	}
	return jsUnknown()
}

// joinWithSeparator folds array.join(sep) element by element, expanding
// branch candidates across elements and degrading unknown elements to "{}".
func (w *astWalker) joinWithSeparator(parts []jsValue, separator string) jsValue {
	out := []jsOpt{{}}
	for _, part := range parts {
		part = capped(part)
		rights := part.opts
		if len(rights) == 0 {
			rights = []jsOpt{{text: "{}", unknown: true}}
		}
		next := make([]jsOpt, 0, len(out))
		for _, left := range out {
			for _, right := range rights {
				text := optText(left) + separator + optText(right)
				next = append(next, jsOpt{text: text, unknown: left.unknown || right.unknown})
			}
		}
		if len(next) > maxEvalOptions {
			return jsUnknown()
		}
		out = next
	}
	return jsValue{opts: out}
}

// evalReplace folds String.replace/replaceAll. Only exact string patterns
// and replacements with no "$" substitution markers are folded: replace
// hits the first occurrence, replaceAll hits every one. Regex patterns and
// substitution semantics degrade to unknown instead of a fabricated value.
func (w *astWalker) evalReplace(
	property string,
	object *sitter.Node,
	arguments []*sitter.Node,
	scope *evalScope,
	depth int,
) jsValue {
	if len(arguments) < 2 {
		return jsUnknown()
	}
	subject := w.evalExpr(object, scope, depth+1)
	patternV := w.evalExpr(arguments[0], scope, depth+1)
	replacementV := w.evalExpr(arguments[1], scope, depth+1)
	if kind(unwrap(arguments[0])) == "regex" {
		// A regex pattern's match set cannot be folded honestly here.
		return jsUnknown()
	}
	pattern, pok := patternV.exactString()
	replacement, rok := replacementV.exactString()
	if !pok || !rok || strings.Contains(replacement, "$") {
		return jsUnknown()
	}
	count := 1
	if property == "replaceAll" {
		count = -1
	}
	out := make([]jsOpt, 0, len(subject.opts))
	for _, opt := range capped(subject).opts {
		text := optText(opt)
		if text == "" && len(subject.opts) == 0 {
			text = "{}"
		}
		out = append(out, jsOpt{
			text:    strings.Replace(text, pattern, replacement, count),
			unknown: true,
		})
	}
	return jsValue{opts: out}
}

// evalBase64Decode folds atob(): the argument folds first, and only a
// printable-ASCII decoding is returned.
func (w *astWalker) evalBase64Decode(arg *sitter.Node, scope *evalScope, depth int) jsValue {
	encoded, ok := w.evalExpr(arg, scope, depth+1).exactString()
	if !ok {
		return jsUnknown()
	}
	if decoded := decodeBase64String(encoded); decoded != "" {
		return jsStr(decoded)
	}
	return jsUnknown()
}

// evalURIEscape folds encodeURIComponent/decodeURIComponent over an exact
// argument. Both follow the spec byte-for-byte; an invalid escape sequence
// (which throws at runtime) degrades to unknown.
func (w *astWalker) evalURIEscape(name string, arg *sitter.Node, scope *evalScope, depth int) jsValue {
	value, ok := w.evalExpr(arg, scope, depth+1).exactString()
	if !ok {
		return jsUnknown()
	}
	if name == "encodeURIComponent" {
		return jsStr(jsEncodeURIComponent(value))
	}
	decoded, ok := jsDecodeURIComponent(value)
	if !ok {
		return jsUnknown()
	}
	return jsStr(decoded)
}

// jsEncodeURIComponent percent-encodes every byte outside the unreserved set
// the spec keeps literal: A-Z a-z 0-9 - _ . ! ~ * ' ( ).
func jsEncodeURIComponent(s string) string {
	var out strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '.', c == '!', c == '~', c == '*',
			c == '\'', c == '(', c == ')':
			out.WriteByte(c)
		default:
			out.WriteByte('%')
			out.WriteByte(upperHex(c >> 4))
			out.WriteByte(upperHex(c & 0x0f))
		}
	}
	return out.String()
}

func upperHex(b byte) byte {
	if b < 10 {
		return '0' + b
	}
	return 'A' + b - 10
}

// jsDecodeURIComponent decodes %XX escape bytes; a malformed sequence or a
// broken UTF-8 result is not decodable and reports false.
func jsDecodeURIComponent(s string) (string, bool) {
	var out strings.Builder
	for i := 0; i < len(s); {
		if s[i] != '%' {
			out.WriteByte(s[i])
			i++
			continue
		}
		if i+2 >= len(s) {
			return "", false
		}
		high, ok1 := parseHexDigit(s[i+1])
		low, ok2 := parseHexDigit(s[i+2])
		if !ok1 || !ok2 {
			return "", false
		}
		out.WriteByte(high<<4 | low)
		i += 3
	}
	return out.String(), true
}

func parseHexDigit(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// resolveURLExpressions resolves a URL expression to every static value it
// can yield — a conditional expression (now folded by the evaluator itself)
// contributes all of its branch candidates.
func (w *astWalker) resolveURLExpressions(n *sitter.Node) []string {
	v := w.evalExpr(n, w.currentScope(), 0)
	seen := map[string]struct{}{}
	out := make([]string, 0, len(v.opts))
	for _, opt := range v.opts {
		if opt.isNum || opt.text == "" {
			continue
		}
		if _, ok := seen[opt.text]; ok {
			continue
		}
		seen[opt.text] = struct{}{}
		out = append(out, opt.text)
	}
	return out
}

// visitNewExpression records `new URL(path, base)` constructions as request
// candidates when the folded values are path-shaped.
func (w *astWalker) visitNewExpression(n *sitter.Node) {
	if _, ok := w.constructorName(n); !ok {
		return
	}
	for _, opt := range capped(w.foldURLValue(n, w.currentScope(), 0)).opts {
		if opt.isNum || !looksLikePath(opt.text) {
			continue
		}
		point := n.StartPosition()
		ctx := w.lines.extract(int(n.StartByte()), contextSpanLines, opt.text)
		w.calls = append(w.calls, apiCall{
			Raw: opt.text, Method: "GET", Evidence: evidenceFor(opt.text),
			Line: int(point.Row) + 1, Column: int(point.Column) + 1, Context: ctx,
		})
	}
}

// constructorName reports whether a new_expression constructs URL (directly
// or through window.URL).
func (w *astWalker) constructorName(n *sitter.Node) (string, bool) {
	constructor := unwrap(n.ChildByFieldName("constructor"))
	if constructor == nil {
		return "", false
	}
	if kind(constructor) == "identifier" {
		name := w.text(constructor)
		return name, name == "URL"
	}
	if object, property, ok := w.memberParts(constructor); ok {
		return property, property == "URL" && w.outermostIdentifier(object) == "window"
	}
	return "", false
}

// foldURLValue statically evaluates `new URL(path[, base])` through the
// evaluator and resolves the result with real URL-reference semantics: an
// absolute URL wins outright, a rooted path attaches to the base origin, a
// relative path replaces the base's last segment, and query/fragment-only
// references keep the base path. An unevaluable base keeps the shape of a
// rooted or absolute path as a degraded placeholder.
func (w *astWalker) foldURLValue(n *sitter.Node, scope *evalScope, depth int) jsValue {
	if _, ok := w.constructorName(n); !ok {
		return jsUnknown()
	}
	args := w.arguments(n)
	if len(args) == 0 {
		return jsUnknown()
	}
	path := capped(w.evalExpr(args[0], scope, depth+1))
	if len(args) < 2 {
		return path
	}
	base := capped(w.evalExpr(args[1], scope, depth+1))
	basePath, baseOK := base.exactString()
	out := make([]jsOpt, 0, len(path.opts))
	for _, opt := range path.opts {
		if opt.isNum {
			continue
		}
		if baseOK {
			resolved, ok := resolveURLReference(basePath, opt.text)
			if ok {
				out = append(out, jsOpt{text: resolved, unknown: opt.unknown})
			}
			continue
		}
		// The base is unknown: a rooted or absolute path still keeps its
		// recoverable structure, marked uncertain.
		if len(base.opts) == 0 &&
			(strings.HasPrefix(opt.text, "/") || strings.Contains(opt.text, "://")) {
			out = append(out, jsOpt{text: opt.text, unknown: true})
		}
	}
	return capped(jsValue{opts: out})
}

// resolveURLReference combines a base with a reference the way the URL
// constructor (RFC 3986 reference resolution) does: an absolute reference
// replaces the base, a rooted path attaches to the base origin, a relative
// path drops the base's last segment, and ".."/"." segments collapse.
// Query- and fragment-only references keep the base path.
func resolveURLReference(base, ref string) (string, bool) {
	base, ref = strings.TrimSpace(base), strings.TrimSpace(ref)
	if ref == "" {
		return base, base != ""
	}
	if strings.Contains(ref, "://") {
		return ref, true
	}
	baseURL, err := url.Parse(base)
	if err != nil || (baseURL.Scheme == "" && baseURL.Host == "" && baseURL.Path == "") {
		return "", false
	}
	refURL, err := url.Parse(ref)
	if err != nil {
		return "", false
	}
	resolved := baseURL.ResolveReference(refURL)
	out := resolved.String()
	if out == "" {
		return "", false
	}
	return out, true
}

// decodeBase64String decodes an atob() argument. Only results made of
// printable ASCII are returned: garbage decodings are not useful candidates.
func decodeBase64String(value string) string {
	cleaned := strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\n', '\r':
			return -1
		}
		return r
	}, value)
	if cleaned == "" {
		return ""
	}
	for _, encoding := range []*base64.Encoding{
		base64.StdEncoding, base64.URLEncoding,
		base64.RawStdEncoding, base64.RawURLEncoding,
	} {
		decoded, err := encoding.DecodeString(cleaned)
		if err != nil || len(decoded) == 0 {
			continue
		}
		printable := true
		for _, b := range decoded {
			if b < 0x20 || b > 0x7e {
				printable = false
				break
			}
		}
		if printable {
			return string(decoded)
		}
	}
	return ""
}

// buildSpec normalizes a call's arguments into a RequestSpec: query and body
// parameters with the best recoverable values, plus an explicit or inferred
// content type. Recall-first: every plausible option object is consulted and
// unknown values degrade to named placeholders instead of being dropped.
func (w *astWalker) buildSpec(args []*sitter.Node, bodyArg int) *model.RequestSpec {
	var queryNodes, bodyNodes []payloadNode
	addKey := func(object *sitter.Node, key string, query bool) {
		if value := w.objectValue(unwrap(object), key); value != nil {
			if query {
				queryNodes = append(queryNodes, payloadNode{value, key})
			} else {
				bodyNodes = append(bodyNodes, payloadNode{value, key})
			}
		}
	}
	switch bodyArg {
	case -2:
		if len(args) > 0 {
			addKey(args[0], "params", true)
			addKey(args[0], "data", false)
		}
	case -3:
		if len(args) > 1 {
			addKey(args[1], "body", false)
		}
	case -4:
		if len(args) > 1 {
			addKey(args[1], "json", false)
		}
	case -5:
		if len(args) > 1 {
			addKey(args[1], "body", false)
			addKey(args[1], "json", false)
		}
	case -6:
		if len(args) > 1 {
			addKey(args[1], "params", true)
			addKey(args[1], "data", false)
		}
	case -7:
		if len(args) > 1 {
			addKey(args[1], "params", true)
			addKey(args[1], "data", false)
			addKey(args[1], "body", false)
			addKey(args[1], "json", false)
		}
	default:
		if bodyArg >= 0 && bodyArg < len(args) {
			bodyNodes = append(bodyNodes, payloadNode{args[bodyArg], "data"})
		}
	}

	spec := &model.RequestSpec{}
	// mergePayload reads one payload candidate. When the payload is a bare
	// variable reference — the wrapper shape `function P(t){...data:t...}` —
	// its fields only exist at runtime. The placeholder then carries the
	// source symbol in its value ("{t}") with an empty key: the axios slot
	// name ("data"/"params") is a config protocol name, never a request
	// field, so reporting it as a key would suggest a field that does not
	// exist on the wire.
	mergePayload := func(nodes []payloadNode, dst *[]model.Param) {
		for _, payload := range nodes {
			pairs := w.paramPairs(payload.node)
			if len(pairs) == 0 {
				if symbol := w.payloadSymbol(payload.node); symbol != "" {
					pairs = []model.Param{{
						Key:      "",
						Value:    "{" + symbol + "}",
						Evidence: model.EvidencePlaceholder,
					}}
				}
			}
			*dst = appendParams(*dst, pairs)
		}
	}
	mergePayload(queryNodes, &spec.Query)
	mergePayload(bodyNodes, &spec.Body)
	spec.ContentType, spec.ContentTypeEvidence = w.contentType(args, payloadNodeNodes(bodyNodes))
	if spec.ContentType == "" && len(spec.Query) == 0 && len(spec.Body) == 0 {
		return nil
	}
	return spec
}

// payloadNode is one payload candidate together with the option key it came
// from ("data", "params", ...), so a dynamic payload can still be reported
// under its own name.
type payloadNode struct {
	node *sitter.Node
	key  string
}

// payloadSymbol returns the source text when a payload is a bare variable
// reference (identifier, member, or subscript expression) — the shapes whose
// fields are decided by the caller, not by this call site.
func (w *astWalker) payloadSymbol(n *sitter.Node) string {
	n = unwrap(n)
	switch kind(n) {
	case "identifier", "member_expression", "subscript_expression":
		return w.text(n)
	}
	return ""
}

// payloadNodeNodes unwraps the payload list for consumers that only want the
// AST nodes.
func payloadNodeNodes(nodes []payloadNode) []*sitter.Node {
	result := make([]*sitter.Node, 0, len(nodes))
	for _, payload := range nodes {
		result = append(result, payload.node)
	}
	return result
}

func appendParams(base, extra []model.Param) []model.Param {
	if len(extra) == 0 {
		return base
	}
	seen := make(map[string]struct{}, len(base)+len(extra))
	for _, param := range base {
		// Placeholder entries have no field key; their value (the source
		// symbol) is what distinguishes them, so dedupe on both.
		seen[param.Key+"\x00"+param.Value] = struct{}{}
	}
	for _, param := range extra {
		if param.Key == "" && param.Evidence != model.EvidencePlaceholder {
			continue
		}
		identity := param.Key + "\x00" + param.Value
		if _, duplicate := seen[identity]; duplicate {
			continue
		}
		seen[identity] = struct{}{}
		base = append(base, param)
	}
	return base
}

// contentType returns the explicit Content-Type from any object argument
// (fetch/axios/ky `headers`, jQuery `contentType` — including axios's third
// argument when the body occupies the second), or infers one from the
// payload shape (JSON.stringify, FormData, inline JSON text).
func (w *astWalker) contentType(args []*sitter.Node, bodyNodes []*sitter.Node) (string, string) {
	for _, arg := range args {
		option := unwrap(arg)
		if kind(option) != "object" {
			continue
		}
		if headers := unwrap(w.objectValue(option, "headers")); kind(headers) == "object" {
			for i := uint(0); i < headers.NamedChildCount(); i++ {
				pair := headers.NamedChild(i)
				if pair.Kind() != "pair" {
					continue
				}
				if strings.EqualFold(w.propertyName(pair.ChildByFieldName("key")), "content-type") {
					if value, evidence := w.valueOf(pair.ChildByFieldName("value")); value != "" {
						return value, evidence
					}
				}
			}
		}
		if value := w.objectValue(option, "contentType"); value != nil {
			if text, evidence := w.valueOf(value); text != "" {
				return text, evidence
			}
		}
	}
	for _, body := range bodyNodes {
		body = unwrap(body)
		switch kind(body) {
		case "call_expression":
			if w.isStringifyCall(body.ChildByFieldName("function")) {
				return "application/json", model.EvidenceInferred
			}
		case "new_expression":
			if w.text(unwrap(body.ChildByFieldName("constructor"))) == "FormData" {
				return "multipart/form-data", model.EvidenceInferred
			}
		case "identifier":
			// A builder variable bound earlier in the file implies the same
			// encoding as its constructor would.
			switch w.builderFor(w.text(body)) {
			case "URLSearchParams":
				return "application/x-www-form-urlencoded", model.EvidenceInferred
			case "FormData":
				return "multipart/form-data", model.EvidenceInferred
			}
		case "string":
			if raw := decodeJSString(w.text(body)); strings.HasPrefix(strings.TrimSpace(raw), "{") {
				return "application/json", model.EvidenceInferred
			}
		}
	}
	return "", ""
}

// paramPairs reads key/value pairs from a payload node: an object literal, a
// JSON.stringify call over one, a JSON string/template inlined by the
// minifier, or a URLSearchParams/FormData builder resolved through its
// append chain. Anything else yields nothing.
func (w *astWalker) paramPairs(node *sitter.Node) []model.Param {
	node = unwrap(node)
	if kind(node) == "call_expression" && w.isStringifyCall(node.ChildByFieldName("function")) {
		if wrapped := w.arguments(node); len(wrapped) > 0 {
			node = unwrap(wrapped[0])
		}
	}
	switch kind(node) {
	case "object":
		return w.objectPairs(node, "", 0)
	case "array":
		return w.arrayPairs(node, "", 0)
	case "string":
		return jsonParamPairs(decodeJSString(w.text(node)))
	case "template_string":
		return jsonParamPairs(w.templatePlaceholder(node))
	case "identifier":
		return w.builderPairs(w.text(node))
	}
	return nil
}

// builderPairs flattens one builder variable's append("key", value) chain
// into request parameters. Values resolve through the ordinary literal
// machinery: strings stay literal, runtime expressions become placeholders
// carrying their source expression (e.g. `{t.loginName}`).
func (w *astWalker) builderPairs(name string) []model.Param {
	if w.builderFor(name) == "" {
		return nil
	}
	pairs := w.appends[name]
	if len(pairs) == 0 {
		return nil
	}
	params := make([]model.Param, 0, len(pairs))
	for _, pair := range pairs {
		if pair.key == "" {
			continue
		}
		value, evidence := "", model.EvidencePlaceholder
		if pair.value != nil {
			value, evidence = w.valueOf(pair.value)
			if value == "" {
				// Runtime expressions like `t.loginName` keep their source
				// shape as a placeholder so the field origin stays visible.
				if symbol := w.payloadSymbol(pair.value); symbol != "" {
					value = "{" + symbol + "}"
				}
			}
		}
		params = appendParams(params,
			[]model.Param{{Key: pair.key, Value: value, Evidence: evidence}})
	}
	return params
}

// arrayPairs flattens an array payload: object elements contribute their
// leaves under `items[].field` keys, nested arrays nest further, and scalar
// elements type the array itself under `items[]`. Keys dedupe across
// elements, so a hundred list rows still yield one row per distinct field.
func (w *astWalker) arrayPairs(array *sitter.Node, prefix string, depth int) []model.Param {
	if depth > maxParamDepth {
		return nil
	}
	name := "[]"
	if prefix != "" {
		name = prefix + "[]"
	}
	params := make([]model.Param, 0, 4)
	for i := uint(0); i < array.NamedChildCount() && len(params) < maxBodyParams; i++ {
		element := unwrap(array.NamedChild(i))
		switch kind(element) {
		case "object":
			params = appendParams(params, w.objectPairs(element, name, depth+1))
		case "array":
			params = appendParams(params, w.arrayPairs(element, name, depth+1))
		default:
			value, evidence := w.valueOf(element)
			if value == "" {
				if symbol := w.payloadSymbol(element); symbol != "" {
					value, evidence = "{"+symbol+"}", model.EvidencePlaceholder
				} else {
					value, evidence = "{}", model.EvidencePlaceholder
				}
			}
			params = appendParams(params,
				[]model.Param{{Key: name, Value: value, Evidence: evidence}})
		}
	}
	return params
}

// objectPairs walks one object literal, flattening nested objects into
// dotted keys up to maxParamDepth so JSON-style payloads stay fuzzable.
func (w *astWalker) objectPairs(object *sitter.Node, prefix string, depth int) []model.Param {
	if depth > maxParamDepth {
		return nil
	}
	params := make([]model.Param, 0, 4)
	for i := uint(0); i < object.NamedChildCount() && len(params) < maxBodyParams; i++ {
		child := object.NamedChild(i)
		var key, value, evidence string
		var valueNode *sitter.Node
		switch child.Kind() {
		case "pair":
			keyNode := child.ChildByFieldName("key")
			if kind(unwrap(keyNode)) == "computed_property_name" {
				continue // dynamic key: nothing stable to fuzz
			}
			key = w.propertyName(keyNode)
			valueNode = unwrap(child.ChildByFieldName("value"))
			value, evidence = w.valueOf(valueNode)
			if value == "" {
				name := key
				if prefix != "" {
					name = prefix + "." + key
				}
				switch kind(valueNode) {
				case "object":
					params = append(params, w.objectPairs(valueNode, name, depth+1)...)
					continue
				case "array":
					params = append(params, w.arrayPairs(valueNode, name, depth+1)...)
					continue
				}
			}
		case "shorthand_property_identifier", "shorthand_property_identifier_pattern":
			key = w.text(child)
			valueNode = child
			value, evidence = w.valueOf(child)
		default:
			continue // spread_element, methods, comments
		}
		if key == "" {
			continue
		}
		if prefix != "" {
			key = prefix + "." + key
		}
		if value == "" {
			if symbol := w.payloadSymbol(valueNode); symbol != "" {
				value, evidence = "{"+symbol+"}", model.EvidencePlaceholder
			} else {
				value, evidence = "{}", model.EvidencePlaceholder
			}
		}
		params = append(params, model.Param{Key: key, Value: value, Evidence: evidence})
	}
	return params
}

// valueOf renders a node as the best static value it yields, paired with the
// evidence for that recovery: literals are verbatim, identifiers resolve
// through their scope binding, and everything dynamic keeps a placeholder —
// a bare unknown identifier carries its source name ({tenantID}), a
// concatenated unknown fragment degrades to "{}".
func (w *astWalker) valueOf(n *sitter.Node) (string, string) {
	n = unwrap(n)
	switch kind(n) {
	case "string":
		return decodeJSString(w.text(n)), model.EvidenceLiteral
	case "number", "true", "false", "null", "undefined":
		return w.text(n), model.EvidenceLiteral
	}
	v := w.evalExpr(n, w.currentScope(), 0)
	if len(v.opts) == 0 {
		// Nothing evaluable: keep the source expression as the placeholder so
		// the report shows where the value flows in from.
		if symbol := w.payloadSymbol(n); symbol != "" {
			return "{" + symbol + "}", model.EvidencePlaceholder
		}
		return "", ""
	}
	opt := v.opts[0]
	text := opt.text
	if opt.isNum {
		text = formatJSNumber(opt.num)
	}
	switch {
	case opt.unknown:
		if text == "{}" && (kind(n) == "identifier" ||
			kind(n) == "shorthand_property_identifier" ||
			kind(n) == "shorthand_property_identifier_pattern") {
			return "{" + w.text(n) + "}", model.EvidencePlaceholder
		}
		return text, model.EvidencePlaceholder
	case len(v.opts) > 1:
		// Several branch candidates: the first is reported, but its value is
		// not certain, so the evidence stays a placeholder.
		return text, model.EvidencePlaceholder
	case kind(n) == "template_string":
		return text, model.EvidenceLiteral
	default:
		return text, model.EvidenceConstant
	}
}

// jsonParamPairs reads key/value pairs from a JSON object written as a plain
// string — the shape minified bundles inline most often.
func jsonParamPairs(raw string) []model.Param {
	trimmed := strings.TrimSpace(raw)
	if !strings.HasPrefix(trimmed, "{") || !json.Valid([]byte(trimmed)) {
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
	params := make([]model.Param, 0, len(names))
	for _, name := range names {
		value, evidence := jsonValueOf(object[name])
		params = append(params, model.Param{Key: name, Value: value, Evidence: evidence})
	}
	return params
}

func jsonValueOf(raw json.RawMessage) (string, string) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return "", ""
	}
	switch trimmed[0] {
	case '"':
		var value string
		if json.Unmarshal(raw, &value) == nil {
			return value, model.EvidenceLiteral
		}
	case '{', '[':
		return trimmed[:1], model.EvidencePlaceholder
	default:
		if trimmed == "true" || trimmed == "false" || trimmed == "null" ||
			trimmed == "undefined" || isJSONNumber(trimmed) {
			return trimmed, model.EvidenceLiteral
		}
	}
	return "{}", model.EvidencePlaceholder
}

func isJSONNumber(raw string) bool {
	if _, err := strconv.ParseFloat(raw, 64); err != nil {
		return false
	}
	for _, r := range raw {
		if !strings.ContainsRune("0123456789+-.eE", r) {
			return false
		}
	}
	return true
}

func (w *astWalker) isStringifyCall(n *sitter.Node) bool {
	object, property, ok := w.memberParts(unwrap(n))
	return ok && property == "stringify" && w.outermostIdentifier(object) == "JSON"
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

func (w *astWalker) axiosCreateBase(n *sitter.Node) (string, string, bool) {
	n = unwrap(n)
	if kind(n) != "call_expression" {
		return "", "", false
	}
	object, property, ok := w.memberParts(unwrap(n.ChildByFieldName("function")))
	if !ok || property != "create" || w.outermostIdentifier(object) != "axios" {
		return "", "", false
	}
	args := w.arguments(n)
	if len(args) == 0 || kind(unwrap(args[0])) != "object" {
		return "", "", false
	}
	value := w.objectValue(unwrap(args[0]), "baseURL")
	if value == nil {
		return "", "", false
	}
	base, baseKind := w.baseURLFromExpression(value)
	return base, baseKind, true
}

func (w *astWalker) baseURLTarget(n *sitter.Node) (string, bool) {
	object, property, ok := w.memberParts(unwrap(n))
	if !ok || property != "baseURL" {
		return "", false
	}
	name := w.outermostIdentifier(object)
	return name, name != ""
}

// baseURLFromExpression recovers a base URL and the evidence for that
// recovery: a literal scores highest, a resolved constant next, and a value
// containing unresolved fragments (including template placeholders) degrades
// to a placeholder. The value itself comes from the shared evaluator, so a
// baseURL built by concatenation, alias or object property folds exactly like
// a request URL would.
func (w *astWalker) baseURLFromExpression(n *sitter.Node) (string, string) {
	n = unwrap(n)
	v := w.evalExpr(n, w.currentScope(), 0)
	if len(v.opts) == 0 {
		return "", ""
	}
	opt := v.opts[0]
	switch {
	case opt.unknown:
		return opt.text, model.EvidencePlaceholder
	case kind(n) == "string":
		return opt.text, model.EvidenceLiteral
	case kind(n) == "template_string":
		// Keep the historical template convention: a template baseURL keeps
		// placeholder evidence even when every part resolved.
		return opt.text, model.EvidencePlaceholder
	default:
		return opt.text, model.EvidenceConstant
	}
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
