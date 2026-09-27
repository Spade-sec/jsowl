package discover

import (
	sitter "github.com/tree-sitter/go-tree-sitter"
	javascript "github.com/tree-sitter/tree-sitter-javascript/bindings/go"
	"strings"
)

// maxASTWebpackBody bounds how much of a bundle is parsed for the AST webpack
// pass. Beyond a few megabytes the parse cost outweighs the chance of finding
// another runtime, and the regex pass still runs on the raw bytes.
const maxASTWebpackBody = 8 * 1024 * 1024

// webpackSeg is one piece of a symbolically evaluated chunk-filename
// expression: a literal string, the runtime's chunk-id parameter, or a
// reference to a {key: value} map subscripted by that parameter.
type webpackSeg struct {
	kind   byte // 'l' literal, 'p' parameter, 'm' map
	lit    string
	mapIdx int
}

// webpackASTExtract recovers the chunk-name maps and the publicPath from a
// webpack runtime through the tree-sitter AST. Unlike the regex pass it
// handles plain-function runtimes, template strings, subscript property
// access (r["u"]) and arbitrary + / join("") expression shapes, because it
// evaluates the .u function body against its parameter symbolically instead
// of matching one spelling of it.
func webpackASTExtract(body []byte) (publicPath string, filenames []string) {
	if len(body) == 0 || len(body) > maxASTWebpackBody {
		return "", nil
	}
	parser := sitter.NewParser()
	defer parser.Close()
	if err := parser.SetLanguage(sitter.NewLanguage(javascript.Language())); err != nil {
		return "", nil
	}
	tree := parser.Parse(body, nil)
	if tree == nil {
		return "", nil
	}
	defer tree.Close()
	root := tree.RootNode()
	if root == nil {
		return "", nil
	}

	finder := &webpackRuntimeFinder{source: body}
	finder.walk(root)

	if finder.publicPath != "" {
		publicPath = finder.publicPath
	}
	for _, result := range finder.runtimes {
		filenames = append(filenames, result.filenames()...)
	}
	// Map-less runtimes (no content-hash output) carry no chunk names, only
	// the id placeholder: enumerate the ids from the .e(<id>) call sites.
	for _, result := range finder.runtimes {
		if len(result.maps) > 0 || !result.hasParam() {
			continue
		}
		for _, id := range finder.chunkIDs {
			if filename, complete := renderSegments(result.segments, id, nil); complete {
				filenames = append(filenames, webpackChunkFile(filename))
			}
		}
	}
	return publicPath, filenames
}

type webpackRuntime struct {
	segments []webpackSeg
	maps     []map[string]string
}

// hasParam reports whether the evaluated filename expression references the
// runtime's chunk-id parameter.
func (r webpackRuntime) hasParam() bool {
	for _, segment := range r.segments {
		if segment.kind == 'p' {
			return true
		}
	}
	return false
}

type webpackRuntimeFinder struct {
	source     []byte
	runtimes   []webpackRuntime
	publicPath string
	// chunkIDs collects the literal ids passed to __webpack_require__.e(<id>)
	// call sites. Map-less runtimes (no content-hash output) can only be
	// enumerated through them.
	chunkIDs []string
}

func (f *webpackRuntimeFinder) walk(n *sitter.Node) {
	if n == nil {
		return
	}
	switch kind(n) {
	case "assignment_expression":
		f.visitAssignment(n)
	case "call_expression":
		f.visitECall(n)
		f.visitDefineProperty(n)
	}
	for i := 0; i < int(n.ChildCount()); i++ {
		f.walk(n.Child(uint(i)))
	}
}

// visitAssignment handles X.u = <function> and X.p = <expression>, including
// the subscript spellings X["u"] / X['p'] that minifiers emit.
func (f *webpackRuntimeFinder) visitAssignment(node *sitter.Node) {
	left := node.ChildByFieldName("left")
	right := node.ChildByFieldName("right")
	if left == nil || right == nil {
		return
	}
	property := f.webpackAssignedProperty(left)
	switch property {
	case "u":
		if fn := webpackRuntimeFunction(right); fn != nil {
			if runtime, ok := f.evaluateRuntime(fn); ok {
				f.runtimes = append(f.runtimes, runtime)
			}
		}
	case "p":
		if segments := f.evaluate(right, "", nil); segments != nil {
			if value, complete := renderSegments(segments, "", nil); complete {
				f.publicPath = value
			}
		}
	}
}

// visitECall collects literal chunk ids from lazy-load triggers such as
// __webpack_require__.e(123) and its minified r.e("vendors") spellings.
func (f *webpackRuntimeFinder) visitECall(node *sitter.Node) {
	function := unwrap(node.ChildByFieldName("function"))
	arguments := node.ChildByFieldName("arguments")
	if function == nil || arguments == nil || arguments.NamedChildCount() == 0 {
		return
	}
	if f.webpackAssignedProperty(function) != "e" {
		return
	}
	arg := unwrap(arguments.NamedChild(0))
	switch kind(arg) {
	case "number":
		f.chunkIDs = append(f.chunkIDs, f.text(arg))
	case "string":
		if id := decodeJSString(f.text(arg)); id != "" {
			f.chunkIDs = append(f.chunkIDs, id)
		}
	}
}

// visitDefineProperty handles the Object.defineProperty(X, "u", {value: fn})
// spelling some builds use instead of a plain assignment.
func (f *webpackRuntimeFinder) visitDefineProperty(node *sitter.Node) {
	function := unwrap(node.ChildByFieldName("function"))
	if kind(function) != "member_expression" ||
		f.text(function.ChildByFieldName("property")) != "defineProperty" {
		return
	}
	object := unwrap(function.ChildByFieldName("object"))
	if kind(object) != "identifier" || f.text(object) != "Object" {
		return
	}
	arguments := node.ChildByFieldName("arguments")
	if arguments == nil || arguments.NamedChildCount() < 3 {
		return
	}
	name := ""
	target := unwrap(arguments.NamedChild(1))
	switch kind(target) {
	case "string", "string_literal":
		name = decodeJSString(f.text(target))
	case "number":
		name = f.text(target)
	}
	definition := unwrap(arguments.NamedChild(2))
	if kind(definition) != "object" {
		return
	}
	var value *sitter.Node
	for i := 0; i < int(definition.NamedChildCount()); i++ {
		pair := definition.NamedChild(uint(i))
		if kind(pair) != "pair" {
			continue
		}
		switch f.text(pair.ChildByFieldName("key")) {
		case "value", "get":
			value = unwrap(pair.ChildByFieldName("value"))
		}
	}
	if value == nil {
		return
	}
	switch name {
	case "u":
		if fn := webpackRuntimeFunction(value); fn != nil {
			if runtime, ok := f.evaluateRuntime(fn); ok {
				f.runtimes = append(f.runtimes, runtime)
			}
		}
	case "p":
		if segments := f.evaluate(value, "", nil); segments != nil {
			if rendered, complete := renderSegments(segments, "", nil); complete {
				f.publicPath = rendered
			}
		}
	}
}

// webpackAssignedProperty returns the property name an assignment writes to.
func (f *webpackRuntimeFinder) webpackAssignedProperty(left *sitter.Node) string {
	left = unwrap(left)
	switch kind(left) {
	case "member_expression":
		return decodeJSString(f.text(left.ChildByFieldName("property")))
	case "subscript_expression":
		index := unwrap(left.ChildByFieldName("index"))
		if kind(index) == "string" || kind(index) == "string_literal" {
			return decodeJSString(f.text(index))
		}
	}
	return ""
}

// webpackRuntimeFunction accepts both runtime spellings the regex pass
// cannot: arrow functions and plain functions.
func webpackRuntimeFunction(right *sitter.Node) *sitter.Node {
	right = unwrap(right)
	switch kind(right) {
	case "arrow_function", "function_expression", "function":
		return right
	}
	return nil
}

// evaluateRuntime symbolically evaluates a .u function body against its
// parameter. The parameter becomes a segment placeholder; every object
// literal subscripted by the parameter is lifted into a name/hash map.
func (f *webpackRuntimeFinder) evaluateRuntime(fn *sitter.Node) (webpackRuntime, bool) {
	parameters := fn.ChildByFieldName("parameters")
	if parameters == nil {
		// A single-parameter arrow function exposes its binding through the
		// "parameter" field instead of a formal_parameters list.
		parameters = fn.ChildByFieldName("parameter")
	}
	body := fn.ChildByFieldName("body")
	if parameters == nil || body == nil {
		return webpackRuntime{}, false
	}
	var param string
	if kind(parameters) == "identifier" {
		param = f.text(parameters)
	} else {
		for i := 0; i < int(parameters.NamedChildCount()); i++ {
			child := parameters.NamedChild(uint(i))
			if kind(child) == "identifier" {
				param = f.text(child)
				break
			}
		}
	}
	if param == "" {
		return webpackRuntime{}, false
	}

	runtime := webpackRuntime{maps: []map[string]string{}}
	runtime.segments = f.evaluate(body, param, &runtime)
	if runtime.segments == nil {
		// Map-less runtimes are still valid: their chunks are enumerated
		// from the .e(<id>) call sites instead of a name/hash map.
		return webpackRuntime{}, false
	}
	return runtime, true
}

// evaluate reduces an expression node to a segment list. A nil result with
// ok=false semantics is expressed as nil: unsupported shapes simply abort
// this branch and leave the chunk to the regex pass.
func (f *webpackRuntimeFinder) evaluate(
	node *sitter.Node,
	param string,
	runtime *webpackRuntime,
) []webpackSeg {
	node = unwrap(node)
	if node == nil {
		return nil
	}
	switch kind(node) {
	case "string", "string_literal":
		literal := decodeJSString(f.text(node))
		if literal == "" && len(f.text(node)) > 2 {
			return nil
		}
		return []webpackSeg{{kind: 'l', lit: literal}}

	case "template_string":
		segments := make([]webpackSeg, 0, 2)
		for i := 0; i < int(node.NamedChildCount()); i++ {
			child := node.NamedChild(uint(i))
			switch kind(child) {
			case "string_fragment":
				segments = append(segments, webpackSeg{kind: 'l', lit: f.text(child)})
			case "template_substitution":
				inner := f.evaluate(unwrap(child.NamedChild(0)), param, runtime)
				if inner == nil {
					return nil
				}
				segments = append(segments, inner...)
			default:
				return nil
			}
		}
		return segments

	// A plain-function runtime body is a statement block; its return value
	// is the chunk expression.
	case "statement_block":
		for i := 0; i < int(node.NamedChildCount()); i++ {
			if segments := f.evaluate(node.NamedChild(uint(i)), param, runtime); segments != nil {
				return segments
			}
		}
		return nil

	case "return_statement", "expression_statement":
		if node.NamedChildCount() == 0 {
			return nil
		}
		return f.evaluate(unwrap(node.NamedChild(0)), param, runtime)

	case "binary_expression":
		if f.text(node.ChildByFieldName("operator")) != "+" {
			return nil
		}
		left := f.evaluate(node.ChildByFieldName("left"), param, runtime)
		right := f.evaluate(node.ChildByFieldName("right"), param, runtime)
		if left == nil || right == nil {
			return nil
		}
		return append(left, right...)

	case "identifier":
		if param != "" && f.text(node) == param {
			return []webpackSeg{{kind: 'p'}}
		}
		return nil

	case "subscript_expression":
		object := unwrap(node.ChildByFieldName("object"))
		index := unwrap(node.ChildByFieldName("index"))
		if kind(object) != "object" || kind(index) != "identifier" || f.text(index) != param {
			return nil
		}
		mapping := webpackObjectPairs(f, object)
		if len(mapping) == 0 {
			return nil
		}
		runtime.maps = append(runtime.maps, mapping)
		return []webpackSeg{{kind: 'm', mapIdx: len(runtime.maps) - 1}}

	case "call_expression":
		return f.evaluateCall(node, param, runtime)

	case "undefined", "null", "void":
		return nil
	}
	return nil
}

// evaluateCall handles Array.prototype.join("") over literals, the one call
// shape webpack runtimes use for chunk assembly.
func (f *webpackRuntimeFinder) evaluateCall(
	node *sitter.Node,
	param string,
	runtime *webpackRuntime,
) []webpackSeg {
	function := node.ChildByFieldName("function")
	arguments := node.ChildByFieldName("arguments")
	if kind(function) != "member_expression" || arguments == nil {
		return nil
	}
	if decodeJSString(f.text(function.ChildByFieldName("property"))) == "join" {
		return f.evaluateJoin(node, function, arguments, param, runtime)
	}
	if decodeJSString(f.text(function.ChildByFieldName("property"))) == "concat" {
		return f.evaluateConcat(function, arguments, param, runtime)
	}
	return nil
}

// evaluateConcat folds String.prototype.concat call chains into a segment
// concatenation, the same semantics the + operator already has.
func (f *webpackRuntimeFinder) evaluateConcat(
	function *sitter.Node,
	arguments *sitter.Node,
	param string,
	runtime *webpackRuntime,
) []webpackSeg {
	segments := f.evaluate(unwrap(function.ChildByFieldName("object")), param, runtime)
	if segments == nil {
		return nil
	}
	for i := 0; i < int(arguments.NamedChildCount()); i++ {
		element := f.evaluate(unwrap(arguments.NamedChild(uint(i))), param, runtime)
		if element == nil {
			return nil
		}
		segments = append(segments, element...)
	}
	return segments
}

// evaluateJoin folds Array.prototype.join over an array literal; only the
// empty-separator join appears in chunk runtimes.
func (f *webpackRuntimeFinder) evaluateJoin(
	_ *sitter.Node,
	function *sitter.Node,
	arguments *sitter.Node,
	param string,
	runtime *webpackRuntime,
) []webpackSeg {
	separator := ""
	if arguments.NamedChildCount() == 1 {
		sep := f.evaluate(unwrap(arguments.NamedChild(0)), param, runtime)
		if sep == nil || len(sep) != 1 || sep[0].kind != 'l' {
			return nil
		}
		separator = sep[0].lit
	}
	if separator != "" {
		// Anything but the empty separator would need a different render
		// strategy.
		return nil
	}
	object := unwrap(function.ChildByFieldName("object"))
	if kind(object) != "array" {
		return nil
	}
	segments := make([]webpackSeg, 0, int(object.NamedChildCount()))
	for i := 0; i < int(object.NamedChildCount()); i++ {
		element := f.evaluate(object.NamedChild(uint(i)), param, runtime)
		if element == nil {
			return nil
		}
		segments = append(segments, element...)
	}
	return segments
}

// webpackObjectPairs extracts the string key/value pairs of one object
// literal straight from AST pair nodes, so keys and values cannot bleed
// across neighbouring objects the way the regex sweep can.
func webpackObjectPairs(f *webpackRuntimeFinder, object *sitter.Node) map[string]string {
	mapping := make(map[string]string)
	for i := 0; i < int(object.NamedChildCount()); i++ {
		pair := object.NamedChild(uint(i))
		if kind(pair) != "pair" {
			continue
		}
		key := pair.ChildByFieldName("key")
		value := unwrap(pair.ChildByFieldName("value"))
		name := ""
		switch kind(key) {
		case "property_identifier":
			name = f.text(key)
		case "string", "string_literal":
			name = decodeJSString(f.text(key))
		case "number":
			name = f.text(key)
		default:
			continue
		}
		if kind(value) != "string" && kind(value) != "string_literal" {
			continue
		}
		if decoded := decodeJSString(f.text(value)); decoded != "" {
			mapping[name] = decoded
		}
	}
	return mapping
}

// filenames turns one evaluated runtime into concrete chunk filenames.
func (r webpackRuntime) filenames() []string {
	if len(r.maps) == 0 {
		// Map-less runtimes are enumerated from .e(<id>) call sites by the
		// caller, not here.
		return nil
	}
	names, hashes := r.pairMaps()
	if names == nil {
		// Single map: the parameter is the chunk id and the map carries the
		// whole filename fragment.
		single := r.maps[0]
		filenames := make([]string, 0, len(single))
		for _, key := range sortedMapKeys(single) {
			filename, complete := renderSegments(r.segments, key, map[int]string{0: single[key]})
			if !complete {
				continue
			}
			filenames = append(filenames, webpackChunkFile(filename))
		}
		return filenames
	}
	filenames := make([]string, 0, len(names))
	for _, key := range sortedMapKeys(names) {
		filename, complete := renderSegments(r.segments, key, map[int]string{0: names[key], 1: hashes[key]})
		if !complete {
			continue
		}
		filenames = append(filenames, webpackChunkFile(filename))
	}
	return filenames
}

// pairMaps picks the name map and the hash map out of the evaluated maps.
// With exactly one map there is no pairing. With two it reuses the proven
// hashScore heuristic; with more it requires all maps to share keys and
// picks the two clearest, falling back to nil when ambiguous.
func (r webpackRuntime) pairMaps() (names, hashes map[string]string) {
	if len(r.maps) == 1 {
		return nil, nil
	}
	for i := 0; i < len(r.maps); i++ {
		for j := i + 1; j < len(r.maps); j++ {
			if !sameMapKeys(r.maps[i], r.maps[j]) {
				continue
			}
			a, b := r.maps[i], r.maps[j]
			if hashScore(a) > hashScore(b) {
				a, b = b, a
			}
			if hashScore(b) < 1 || hashScore(a) >= hashScore(b) {
				continue
			}
			return a, b
		}
	}
	return nil, nil
}

// renderSegments substitutes the parameter and map references in a segment
// list. Substitutions is keyed by the order the map segments appear; any
// segment without a substitution leaves the result incomplete.
func renderSegments(
	segments []webpackSeg,
	param string,
	substitutions map[int]string,
) (string, bool) {
	var out strings.Builder
	mapOrdinal := 0
	for _, segment := range segments {
		switch segment.kind {
		case 'l':
			out.WriteString(segment.lit)
		case 'p':
			out.WriteString(param)
		case 'm':
			value, ok := substitutions[mapOrdinal]
			mapOrdinal++
			if !ok {
				return "", false
			}
			out.WriteString(value)
		}
	}
	return out.String(), true
}

// webpackChunkFile appends the .js extension webpack leaves to the .u
// expression.
func webpackChunkFile(filename string) string {
	if strings.HasSuffix(strings.ToLower(filename), ".js") {
		return filename
	}
	return filename + ".js"
}

func (f *webpackRuntimeFinder) text(n *sitter.Node) string {
	if n == nil || n.StartByte() > n.EndByte() || n.EndByte() > uint(len(f.source)) {
		return ""
	}
	return string(f.source[n.StartByte():n.EndByte()])
}
