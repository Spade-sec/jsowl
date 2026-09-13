package discover

import (
	"net/url"
	"reflect"
	"sort"
	"strings"

	"github.com/dop251/goja/ast"
	"github.com/dop251/goja/file"
	"github.com/dop251/goja/parser"
	"github.com/dop251/goja/token"
	"github.com/youmulijiang/jsowl/internal/model"
)

// apiCall is one HTTP call site recovered from the syntax tree.
type apiCall struct {
	Raw        string
	Method     string
	Evidence   string
	Line       int
	Column     int
	Context    []model.ContextLine
	BodyParams []string
}

// APIFromAST parses JavaScript with a real grammar and recovers HTTP call
// sites that regex extraction misses: wrapped clients, object-literal
// arguments, template URLs and constant baseURL concatenation. Unparsable
// input yields nothing; regex rules remain the fallback.
func APIFromAST(source *url.URL, body []byte) []Candidate {
	program, err := parser.ParseFile(nil, source.String(), body, 0)
	if err != nil || program == nil || len(program.Body) == 0 {
		return nil
	}
	w := &astWalker{
		constants:   make(map[string]string),
		instanceBSE: make(map[string]string),
		file:        program.File,
		source:      body,
	}
	w.walkProgram(program)

	calls := w.calls
	sort.SliceStable(calls, func(i, j int) bool {
		if calls[i].Line != calls[j].Line {
			return calls[i].Line < calls[j].Line
		}
		return calls[i].Raw < calls[j].Raw
	})
	seen := make(map[string]struct{}, len(calls))
	candidates := make([]Candidate, 0, len(calls))
	for _, call := range calls {
		if call.Raw == "" {
			continue
		}
		key := call.Method + "\x00" + call.Raw
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		candidates = append(candidates, Candidate{
			Raw: call.Raw, Kind: KindEndpoint,
			Method: call.Method, Evidence: call.Evidence,
			Line: call.Line, Column: call.Column,
			ContextLines: call.Context, BodyParams: call.BodyParams,
			Source: "ast",
		})
	}
	return candidates
}

type astWalker struct {
	calls       []apiCall
	constants   map[string]string // identifier -> folded string constant
	instanceBSE map[string]string // client instance identifier -> baseURL
	file        *file.File
	source      []byte
}

func (w *astWalker) position(index file.Idx) (int, int) {
	if w.file == nil {
		return 0, 0
	}
	positioned := w.file.Position(int(index) - w.file.Base())
	return positioned.Line, positioned.Column
}

func (w *astWalker) walkProgram(program *ast.Program) {
	for _, item := range program.Body {
		w.walk(item)
	}
}

func (w *astWalker) walk(node ast.Node) {
	// Parser output can carry typed-nil nodes; a plain nil check below would
	// not catch a nil pointer inside a non-nil interface.
	if node == nil {
		return
	}
	if value := reflect.ValueOf(node); value.Kind() == reflect.Pointer && value.IsNil() {
		return
	}
	switch n := node.(type) {
	case *ast.Program:
		for _, item := range n.Body {
			w.walk(item)
		}

	case *ast.VariableDeclaration:
		for _, binding := range n.List {
			w.bind(binding)
			w.walk(binding.Initializer)
		}
	case *ast.VariableStatement:
		for _, binding := range n.List {
			w.bind(binding)
			w.walk(binding.Initializer)
		}
	case *ast.LexicalDeclaration:
		for _, binding := range n.List {
			w.bind(binding)
			w.walk(binding.Initializer)
		}
	case *ast.AssignExpression:
		w.walk(n.Left)
		w.walk(n.Right)
		if n.Operator != token.ASSIGN {
			return
		}
		if identifier, ok := n.Left.(*ast.Identifier); ok {
			if base, ok := axiosCreateBase(n.Right); ok {
				w.instanceBSE[string(identifier.Name)] = base
			} else if literal, ok := n.Right.(*ast.StringLiteral); ok {
				w.constants[string(identifier.Name)] = string(literal.Value)
			}
		}
		if base, ok := baseURLTarget(n.Left); ok {
			w.instanceBSE[base] = baseURLFromExpression(n.Right, w.constants)
		}

	case *ast.BinaryExpression:
		w.walk(n.Left)
		w.walk(n.Right)
	case *ast.UnaryExpression:
		w.walk(n.Operand)
	case *ast.ConditionalExpression:
		w.walk(n.Test)
		w.walk(n.Consequent)
		w.walk(n.Alternate)
	case *ast.SequenceExpression:
		for _, expression := range n.Sequence {
			w.walk(expression)
		}
	case *ast.CallExpression:
		w.visitCall(n.Callee, n.ArgumentList)
	case *ast.NewExpression:
		w.walk(n.Callee)
		for _, argument := range n.ArgumentList {
			w.walk(argument)
		}
	case *ast.DotExpression:
		w.walk(n.Left)
	case *ast.PrivateDotExpression:
		w.walk(n.Left)
	case *ast.OptionalChain:
		w.walk(n.Expression)
	case *ast.Optional:
		w.walk(n.Expression)
	case *ast.BracketExpression:
		w.walk(n.Left)
		w.walk(n.Member)
	case *ast.ArrayLiteral:
		for _, value := range n.Value {
			w.walk(value)
		}
	case *ast.ObjectLiteral:
		for _, property := range n.Value {
			w.walkProperty(property)
		}
	case *ast.ObjectPattern:
		for _, property := range n.Properties {
			w.walkProperty(property)
		}
	case *ast.ArrayPattern:
		for _, element := range n.Elements {
			w.walk(element)
		}
		w.walk(n.Rest)
	case *ast.TemplateLiteral:
		for _, expression := range n.Expressions {
			w.walk(expression)
		}
	case *ast.FunctionLiteral:
		w.walk(n.Body)
	case *ast.ArrowFunctionLiteral:
		switch body := n.Body.(type) {
		case *ast.BlockStatement:
			w.walk(body)
		case *ast.ExpressionBody:
			w.walk(body.Expression)
		}
	case *ast.ClassLiteral:
		for _, element := range n.Body {
			w.walkClassElement(element)
		}
	case *ast.ClassStaticBlock:
		w.walk(n.Block)
	case *ast.SpreadElement:
		w.walk(n.Expression)
	case *ast.BlockStatement:
		for _, item := range n.List {
			w.walk(item)
		}
	case *ast.ExpressionStatement:
		w.walk(n.Expression)
	case *ast.IfStatement:
		w.walk(n.Test)
		w.walk(n.Consequent)
		w.walk(n.Alternate)
	case *ast.ForStatement:
		switch initializer := n.Initializer.(type) {
		case *ast.ForLoopInitializerExpression:
			w.walk(initializer.Expression)
		case *ast.ForLoopInitializerVarDeclList:
			for _, binding := range initializer.List {
				w.bind(binding)
				w.walk(binding.Initializer)
			}
		case *ast.ForLoopInitializerLexicalDecl:
			for _, binding := range initializer.LexicalDeclaration.List {
				w.bind(binding)
				w.walk(binding.Initializer)
			}
		}
		w.walk(n.Test)
		w.walk(n.Update)
		w.walk(n.Body)
	case *ast.ForInStatement:
		w.walkForInto(n.Into)
		w.walk(n.Source)
		w.walk(n.Body)
	case *ast.ForOfStatement:
		w.walkForInto(n.Into)
		w.walk(n.Source)
		w.walk(n.Body)
	case *ast.WhileStatement:
		w.walk(n.Test)
		w.walk(n.Body)
	case *ast.DoWhileStatement:
		w.walk(n.Body)
		w.walk(n.Test)
	case *ast.SwitchStatement:
		w.walk(n.Discriminant)
		for _, item := range n.Body {
			w.walk(item.Test)
			for _, statement := range item.Consequent {
				w.walk(statement)
			}
		}
	case *ast.TryStatement:
		w.walk(n.Body)
		if n.Catch != nil {
			w.walk(n.Catch.Body)
		}
		w.walk(n.Finally)
	case *ast.ReturnStatement:
		w.walk(n.Argument)
	case *ast.ThrowStatement:
		w.walk(n.Argument)
	case *ast.LabelledStatement:
		w.walk(n.Statement)
	case *ast.WithStatement:
		w.walk(n.Object)
		w.walk(n.Body)
	case *ast.FunctionDeclaration:
		w.walk(n.Function.Body)
	case *ast.ClassDeclaration:
		for _, element := range n.Class.Body {
			w.walkClassElement(element)
		}
	case *ast.AwaitExpression:
		w.walk(n.Argument)
	case *ast.YieldExpression:
		w.walk(n.Argument)
	}
}

func (w *astWalker) walkProperty(property ast.Property) {
	switch p := property.(type) {
	case *ast.PropertyKeyed:
		w.walk(p.Key)
		w.walk(p.Value)
	case *ast.PropertyShort:
		w.walk(p.Initializer)
	}
}

func (w *astWalker) walkClassElement(element ast.ClassElement) {
	switch e := element.(type) {
	case *ast.MethodDefinition:
		if e.Body != nil {
			w.walk(e.Body.Body)
		}
	case *ast.FieldDefinition:
		w.walk(e.Initializer)
	case *ast.ClassStaticBlock:
		w.walk(e.Block)
	}
}

func (w *astWalker) walkForInto(into ast.ForInto) {
	switch i := into.(type) {
	case *ast.ForIntoVar:
		w.bind(i.Binding)
		w.walk(i.Binding.Initializer)
	case *ast.ForIntoExpression:
		w.walk(i.Expression)
	}
}

// bind records string-literal constants for later URL folding, and captures
// `client = axios.create({baseURL: ...})` instance bindings.
func (w *astWalker) bind(binding *ast.Binding) {
	if binding == nil || binding.Initializer == nil {
		return
	}
	identifier, ok := binding.Target.(*ast.Identifier)
	if !ok {
		return
	}
	if base, ok := axiosCreateBase(binding.Initializer); ok {
		w.instanceBSE[string(identifier.Name)] = base
		return
	}
	literal, ok := binding.Initializer.(*ast.StringLiteral)
	if !ok {
		return
	}
	w.constants[string(identifier.Name)] = string(literal.Value)
}

// visitCall inspects one call site and records it when the callee matches a
// known HTTP client pattern.
func (w *astWalker) visitCall(callee ast.Expression, args []ast.Expression) {
	w.walk(callee)

	method := ""
	urlArgument := -1
	bodyArgument := -1
	switch expressed := unwrap(callee).(type) {
	case *ast.DotExpression:
		property := string(expressed.Identifier.Name)
		receiver := outermostIdentifierString(expressed.Left)
		switch property {
		case "open":
			// XMLHttpRequest.open(method, url, ...)
			if len(args) >= 2 {
				if literal, ok := unwrap(args[0]).(*ast.StringLiteral); ok {
					method = strings.ToUpper(string(literal.Value))
				}
				urlArgument = 1
			}
		case "get", "post", "put", "patch", "delete", "head", "options",
			"getJSON":
			method = strings.ToUpper(strings.TrimSuffix(property, "JSON"))
			urlArgument = 0
			writeVerb := method == "POST" || method == "PUT" ||
				method == "PATCH" || method == "DELETE"
			if receiver == "ky" {
				// ky.post(url, {json: ...}) keeps the body in the options.
				if arg(args, 1) != nil {
					bodyArgument = -4
				}
			} else if writeVerb {
				bodyArgument = 1
			}
		case "request", "ajax", "api":
			method, urlArgument = objectCallArgs(args)
			bodyArgument = -2 // body rides inside the options object
		case "fetch":
			method = "GET"
			urlArgument = 0
			if fromOptions := optionsMethod(arg(args, 1)); fromOptions != "" {
				method = fromOptions
			}
			if arg(args, 1) != nil {
				bodyArgument = -3 // body may live in the options object
			}
		}
		if receiver == "wx" || receiver == "uni" || receiver == "taro" ||
			receiver == "Taro" || receiver == "my" || receiver == "tt" {
			if property == "request" {
				method, urlArgument = objectCallArgs(args)
				if method == "" {
					method = "GET" // mini-program requests default to GET
				}
				bodyArgument = -2 // mini-program bodies ride in {data: ...}
			}
		}
	case *ast.Identifier:
		switch expressed.Name {
		case "fetch":
			method = "GET"
			urlArgument = 0
			if fromOptions := optionsMethod(arg(args, 1)); fromOptions != "" {
				method = fromOptions
			}
			if arg(args, 1) != nil {
				bodyArgument = -3 // body may live in the options object
			}
		case "ajax", "api":
			method, urlArgument = objectCallArgs(args)
			bodyArgument = -2 // body rides inside the options object
		case "$fetch", "ofetch", "$ofetch", "ky":
			// ofetch/ky callables: url first, options object second.
			method = "GET"
			urlArgument = 0
			if fromOptions := optionsMethod(arg(args, 1)); fromOptions != "" {
				method = fromOptions
			}
			if arg(args, 1) != nil {
				bodyArgument = -5 // {body} for ofetch, {json} for ky
			}
		}
	}
if urlArgument < 0 || urlArgument >= len(args) {
		return
	}
	raw, evidence := w.resolveURLExpression(args[urlArgument])
	if raw == "" {
		return
	}
	line, column := w.position(callee.Idx0())
	context := extractContext(w.source, int(callee.Idx0())-1, contextSpanLines)
	bodyParams := w.bodyParameterNames(args, method, urlArgument, bodyArgument)
	w.calls = append(w.calls, apiCall{
		Raw: raw, Method: method, Evidence: evidence,
		Line: line, Column: column, Context: context, BodyParams: bodyParams,
	})
	// Keep the static relative endpoint and additionally emit the client's
	// bound baseURL folded in, upgraded to full-url evidence.
	if dot, ok := unwrap(callee).(*ast.DotExpression); ok && evidence == model.EvidenceStatic {
		if base, ok := w.instanceBSE[outermostIdentifierString(dot.Left)]; ok && base != "" {
			if joined := joinBaseURL(base, raw); joined != "" {
				w.calls = append(w.calls, apiCall{
					Raw: joined, Method: method, Evidence: model.EvidenceFullURL,
					Line: line, Column: column, Context: context, BodyParams: bodyParams,
				})
			}
		}
	}
}

// objectCallArgs handles request({url, method}) and $.ajax({url, type}).
func objectCallArgs(args []ast.Expression) (method string, urlIndex int) {
	urlIndex = -1
	if len(args) == 0 {
		return "", -1
	}
	switch first := unwrap(args[0]).(type) {
	case *ast.ObjectLiteral:
		for _, property := range first.Value {
			keyed, ok := property.(*ast.PropertyKeyed)
			if !ok {
				continue
			}
			literal, ok := unwrap(keyed.Value).(*ast.StringLiteral)
			if !ok {
				continue
			}
			switch propertyName(keyed.Key) {
			case "url":
				urlIndex = 0
			case "method", "type":
				method = strings.ToUpper(string(literal.Value))
			}
		}
		return method, urlIndex
	case *ast.StringLiteral, *ast.TemplateLiteral:
		return "", 0
	}
	return "", -1
}

// resolveURLExpression extracts a URL string from literals, identifier
// constants, concatenation folds, and templates (as {} placeholders).
func (w *astWalker) resolveURLExpression(expression ast.Expression) (string, string) {
	switch expressed := unwrap(expression).(type) {
	case *ast.StringLiteral:
		return string(expressed.Value), evidenceFor(string(expressed.Value))
	case *ast.Identifier:
		if value, ok := w.constants[string(expressed.Name)]; ok {
			return value, evidenceFor(value)
		}
	case *ast.TemplateLiteral:
		return templatePlaceholder(expressed), model.EvidenceStatic
	case *ast.BinaryExpression:
		if expressed.Operator == token.PLUS {
			if raw, ok := w.foldConcat(expressed, 0); ok {
				return raw, evidenceFor(raw)
			}
		}
	case *ast.ObjectLiteral:
		for _, property := range expressed.Value {
			keyed, ok := property.(*ast.PropertyKeyed)
			if !ok || propertyName(keyed.Key) != "url" {
				continue
			}
			return w.resolveURLExpression(keyed.Value)
		}
	}
	return "", ""
}

// bodyParameterNames collects body field names for write-method calls:
// the second positional argument, the options object's data/body property,
// or FormData.append keys seen inside the call arguments.
func (w *astWalker) bodyParameterNames(args []ast.Expression, method string, urlArgument, bodyArgument int) []string {
	var body ast.Expression
	switch bodyArgument {
	case -2: // request({url, method, data: {...}})
		if options, ok := unwrap(arg(args, 0)).(*ast.ObjectLiteral); ok {
			for _, property := range options.Value {
				keyed, ok := property.(*ast.PropertyKeyed)
				if !ok || propertyName(keyed.Key) != "data" {
					continue
				}
				body = keyed.Value
			}
		}
	case -3: // fetch/ofetch(url, {body: ...})
		if options, ok := unwrap(arg(args, 1)).(*ast.ObjectLiteral); ok {
			for _, property := range options.Value {
				keyed, ok := property.(*ast.PropertyKeyed)
				if !ok || propertyName(keyed.Key) != "body" {
					continue
				}
				body = keyed.Value
			}
		}
	case -4: // ky.post(url, {json: ...})
		if options, ok := unwrap(arg(args, 1)).(*ast.ObjectLiteral); ok {
			for _, property := range options.Value {
				keyed, ok := property.(*ast.PropertyKeyed)
				if !ok || propertyName(keyed.Key) != "json" {
					continue
				}
				body = keyed.Value
			}
		}
	case -5: // ofetch/$fetch/ky(url, {body|json: ...})
		if options, ok := unwrap(arg(args, 1)).(*ast.ObjectLiteral); ok {
			for _, property := range options.Value {
				keyed, ok := property.(*ast.PropertyKeyed)
				if !ok {
					continue
				}
				switch propertyName(keyed.Key) {
				case "body", "json":
					body = keyed.Value
				}
			}
		}
	default:
		if bodyArgument >= 0 && bodyArgument < len(args) {
			body = args[bodyArgument]
		}
	}
	if body == nil {
		return nil
	}
	// JSON.stringify({...}) is the most common fetch body wrapper.
	if call, ok := unwrap(body).(*ast.CallExpression); ok {
		if isStringifyCall(call.Callee) {
			body = arg(call.ArgumentList, 0)
		}
	}
	if object, ok := unwrap(body).(*ast.ObjectLiteral); ok {
		return objectPropertyNames(object)
	}
	return nil
}

// isStringifyCall reports whether the callee is JSON.stringify.
func isStringifyCall(callee ast.Expression) bool {
	dot, ok := unwrap(callee).(*ast.DotExpression)
	return ok && string(dot.Identifier.Name) == "stringify"
}

// objectPropertyNames lists the top-level keys of an object literal,
// including shorthand properties like {username, password}.
func objectPropertyNames(object *ast.ObjectLiteral) []string {
	const maxBodyParams = 32
	names := make([]string, 0, len(object.Value))
	for _, property := range object.Value {
		name := ""
		switch p := property.(type) {
		case *ast.PropertyKeyed:
			name = propertyName(p.Key)
		case *ast.PropertyShort:
			name = string(p.Name.Name)
		}
		if name == "" {
			continue
		}
		names = append(names, name)
		if len(names) >= maxBodyParams {
			break
		}
	}
	return names
}

// optionsMethod reads {method: "..."} / {type: "..."} option objects.
func optionsMethod(expression ast.Expression) string {
	object, ok := unwrap(expression).(*ast.ObjectLiteral)
	if !ok {
		return ""
	}
	for _, property := range object.Value {
		keyed, ok := property.(*ast.PropertyKeyed)
		if !ok {
			continue
		}
		name := propertyName(keyed.Key)
		if name != "method" && name != "type" {
			continue
		}
		if literal, ok := unwrap(keyed.Value).(*ast.StringLiteral); ok {
			return strings.ToUpper(string(literal.Value))
		}
	}
	return ""
}

// foldConcat folds identifier/string concatenation chains such as
// baseURL + "/user/" + id; unknown identifiers become {} placeholders.
func (w *astWalker) foldConcat(expression ast.Expression, depth int) (string, bool) {
	if depth > 8 {
		return "", false
	}
	switch expressed := unwrap(expression).(type) {
	case *ast.BinaryExpression:
		if expressed.Operator != token.PLUS {
			return "", false
		}
		left, leftOK := w.foldConcat(expressed.Left, depth+1)
		right, rightOK := w.foldConcat(expressed.Right, depth+1)
		return left + right, leftOK && rightOK
	case *ast.StringLiteral:
		return string(expressed.Value), true
	case *ast.Identifier:
		if value, ok := w.constants[string(expressed.Name)]; ok {
			return value, true
		}
		return "{}", true
	}
	return "", false
}

// templatePlaceholder renders `…${expr}…` templates with {} placeholders so
// parameterised endpoints still appear in reports.
func templatePlaceholder(template *ast.TemplateLiteral) string {
	var builder strings.Builder
	for index, element := range template.Elements {
		if element.Valid {
			builder.WriteString(string(element.Parsed))
		} else {
			builder.WriteString(element.Literal)
		}
		if index < len(template.Expressions) {
			builder.WriteString("{}")
		}
	}
	return builder.String()
}

func evidenceFor(raw string) string {
	parsed, err := url.Parse(raw)
	if err == nil && (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Host != "" {
		return model.EvidenceFullURL
	}
	return model.EvidenceStatic
}

// axiosCreateBase recognises axios.create({baseURL: ...}) and returns the
// folded baseURL value.
func axiosCreateBase(expression ast.Expression) (string, bool) {
	call, ok := unwrap(expression).(*ast.CallExpression)
	if !ok {
		return "", false
	}
	dot, ok := unwrap(call.Callee).(*ast.DotExpression)
	if !ok || string(dot.Identifier.Name) != "create" {
		return "", false
	}
	receiver := unwrap(dot.Left)
	name := ""
	if identifier, ok := receiver.(*ast.Identifier); ok {
		name = string(identifier.Name)
	}
	if name != "axios" {
		return "", false
	}
	options, ok := arg(call.ArgumentList, 0).(*ast.ObjectLiteral)
	if !ok {
		return "", false
	}
	for _, property := range options.Value {
		keyed, ok := property.(*ast.PropertyKeyed)
		if !ok || propertyName(keyed.Key) != "baseURL" {
			continue
		}
		return baseURLFromExpression(keyed.Value, nil), true
	}
	return "", false
}

// baseURLTarget reports the root identifier of assignments shaped like
// `X.defaults.baseURL = ...` or `X.baseURL = ...`.
func baseURLTarget(left ast.Expression) (string, bool) {
	dot, ok := left.(*ast.DotExpression)
	if !ok || string(dot.Identifier.Name) != "baseURL" {
		return "", false
	}
	return outermostIdentifier(dot.Left)
}

// baseURLFromExpression folds a baseURL expression to a string; anything
// unresolvable degrades to an empty value.
func baseURLFromExpression(expression ast.Expression, constants map[string]string) string {
	switch expressed := unwrap(expression).(type) {
	case *ast.StringLiteral:
		return string(expressed.Value)
	case *ast.Identifier:
		return constants[string(expressed.Name)]
	case *ast.TemplateLiteral:
		return templatePlaceholder(expressed)
	case *ast.BinaryExpression:
		if expressed.Operator == token.PLUS {
			left := baseURLFromExpression(expressed.Left, constants)
			right := baseURLFromExpression(expressed.Right, constants)
			if left != "" && right != "" {
				return left + right
			}
			return left
		}
	}
	return ""
}

// outermostIdentifier walks `a.b.c` chains back to the leading identifier.
func outermostIdentifier(expression ast.Expression) (string, bool) {
	for {
		switch expressed := expression.(type) {
		case *ast.Identifier:
			return string(expressed.Name), true
		case *ast.DotExpression:
			expression = expressed.Left
		case *ast.OptionalChain:
			expression = expressed.Expression
		case *ast.Optional:
			expression = expressed.Expression
		default:
			return "", false
		}
	}
}

// joinBaseURL folds a relative endpoint under an instance baseURL.
func joinBaseURL(base, raw string) string {
	if raw == "" || strings.Contains(raw, "://") || strings.HasPrefix(raw, "//") {
		return ""
	}
	return strings.TrimRight(base, "/") + "/" + strings.TrimLeft(raw, "/")
}

func outermostIdentifierString(expression ast.Expression) string {
	if name, ok := outermostIdentifier(expression); ok {
		return name
	}
	return ""
}

func propertyName(key ast.Expression) string {
	switch k := key.(type) {
	case *ast.StringLiteral:
		return string(k.Value)
	case *ast.Identifier:
		return string(k.Name)
	}
	return ""
}

// unwrap strips parens and optional-chain wrappers so callee inspection sees
// the underlying expression.
func unwrap(expression ast.Expression) ast.Expression {
	for {
		switch paren := expression.(type) {
		case *ast.Optional:
			expression = paren.Expression
		case *ast.OptionalChain:
			expression = paren.Expression
		default:
			return expression
		}
	}
}

func arg(args []ast.Expression, index int) ast.Expression {
	if index < len(args) {
		return args[index]
	}
	return nil
}
