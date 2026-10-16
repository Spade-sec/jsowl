package discover

import (
	"net/url"
	"strconv"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	javascript "github.com/tree-sitter/tree-sitter-javascript/bindings/go"
	"github.com/youmulijiang/jsowl/internal/model"
)

// maxParamHits caps how many parameter hits one file contributes, so a huge
// bundle full of object literals cannot flood the parameter inventory.
const maxParamHits = 500

// minParamNameLen filters single-letter minified names: a property or
// parameter called "t" or "e" is a minifier artifact, not a useful parameter.
const minParamNameLen = 2

// maxConfigDepth bounds how deep nested config objects are flattened
// (config: { retry: { limit: 3 } } still yields limit; deeper stops).
const maxConfigDepth = 2

// jsReservedWords are keywords that can legally appear as property names in
// bundles but never make sense as a request parameter.
var jsReservedWords = map[string]struct{}{
	"break": {}, "case": {}, "catch": {}, "class": {}, "const": {},
	"continue": {}, "debugger": {}, "default": {}, "delete": {}, "do": {},
	"else": {}, "export": {}, "extends": {}, "finally": {}, "for": {},
	"function": {}, "if": {}, "import": {}, "in": {}, "instanceof": {},
	"new": {}, "return": {}, "super": {}, "switch": {}, "this": {},
	"throw": {}, "try": {}, "typeof": {}, "var": {}, "void": {}, "while": {},
	"with": {}, "yield": {}, "let": {}, "static": {}, "enum": {},
	"null": {}, "true": {}, "false": {}, "undefined": {},
}

// ParamsFromAST parses JavaScript with Tree-sitter and extracts parameter
// names from the code shapes the request-oriented AST pass never records on
// its own: object properties bound to variables, destructuring patterns,
// function signatures, literal variable assignments and nested config
// objects. Request-shaped scenarios (API body, URL query, route placeholders)
// are derived from endpoints by the pipeline instead. Results are deduplicated
// per (name, scenario, line) and capped per file.
func ParamsFromAST(source *url.URL, body []byte) []model.ParamHit {
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
	collector := &paramCollector{sourceURL: source, body: body, seen: map[string]struct{}{}}
	collector.walk(root)
	return collector.hits
}

type paramCollector struct {
	sourceURL *url.URL
	body      []byte
	hits      []model.ParamHit
	seen      map[string]struct{}
}

func (c *paramCollector) text(n *sitter.Node) string {
	if n == nil || n.StartByte() > n.EndByte() || n.EndByte() > uint(len(c.body)) {
		return ""
	}
	return string(c.body[n.StartByte():n.EndByte()])
}

func (c *paramCollector) walk(n *sitter.Node) {
	if n == nil || len(c.hits) >= maxParamHits {
		return
	}
	switch n.Kind() {
	case "variable_declarator":
		name := unwrap(n.ChildByFieldName("name"))
		value := unwrap(n.ChildByFieldName("value"))
		if name != nil && value != nil {
			c.recordDeclarator(name, value)
		}
	case "function_declaration", "function", "function_expression",
		"generator_function_declaration", "generator_function":
		c.recordFunctionParams(n)
	case "pair":
		c.recordConfigObject(n)
	}
	for i := uint(0); i < n.NamedChildCount() && len(c.hits) < maxParamHits; i++ {
		c.walk(n.NamedChild(i))
	}
}

// recordDeclarator handles one `const NAME = VALUE` binding: an object value
// contributes its property names (对象属性), an object pattern destructures
// (解构赋值 / 嵌套解构), a string literal makes the variable itself a
// parameter-like constant (变量赋值), and an arrow function contributes its
// signature (函数参数).
func (c *paramCollector) recordDeclarator(name, value *sitter.Node) {
	// Destructuring binds through the declarator's NAME side:
	// const {id, name} = user — the pattern is the name, not the value.
	if name.Kind() == "object_pattern" {
		c.recordPatternNode(name, false)
		return
	}
	switch value.Kind() {
	case "object":
		c.recordObjectProperties(value)
	case "object_pattern":
		c.recordPatternNode(value, false)
	case "string":
		c.recordVariable(name, value)
	case "template_string":
		// Only a fully static template (no substitutions) counts as a
		// literal; anything dynamic is runtime data, not a named constant.
		if !hasTemplateSubstitution(value) {
			c.recordVariable(name, value)
		}
	case "arrow_function", "function_expression":
		c.recordParamList(value, c.text(name))
	}
}

// recordObjectProperties walks an object literal bound to a variable. Its
// top-level property names are object_property hits (const user = { userId:
// 123 } → userId); a property whose value is itself an object literal is a
// config object and its keys are config_object hits.
func (c *paramCollector) recordObjectProperties(object *sitter.Node) {
	for i := uint(0); i < object.NamedChildCount() && len(c.hits) < maxParamHits; i++ {
		child := object.NamedChild(i)
		switch child.Kind() {
		case "pair":
			keyNode := unwrap(child.ChildByFieldName("key"))
			valueNode := unwrap(child.ChildByFieldName("value"))
			if keyNode == nil || kind(keyNode) == "computed_property_name" {
				continue
			}
			name := c.propertyName(keyNode)
			if !usableParamName(name) {
				continue
			}
			if valueNode != nil && valueNode.Kind() == "object" {
				c.recordConfigPairs(valueNode, 1)
				continue
			}
			value, evidence := c.literalValue(valueNode)
			c.add(name, model.ParamScenarioObjectProperty, value, evidence, keyNode)
		case "shorthand_property_identifier", "shorthand_property_identifier_pattern":
			name := c.text(child)
			if !usableParamName(name) {
				continue
			}
			value, evidence := c.literalValue(child)
			c.add(name, model.ParamScenarioObjectProperty, value, evidence, child)
		}
	}
}

// recordConfigPairs records the keys of a config object as config_object
// hits (config: { timeout: 5000 } → timeout), up to maxConfigDepth.
func (c *paramCollector) recordConfigPairs(object *sitter.Node, depth int) {
	for i := uint(0); i < object.NamedChildCount() && len(c.hits) < maxParamHits; i++ {
		child := object.NamedChild(i)
		switch child.Kind() {
		case "pair":
			keyNode := unwrap(child.ChildByFieldName("key"))
			valueNode := unwrap(child.ChildByFieldName("value"))
			if keyNode == nil || kind(keyNode) == "computed_property_name" {
				continue
			}
			name := c.propertyName(keyNode)
			if !usableParamName(name) {
				continue
			}
			if valueNode != nil && valueNode.Kind() == "object" && depth < maxConfigDepth {
				c.recordConfigPairs(valueNode, depth+1)
				continue
			}
			value, evidence := c.literalValue(valueNode)
			c.add(name, model.ParamScenarioConfigObject, value, evidence, keyNode)
		case "shorthand_property_identifier", "shorthand_property_identifier_pattern":
			name := c.text(child)
			if usableParamName(name) {
				value, evidence := c.literalValue(child)
				c.add(name, model.ParamScenarioConfigObject, value, evidence, child)
			}
		}
	}
}

// recordConfigObject is the standalone pair handler: a property anywhere in
// the walk whose value is an object literal is a config shape
// (config: { timeout: 5000 }), regardless of what holds the outer object.
func (c *paramCollector) recordConfigObject(pair *sitter.Node) {
	keyNode := unwrap(pair.ChildByFieldName("key"))
	valueNode := unwrap(pair.ChildByFieldName("value"))
	if keyNode == nil || valueNode == nil || valueNode.Kind() != "object" {
		return
	}
	if kind(keyNode) == "computed_property_name" {
		return
	}
	c.recordConfigPairs(valueNode, 1)
}

// recordPatternNode walks a destructuring pattern (const {id, name} = user).
// Flat bindings are destructuring hits; a binding that nests another object
// pattern produces nested_destructuring hits for both the navigation key and
// the inner names (const {profile: {email}} = data → profile, email).
func (c *paramCollector) recordPatternNode(pattern *sitter.Node, nested bool) {
	for i := uint(0); i < pattern.NamedChildCount() && len(c.hits) < maxParamHits; i++ {
		child := pattern.NamedChild(i)
		switch child.Kind() {
		case "pair_pattern":
			keyNode := unwrap(child.ChildByFieldName("key"))
			valueNode := unwrap(child.ChildByFieldName("value"))
			if keyNode == nil || valueNode == nil {
				continue
			}
			key := c.patternName(keyNode)
			if valueNode.Kind() == "object_pattern" {
				if usableParamName(key) {
					c.add(key, model.ParamScenarioNestedDestructurin, "", "", keyNode)
				}
				c.recordPatternNode(valueNode, true)
				continue
			}
			if !usableParamName(key) {
				continue
			}
			scenario := model.ParamScenarioDestructuring
			if nested {
				scenario = model.ParamScenarioNestedDestructurin
			}
			// const {page: p = 1} = q: the default is the literal.
			value, evidence := "", ""
			if valueNode.Kind() == "assignment_pattern" {
				value, evidence = c.literalValue(unwrap(valueNode.NamedChild(1)))
			}
			c.add(key, scenario, value, evidence, keyNode)
		case "object_assignment_pattern":
			// const {page = 1} = q — shorthand with a default; the grammar
			// wraps left (the identifier) and right (the default) here.
			left := unwrap(child.ChildByFieldName("left"))
			right := unwrap(child.ChildByFieldName("right"))
			if left == nil {
				continue
			}
			name := c.text(left)
			if !usableParamName(name) {
				continue
			}
			scenario := model.ParamScenarioDestructuring
			if nested {
				scenario = model.ParamScenarioNestedDestructurin
			}
			value, evidence := "", ""
			if right != nil {
				value, evidence = c.literalValue(right)
			}
			c.add(name, scenario, value, evidence, left)
		case "shorthand_property_identifier_pattern":
			name := c.text(child)
			if !usableParamName(name) {
				continue
			}
			scenario := model.ParamScenarioDestructuring
			if nested {
				scenario = model.ParamScenarioNestedDestructurin
			}
			c.add(name, scenario, "", "", child)
		case "object_pattern":
			// Rest/nested pattern without a pair wrapper: keep walking it
			// with the same nesting flag.
			c.recordPatternNode(child, nested)
		}
	}
}

// recordFunctionParams records the identifier parameters of a NAMED function
// declaration (function getUser(userId, token)). Minified single-letter
// functions are skipped: their names collide across a bundle and the
// parameters would be pure noise.
func (c *paramCollector) recordFunctionParams(fn *sitter.Node) {
	nameNode := fn.ChildByFieldName("name")
	if nameNode == nil || !usableFunctionName(c.text(nameNode)) {
		return
	}
	c.recordParamList(fn, c.text(nameNode))
}

func (c *paramCollector) recordParamList(fn *sitter.Node, fnName string) {
	parameters := unwrap(fn.ChildByFieldName("parameters"))
	if parameters == nil {
		return
	}
	for i := uint(0); i < parameters.NamedChildCount() && len(c.hits) < maxParamHits; i++ {
		param := unwrap(parameters.NamedChild(i))
		switch param.Kind() {
		case "identifier":
			name := c.text(param)
			if usableParamName(name) {
				c.add(name, model.ParamScenarioFunctionParam, "", "", param)
			}
		case "assignment_pattern":
			// function getUser(page = 1): the name with its default.
			inner := unwrap(param.NamedChild(0))
			if inner != nil && inner.Kind() == "identifier" {
				name := c.text(inner)
				if usableParamName(name) {
					value, evidence := c.literalValue(unwrap(param.NamedChild(1)))
					c.add(name, model.ParamScenarioFunctionParam, value, evidence, inner)
				}
			}
		case "object_pattern":
			// function getUser({userId, token}): destructured parameter.
			c.recordPatternNode(param, false)
		}
	}
}

// recordVariable records a literal variable assignment as a variable-scenario
// hit (const apiKey = "xxx" → apiKey).
func (c *paramCollector) recordVariable(name, value *sitter.Node) {
	if name.Kind() != "identifier" {
		return
	}
	nameText := c.text(name)
	if !usableParamName(nameText) {
		return
	}
	literal, evidence := c.literalValue(value)
	c.add(nameText, model.ParamScenarioVariable, literal, evidence, name)
}

// usableParamName filters names that carry no parameter signal: minified
// single letters, reserved words, language internals, and — per the report's
// requirement — anything that is not a plain English identifier. Names
// carrying CJK text or other symbols (用户ID, $scope, a.b, kebab-case) are
// dropped so the extracted inventory stays ASCII-only.
func usableParamName(name string) bool {
	if len(name) < minParamNameLen || name != strings.TrimSpace(name) {
		return false
	}
	if _, reserved := jsReservedWords[name]; reserved {
		return false
	}
	switch name {
	case "prototype", "constructor", "__proto__", "length", "arguments":
		return false
	}
	return isEnglishParamName(name)
}

// isEnglishParamName reports whether a name is a plausible English parameter
// identifier: only ASCII letters, digits and underscores, with at least one
// letter. A leading digit is tolerated (2fa_code) but a name made of digits
// alone is not, and any non-ASCII rune or symbol fails.
func isEnglishParamName(name string) bool {
	letters := false
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
			letters = true
		case r >= '0' && r <= '9', r == '_':
		default:
			return false
		}
	}
	return letters
}

// usableFunctionName gates function-parameter extraction on a meaningful
// function name: single-letter minified names produce nothing but noise.
func usableFunctionName(name string) bool {
	return len(name) > 1
}

// literalValue renders a node as a literal when it is one: strings decode
// their escapes, numbers/booleans keep their text, and everything dynamic
// yields nothing (the hit keeps the name only).
func (c *paramCollector) literalValue(n *sitter.Node) (string, string) {
	n = unwrap(n)
	if n == nil {
		return "", ""
	}
	switch kind(n) {
	case "string":
		return decodeJSString(c.text(n)), model.EvidenceLiteral
	case "template_string":
		if hasTemplateSubstitution(n) {
			return "", ""
		}
		return c.templateText(n), model.EvidenceLiteral
	case "number", "true", "false", "null", "undefined":
		return c.text(n), model.EvidenceLiteral
	}
	return "", ""
}

// hasTemplateSubstitution reports whether a template string embeds any
// expression (${...}).
func hasTemplateSubstitution(n *sitter.Node) bool {
	for i := uint(0); i < n.NamedChildCount(); i++ {
		if n.NamedChild(i).Kind() == "template_substitution" {
			return true
		}
	}
	return false
}

// templateText renders a static template string's text content.
func (c *paramCollector) templateText(n *sitter.Node) string {
	var out strings.Builder
	for i := uint(0); i < n.NamedChildCount(); i++ {
		child := n.NamedChild(i)
		switch child.Kind() {
		case "string_fragment":
			out.WriteString(c.text(child))
		case "escape_sequence":
			out.WriteString(decodeJSEscapes(c.text(child)))
		}
	}
	return out.String()
}

// patternName extracts the identifier a destructuring binding navigates by:
// profile in const {profile: {email}} = data.
func (c *paramCollector) patternName(n *sitter.Node) string {
	n = unwrap(n)
	switch kind(n) {
	case "identifier", "property_identifier", "shorthand_property_identifier_pattern":
		return c.text(n)
	case "string":
		return decodeJSString(c.text(n))
	}
	return ""
}

// propertyName mirrors the walker's key decoder but on the collector's body.
func (c *paramCollector) propertyName(n *sitter.Node) string {
	n = unwrap(n)
	if kind(n) == "string" {
		return decodeJSString(c.text(n))
	}
	switch kind(n) {
	case "identifier", "property_identifier", "private_property_identifier",
		"shorthand_property_identifier", "shorthand_property_identifier_pattern":
		return c.text(n)
	}
	return ""
}

// add appends one hit unless the same (name, scenario, line) already exists
// in this file. Context lines are extracted around the match so the report
// can show the shape without re-downloading the bundle.
func (c *paramCollector) add(name, scenario, value, evidence string, at *sitter.Node) {
	if len(c.hits) >= maxParamHits {
		return
	}
	point := at.StartPosition()
	line, column := int(point.Row)+1, int(point.Column)+1
	key := name + "\x00" + scenario + "\x00" + strconv.Itoa(line)
	if _, duplicate := c.seen[key]; duplicate {
		return
	}
	c.seen[key] = struct{}{}
	source := ""
	if c.sourceURL != nil {
		source = c.sourceURL.String()
	}
	c.hits = append(c.hits, model.ParamHit{
		Name:      name,
		Scenario:  scenario,
		Value:     value,
		Evidence:  evidence,
		SourceURL: source,
		Line:      line,
		Column:    column,
		ContextLines: extractContext(
			c.body, int(at.StartByte()), contextSpanLines, name,
		),
	})
}
