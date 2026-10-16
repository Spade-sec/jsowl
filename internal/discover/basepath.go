package discover

import (
	"path"
	"regexp"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"

	"github.com/youmulijiang/jsowl/internal/model"
)

// A base path is the prefix an application puts in front of its interfaces —
// axios.create({ baseURL: "/api" }) or a config blob carrying "baseUrl": "/v1".
// JsOwl records the prefixes it sees so relative references can be tried under
// them, because a reference written as "/users" does not say whether the
// application actually requests "/users" or "/api/users".

// maxBasePathsPerFile caps how many prefixes one file contributes.
const maxBasePathsPerFile = 8

// maxBasePathLength bounds a plausible prefix; anything longer is not a base.
const maxBasePathLength = 64

// basePathKeys are the binding names whose value is a base path. The set is
// deliberately conservative: a name that merely might be a prefix would add
// probe traffic without adding information.
var basePathKeys = map[string]struct{}{
	"baseurl": {}, "base_url": {}, "basepath": {}, "base_path": {},
	"apibase": {}, "api_base": {}, "apibaseurl": {}, "api_base_url": {},
	"apiprefix": {}, "api_prefix": {}, "baseapi": {}, "base_api": {},
	"vue_app_base_api": {}, "apiroot": {}, "api_root": {}, "apirooturl": {},
}

// isBasePathFieldName reports whether a binding name holds a base path.
func isBasePathFieldName(name string) bool {
	if name == "" {
		return false
	}
	_, ok := basePathKeys[strings.ToLower(name)]
	return ok
}

// basePathAssignmentPattern finds the same information in text the AST cannot
// read: a JSON or config blob carrying "baseUrl": "/api".
var basePathAssignmentPattern = regexp.MustCompile(
	`(?i)["']?(?:base_?url|base_?path|api_?base|api_?prefix|base_?api|api_?root|vue_app_base_api)["']?\s*[:=]\s*["'](\/[A-Za-z0-9._~\-/]{0,63})["']`,
)

// normalizeBasePath accepts a value only when it is a plain absolute path
// prefix: start with "/", no scheme, query, fragment or whitespace, bounded
// length, cleaned of redundant separators, and never just "/".
func normalizeBasePath(raw string) (string, bool) {
	value := strings.TrimSpace(raw)
	if value == "" || len(value) > maxBasePathLength {
		return "", false
	}
	if !strings.HasPrefix(value, "/") {
		return "", false
	}
	if strings.ContainsAny(value, " \t\r\n\\?#\"'<>|*") || strings.Contains(value, "://") {
		return "", false
	}
	for index := 0; index < len(value); index++ {
		char := value[index]
		switch {
		case char >= 'a' && char <= 'z', char >= 'A' && char <= 'Z':
		case char >= '0' && char <= '9':
		case char == '/', char == '.', char == '-', char == '_', char == '~':
		default:
			return "", false
		}
	}
	cleaned := path.Clean(value)
	if cleaned == "/" || cleaned == "." || cleaned == "" {
		return "", false
	}
	if !strings.HasPrefix(cleaned, "/") {
		return "", false
	}
	return cleaned, true
}

// BasePathCandidate is one path prefix recovered from a source, with the place
// it was read from so reports can explain where the guess came from.
type BasePathCandidate struct {
	Path   string
	Source string
	Method string
	Line   int
	Column int
	// ContextLines carries the surrounding source lines of the match.
	ContextLines []model.ContextLine
}

// scanBasePathText finds base-path assignments in text the AST could not read
// (an inlined JSON config, a stringified settings blob).
func scanBasePathText(body []byte, limit int) []BasePathCandidate {
	if len(body) == 0 || limit <= 0 {
		return nil
	}
	found := make([]BasePathCandidate, 0, 4)
	seen := map[string]struct{}{}
	for _, match := range basePathAssignmentPattern.FindAllSubmatchIndex(body, -1) {
		if len(match) < 4 || match[2] < 0 {
			continue
		}
		raw := string(body[match[2]:match[3]])
		prefix, ok := normalizeBasePath(raw)
		if !ok {
			continue
		}
		if _, duplicate := seen[prefix]; duplicate {
			continue
		}
		seen[prefix] = struct{}{}
		line, column := lineColumn(body, match[2])
		found = append(found, BasePathCandidate{
			Path: prefix, Source: "regex", Method: model.HostMethodRegex,
			Line: line, Column: column,
			ContextLines: extractContext(body, match[2], contextSpanLines, raw),
		})
		if len(found) >= limit {
			break
		}
	}
	return found
}

// recordBasePath stores one prefix value read from a base-path binding. It
// reports whether the value was a path: a baseURL holding a URL or a bare host
// is not a prefix and stays host evidence.
func (c *hostCollector) recordBasePath(n *sitter.Node) bool {
	if n == nil || len(c.basePaths) >= maxBasePathsPerFile {
		return false
	}
	raw, ok := c.staticOperand(n)
	if !ok {
		return false
	}
	prefix, ok := normalizeBasePath(raw)
	if !ok {
		return false
	}
	for _, existing := range c.basePaths {
		if existing.Path == prefix {
			return true
		}
	}
	line, column := int(n.StartPosition().Row)+1, int(n.StartPosition().Column)+1
	c.basePaths = append(c.basePaths, BasePathCandidate{
		Path: prefix, Source: "ast", Method: model.HostMethodASTLiteral,
		Line: line, Column: column,
		ContextLines: extractContext(c.body, int(n.StartByte()), contextSpanLines, raw),
	})
	return true
}

// staticOperand resolves a node to a literal string when it is one: a string
// literal, a template without substitutions or an all-literal concatenation.
func (c *hostCollector) staticOperand(n *sitter.Node) (string, bool) {
	n = unwrap(n)
	if n == nil {
		return "", false
	}
	switch n.Kind() {
	case "string":
		return decodeJSString(c.text(n)), true
	case "template_string":
		if hasTemplateSubstitution(n) {
			return "", false
		}
		return c.templateText(n), true
	case "binary_expression":
		return c.staticString(n)
	}
	return "", false
}

// BasePathNames renders candidates as the plain prefix list the pipeline keeps.
func BasePathNames(candidates []BasePathCandidate) []string {
	paths := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.Path != "" {
			paths = append(paths, candidate.Path)
		}
	}
	return paths
}
