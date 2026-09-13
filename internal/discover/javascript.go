package discover

import (
	"bytes"
	"net/url"
	"path"
	"strings"

	"github.com/youmulijiang/jsowl/internal/analyze"
	"github.com/youmulijiang/jsowl/internal/model"
)

const largeBundleThreshold = 512 * 1024

// FromJavaScript applies extraction rules and detects dynamic-loading signals in JavaScript.
func FromJavaScript(source *url.URL, body []byte, engine *analyze.Engine) JSResult {
	findings, extracted := engine.Analyze(analyze.ResourceRef{
		URL:  source.String(),
		Type: model.ResourceTypeScript,
	}, body)

	result := JSResult{Findings: findings}
	seen := make(map[string]struct{})
	for _, extractedCandidate := range extracted {
		kind := classifyCandidate(extractedCandidate)
		key := string(kind) + "\x00" + extractedCandidate.Raw
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		candidate := Candidate{
			Raw:       extractedCandidate.Raw,
			Kind:      kind,
			SourceURL: source.String(),
			Source:    "regex",
			Method:    extractedCandidate.Method,
		}
		if kind == KindEndpoint && extractedCandidate.Offset > 0 {
			candidate.Line, candidate.Column = lineColumn(body, extractedCandidate.Offset)
			candidate.ContextLines = extractContext(
				body, extractedCandidate.Offset, contextSpanLines,
			)
		}
		result.Candidates = append(result.Candidates, candidate)
	}

	lower := bytes.ToLower(body)
	result.SPA.DynamicImport = bytes.Contains(lower, []byte("import("))
	result.SPA.HistoryRouting = bytes.Contains(lower, []byte("history.pushstate")) ||
		bytes.Contains(lower, []byte("history.replacestate"))
	result.SPA.DynamicScript = bytes.Contains(lower, []byte("createelement(\"script\"")) ||
		bytes.Contains(lower, []byte("createelement('script'"))
	result.SPA.Webpack = bytes.Contains(lower, []byte("webpackchunk")) ||
		bytes.Contains(lower, []byte("__webpack_require__"))
	result.SPA.RequireJS = bytes.Contains(lower, []byte("requirejs.config")) ||
		bytes.Contains(lower, []byte("require.config"))
	result.SPA.LargeBundle = len(body) >= largeBundleThreshold
	return result
}

func classifyCandidate(candidate analyze.Candidate) Kind {
	switch candidate.RuleID {
	case "url.api-call", "url.api-prefix", "url.path-variable":
		return KindEndpoint
	case "url.vue-route":
		return KindRoute
	case "url.webpack-loader":
		return KindChunk
	case "url.static-resource":
		if isJavaScriptPath(candidate.Raw) {
			return KindScript
		}
		return KindAsset
	}
	if isJavaScriptPath(candidate.Raw) {
		return KindScript
	}
	return KindRoute
}

func isJavaScriptPath(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil {
		return false
	}
	switch strings.ToLower(path.Ext(parsed.Path)) {
	case ".js", ".mjs", ".jsx", ".ts", ".tsx":
		return true
	default:
		return false
	}
}

// lineColumn converts a byte offset into 1-based line and rune column.
func lineColumn(body []byte, offset int) (int, int) {
	if offset < 0 || offset > len(body) {
		return 0, 0
	}
	line := countLine(lineStarts(body), offset) + 1
	lineStart := lineStarts(body)[line-1]
	column := len([]rune(string(body[lineStart:offset]))) + 1
	return line, column
}
