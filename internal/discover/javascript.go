package discover

import (
	"bytes"
	"net/url"
	"path"
	"strings"

	"github.com/youmulijiang/jsowl/internal/analyze"
	"github.com/youmulijiang/jsowl/internal/extract"
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
		if (kind == KindEndpoint || kind == KindRoute) &&
			!looksLikePath(extractedCandidate.Raw) {
			// Quoted field names, i18n labels and regex fragments are not
			// request targets; keeping them floods the path reports.
			continue
		}
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
			RuleID:    extractedCandidate.RuleID,
		}
		if (kind == KindEndpoint || kind == KindRoute) &&
			extractedCandidate.Offset > 0 {
			candidate.Line, candidate.Column = lineColumn(body, extractedCandidate.Offset)
			candidate.ContextLines = extractContext(
				body, extractedCandidate.Offset, contextSpanLines,
				extractedCandidate.Raw,
			)
		}
		result.Candidates = append(result.Candidates, candidate)
		// A rule that matched a network URL also produced a host observation:
		// the same value, recorded as host evidence without another body scan.
		if host := hostCandidateFromURL(source, body, extractedCandidate); host != nil {
			result.Hosts = append(result.Hosts, *host)
		}
	}

	lower := bytes.ToLower(body)
	result.SPA.DynamicImport = bytes.Contains(lower, []byte("import("))
	result.SPA.HistoryRouting = bytes.Contains(lower, []byte("history.pushstate")) ||
		bytes.Contains(lower, []byte("history.replacestate"))
	result.SPA.HashRouting = bytes.Contains(lower, []byte("createwebhashhistory")) ||
		bytes.Contains(lower, []byte(`mode:"hash"`)) ||
		bytes.Contains(lower, []byte(`mode:'hash'`))
	result.SPA.DynamicScript = bytes.Contains(lower, []byte("createelement(\"script\"")) ||
		bytes.Contains(lower, []byte("createelement('script'"))
	result.SPA.Webpack = bytes.Contains(lower, []byte("webpackchunk")) ||
		bytes.Contains(lower, []byte("__webpack_require__"))
	result.SPA.RequireJS = bytes.Contains(lower, []byte("requirejs.config")) ||
		bytes.Contains(lower, []byte("require.config"))
	result.SPA.LargeBundle = len(body) >= largeBundleThreshold
	// A base path often lives in a config blob the AST does not model, so the
	// text pass looks for the same assignments.
	result.BasePaths = scanBasePathText(body, maxBasePathsPerFile)
	return result
}

func classifyCandidate(candidate analyze.Candidate) Kind {
	switch candidate.RuleID {
	case "url.api-call", "url.api-prefix", "url.path-variable":
		return KindEndpoint
	case "url.vue-route", "url.react-route-element", "url.react-route-jsx":
		return KindRoute
	case "url.webpack-loader":
		return KindChunk
	case "url.static-resource":
		if isSourceMapPath(candidate.Raw) {
			return KindSourceMap
		}
		if isJavaScriptPath(candidate.Raw) {
			return KindScript
		}
		return KindAsset
	}
	if isSourceMapPath(candidate.Raw) {
		return KindSourceMap
	}
	if isJavaScriptPath(candidate.Raw) {
		return KindScript
	}
	return KindRoute
}

// pathSegmentAlphabet lists the characters allowed inside one relative-path
// segment. Braces are kept so template paths ("/api/{id}") survive.
const pathSegmentAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-{}"

// moduleDirectoryNames lists first path segments that mark a webpack module
// request ("lib/inflate", "utils/common") rather than an application route or
// endpoint. Chunks are full of these; keeping them drowns the real paths.
var moduleDirectoryNames = map[string]struct{}{
	"audio": {}, "blots": {}, "core": {}, "ace": {}, "icon": {},
	"css": {}, "formats": {}, "image": {}, "js": {}, "modules": {},
	"text": {}, "themes": {}, "ui": {}, "video": {}, "static": {},
	"attributors": {}, "application": {}, "lib": {}, "utils": {},
	"lang": {}, "locale": {}, "locales": {}, "plugins": {},
	"directives": {}, "mixins": {}, "node_modules": {}, "dist": {}, "src": {},
}

// looksLikePath reports whether an extracted string can be a request target.
// Minified bundles and i18n dictionaries yield thousands of quoted strings
// that are field names, labels or regex fragments; this gate keeps them out
// of the path reports.
func looksLikePath(value string) bool {
	if value == "" || len(value) > 2048 {
		return false
	}
	for _, char := range value {
		switch char {
		case ' ', '\t', '\n', '\r',
			'(', ')', '[', ']', '<', '>', '|', '\\',
			'^', '$', '*', '"', '\'', '`', ',':
			return false
		}
	}
	if strings.Contains(value, "://") {
		return true
	}
	// "./x" and "../x" are module specifiers, never request targets.
	if strings.HasPrefix(value, "./") || strings.HasPrefix(value, "../") {
		return false
	}
	if strings.HasPrefix(value, "#/") || strings.HasPrefix(value, "/") {
		return true
	}
	// Bare relative path such as "user/login": require at least two
	// identifier-like segments so "mmol/L" or "m/d/yy" are rejected, and
	// drop the module directories chunks are full of.
	segments := strings.Split(value, "/")
	if len(segments) < 2 {
		return false
	}
	if _, module := moduleDirectoryNames[strings.ToLower(segments[0])]; module {
		return false
	}
	for _, segment := range segments {
		if len(segment) < 2 {
			return false
		}
		if strings.Trim(segment, pathSegmentAlphabet) != "" {
			return false
		}
	}
	return true
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

// staticAssetExtensions lists path extensions that never identify an API
// endpoint: images, fonts, stylesheets, media, bundles, documents and
// archives. A quoted "/a/b.png" is a resource reference, not an interface.
// Mirrors the extension filters browser-extension collectors apply.
var staticAssetExtensions = map[string]struct{}{
	// images
	".png": {}, ".jpg": {}, ".jpeg": {}, ".gif": {}, ".webp": {}, ".svg": {},
	".ico": {}, ".bmp": {}, ".tif": {}, ".tiff": {}, ".avif": {},
	// fonts and stylesheets
	".woff": {}, ".woff2": {}, ".ttf": {}, ".otf": {}, ".eot": {}, ".css": {},
	".scss": {}, ".sass": {}, ".less": {}, ".styl": {},
	// media
	".mp3": {}, ".wav": {}, ".ogg": {}, ".flac": {}, ".m4a": {}, ".swf": {},
	".mp4": {}, ".webm": {}, ".avi": {}, ".mov": {}, ".mkv": {},
	// scripts, bundles and source maps
	".js": {}, ".mjs": {}, ".jsx": {}, ".ts": {}, ".tsx": {}, ".map": {},
	// documents, office internals and archives
	".pdf": {}, ".doc": {}, ".docx": {}, ".xls": {}, ".xlsx": {},
	".ppt": {}, ".pptx": {}, ".zip": {}, ".rar": {}, ".7z": {}, ".tar": {},
	".gz": {}, ".dmg": {}, ".exe": {}, ".dll": {}, ".apk": {}, ".iso": {},
	".xml": {}, ".rels": {}, ".bin": {}, ".vml": {},
	// markup and binary blobs
	".html": {}, ".htm": {}, ".wasm": {},
}

// IsStaticAssetPath reports whether a path ends in an extension that is never
// an API endpoint. Query strings and fragments are ignored.
func IsStaticAssetPath(pathname string) bool {
	ext := strings.ToLower(path.Ext(pathname))
	if ext == "" {
		return false
	}
	_, blocked := staticAssetExtensions[ext]
	return blocked
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

// hostCandidateFromURL turns a rule-engine hit on a network URL into a host
// candidate. Values that are not network URLs (paths, filenames, bare
// literals) yield nothing: the rules engine matches request targets, and only
// its URL hits carry a host.
func hostCandidateFromURL(
	source *url.URL,
	body []byte,
	extracted analyze.Candidate,
) *extract.Candidate {
	if _, ok := extract.HostFromNetworkURL(extracted.Raw); !ok {
		return nil
	}
	candidate := extract.Candidate{
		Raw:       extracted.Raw,
		Context:   extract.ContextURL,
		Method:    model.HostMethodRegex,
		SourceURL: source.String(),
	}
	if extracted.Offset > 0 {
		candidate.Line, candidate.Column = lineColumn(body, extracted.Offset)
		candidate.ContextLines = extractContext(
			body, extracted.Offset, contextSpanLines, extracted.Raw,
		)
	}
	return &candidate
}
