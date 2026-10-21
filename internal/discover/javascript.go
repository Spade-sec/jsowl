package discover

import (
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
	return fromJavaScript(source, body, newLineIndex(body), engine, true)
}

// FromJavaScriptDiscovery is the download-phase variant: it runs only the URL
// rules and returns the candidates (plus SPA evidence) needed to discover and
// fetch follow-up resources. Sensitive rules, findings, host candidates and
// match context are skipped because the deferred analysis pass produces them
// from the saved file. The candidate set is identical to FromJavaScript's:
// the engine only ever derives candidates from URL-category rules.
func FromJavaScriptDiscovery(
	source *url.URL,
	body []byte,
	engine *analyze.Engine,
) JSResult {
	return fromJavaScript(source, body, newLineIndex(body), engine, false)
}

func fromJavaScript(
	source *url.URL,
	body []byte,
	lines *lineIndex,
	engine *analyze.Engine,
	full bool,
) JSResult {
	var findings []model.Finding
	var extracted []analyze.Candidate
	if full {
		findings, extracted = engine.Analyze(analyze.ResourceRef{
			URL:  source.String(),
			Type: model.ResourceTypeScript,
		}, body)
	} else {
		extracted = engine.AnalyzeCandidates(analyze.ResourceRef{
			URL:  source.String(),
			Type: model.ResourceTypeScript,
		}, body)
	}

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
			candidate.Line, candidate.Column = lines.position(extractedCandidate.Offset)
			if full {
				candidate.ContextLines = lines.extract(
					extractedCandidate.Offset, contextSpanLines,
					extractedCandidate.Raw,
				)
			}
		}
		result.Candidates = append(result.Candidates, candidate)
		// A rule that matched a network URL also produced a host observation:
		// the same value, recorded as host evidence without another body scan.
		if full {
			if host := hostCandidateFromURL(source, lines, extractedCandidate); host != nil {
				result.Hosts = append(result.Hosts, *host)
			}
		}
	}

	result.SPA.DynamicImport = containsFold(body, []byte("import("))
	result.SPA.HistoryRouting = containsFold(body, []byte("history.pushstate")) ||
		containsFold(body, []byte("history.replacestate"))
	result.SPA.HashRouting = containsFold(body, []byte("createwebhashhistory")) ||
		containsFold(body, []byte(`mode:"hash"`)) ||
		containsFold(body, []byte(`mode:'hash'`))
	result.SPA.DynamicScript = containsFold(body, []byte("createelement(\"script\"")) ||
		containsFold(body, []byte("createelement('script'"))
	result.SPA.Webpack = containsFold(body, []byte("webpackchunk")) ||
		containsFold(body, []byte("__webpack_require__"))
	result.SPA.RequireJS = containsFold(body, []byte("requirejs.config")) ||
		containsFold(body, []byte("require.config"))
	result.SPA.LargeBundle = len(body) >= largeBundleThreshold
	if full {
		// A base path often lives in a config blob the AST does not model, so
		// the text pass looks for the same assignments. The download phase does
		// not consume base paths; the deferred analysis pass derives them.
		result.BasePaths = scanBasePathTextIndexed(lines, maxBasePathsPerFile)
	}
	return result
}

// containsFold reports whether haystack contains needle, comparing ASCII
// letters case-insensitively. needle must already be lower case. It avoids the
// full copy bytes.ToLower allocates for a multi-megabyte bundle.
func containsFold(haystack, needle []byte) bool {
	if len(needle) == 0 {
		return true
	}
	if len(needle) > len(haystack) {
		return false
	}
	first := needle[0]
	for start := 0; start <= len(haystack)-len(needle); start++ {
		if lowerASCII(haystack[start]) != first {
			continue
		}
		matched := true
		for offset := 1; offset < len(needle); offset++ {
			if lowerASCII(haystack[start+offset]) != needle[offset] {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}

func lowerASCII(char byte) byte {
	if char >= 'A' && char <= 'Z' {
		return char + ('a' - 'A')
	}
	return char
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

// hostCandidateFromURL turns a rule-engine hit on a network URL into a host
// candidate. Values that are not network URLs (paths, filenames, bare
// literals) yield nothing: the rules engine matches request targets, and only
// its URL hits carry a host.
func hostCandidateFromURL(
	source *url.URL,
	lines *lineIndex,
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
		candidate.Line, candidate.Column = lines.position(extracted.Offset)
		candidate.ContextLines = lines.extract(
			extracted.Offset, contextSpanLines, extracted.Raw,
		)
	}
	return &candidate
}
