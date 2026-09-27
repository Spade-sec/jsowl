package discover

import (
	"bytes"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

const maxChunkMapBytes = 2 * 1024 * 1024

var (
	webpackPublicPath = regexp.MustCompile(
		`(?:__webpack_require__|[A-Za-z_$][\w$]*)\.p\s*=\s*["']([^"']*)["']`,
	)
	webpackEvidence = regexp.MustCompile(
		`(?i)(?:(?:__webpack_require__|[A-Za-z_$][\w$]*)\.(?:p|u)\s*=|webpackchunk)`,
	)
	webpackUFunction = regexp.MustCompile(
		`(?s)(?:__webpack_require__|[A-Za-z_$][\w$]*)\.u\s*=\s*\(?\s*([A-Za-z_$][\w$]*)\s*\)?\s*=>\s*([^;]*)`,
	)
	webpackObject = regexp.MustCompile(
		`(?s)\{(?:\s*["']?[A-Za-z0-9_-]+["']?\s*:\s*["'][^"']+["']\s*,?)+\s*\}`,
	)
	webpackNamedObject = regexp.MustCompile(
		`(?s)(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*(\{(?:\s*["']?[A-Za-z0-9_-]+["']?\s*:\s*["'][^"']+["']\s*,?)+\s*\})`,
	)
	webpackPair = regexp.MustCompile(
		`["']?([A-Za-z0-9_-]+)["']?\s*:\s*["']([^"']+)["']`,
	)
	// webpackInlineChunkName matches the chunk-filename expression webpack
	// inlines into the HTML entry: a literal directory prefix, the chunk id,
	// a dot, a {name: hash} map indexed by that same id, and ".js". Vue CLI
	// writes it as a plain function ("function c(e){return i.p+...}") rather
	// than __webpack_require__.u, so the .u matcher never sees it.
	webpackInlineChunkName = regexp.MustCompile(
		`(?s)["']([^"']*/)["'][^:;]{1,80}\+\s*["']\.["']\s*\+\s*(\{(?:\s*["']?[A-Za-z0-9_-]+["']?\s*:\s*["'][^"']+["']\s*,?)+\})\s*\[`,
	)
	// chunkHashToken accepts every token shape webpack uses for chunk hashes:
	// lowercase hex, base64url fragments and short content hashes. The old
	// hex-only check discarded whole chunk maps whenever one hash carried a
	// letter past "f" or a "-"/"_".
	chunkHashToken = regexp.MustCompile(`^[A-Za-z0-9_-]{2,}$`)
)

// FromWebpack extracts bounded, resolved chunk URLs from common Webpack runtimes.
func FromWebpack(source *url.URL, body []byte, limit int) []Candidate {
	if source == nil || limit <= 0 {
		return nil
	}
	inlineChunks := webpackInlineChunkName.FindAllSubmatch(body, -1)
	if !webpackEvidence.Match(body) && len(inlineChunks) == 0 {
		return nil
	}
	publicBase := source
	// The AST pass runs unconditionally on webpack-evidenced bundles and its
	// results are unioned with the regex pass below: the two have disjoint
	// blind spots (the AST misses truncated/mangled bundles, the regex
	// misses plain-function runtimes, template strings and subscript
	// property access).
	astPublicPath, astFilenames := webpackASTExtract(body)
	if match := webpackPublicPath.FindSubmatch(body); len(match) == 2 {
		if resolved, ok := resolveURL(source, string(match[1])); ok {
			publicBase = ensureDirectoryURL(resolved)
		}
	} else if astPublicPath != "" {
		if resolved, ok := resolveURL(source, astPublicPath); ok {
			publicBase = ensureDirectoryURL(resolved)
		}
	} else {
		publicBase = ensureDirectoryURL(source.ResolveReference(&url.URL{Path: "."}))
	}

	type chunkMap map[string]string
	maps := make([]chunkMap, 0)
	for _, object := range webpackChunkObjects(body) {
		if len(object) > maxChunkMapBytes {
			continue
		}
		parsed := make(chunkMap)
		for _, pair := range webpackPair.FindAllSubmatch(object, -1) {
			parsed[string(pair[1])] = string(pair[2])
		}
		if len(parsed) > 0 {
			maps = append(maps, parsed)
		}
	}

	var filenames []string
	idHashTemplate := usesIDHashTemplate(body)
	consumed := make(map[int]bool)
	for i := 0; i < len(maps); i++ {
		for j := i + 1; j < len(maps); j++ {
			if !sameMapKeys(maps[i], maps[j]) {
				continue
			}
			names, hashes := maps[i], maps[j]
			if hashScore(names) > hashScore(hashes) {
				names, hashes = hashes, names
			}
			if hashScore(hashes) < 1 || hashScore(names) >= hashScore(hashes) {
				// Ambiguous pair: neither side is clearly the hash map.
				continue
			}
			for _, id := range sortedMapKeys(names) {
				filenames = append(filenames, names[id]+"."+hashes[id]+".js")
			}
			consumed[i], consumed[j] = true, true
			break
		}
	}
	for index, values := range maps {
		if consumed[index] {
			continue
		}
		for _, id := range sortedMapKeys(values) {
			value := values[id]
			if idHashTemplate && hashScore(values) >= 1 {
				value = id + "." + value
			}
			if !strings.HasSuffix(strings.ToLower(value), ".js") {
				value += ".js"
			}
			filenames = append(filenames, value)
		}
	}

	// Inline runtimes name every chunk in one expression, so the map is
	// already complete: emit <prefix><name>.<hash>.js for each entry.
	for _, match := range inlineChunks {
		prefix := string(match[1])
		for _, pair := range webpackPair.FindAllSubmatch(match[2], -1) {
			filenames = append(filenames,
				prefix+string(pair[1])+"."+string(pair[2])+".js")
		}
	}

	// Union in the AST pass filenames; the result loop deduplicates.
	filenames = append(filenames, astFilenames...)

	result := make([]Candidate, 0, min(limit, len(filenames)))
	seen := make(map[string]struct{})
	for _, filename := range filenames {
		if len(result) >= limit {
			break
		}
		resolved, ok := resolveURL(publicBase, filename)
		if !ok {
			continue
		}
		raw := resolved.String()
		if _, duplicate := seen[raw]; duplicate {
			continue
		}
		seen[raw] = struct{}{}
		result = append(result, Candidate{
			Raw: raw, Kind: KindChunk, SourceURL: source.String(),
		})
	}
	return result
}

func webpackChunkObjects(body []byte) [][]byte {
	if loader := webpackUFunction.FindSubmatch(body); len(loader) == 3 {
		return webpackObject.FindAll(loader[2], -1)
	}

	objects := make([][]byte, 0)
	for _, assignment := range webpackNamedObject.FindAllSubmatch(body, -1) {
		if len(assignment) != 3 {
			continue
		}
		if referencedByChunkExpression(body, assignment[1]) {
			objects = append(objects, assignment[2])
		}
	}
	return objects
}

func referencedByChunkExpression(body, name []byte) bool {
	searchFrom := 0
	for searchFrom < len(body) {
		relative := bytes.Index(body[searchFrom:], name)
		if relative < 0 {
			return false
		}
		start := searchFrom + relative
		afterName := start + len(name)
		if start > 0 && isJSIdentifierByte(body[start-1]) {
			searchFrom = afterName
			continue
		}
		cursor := afterName
		for cursor < len(body) && isJSSpace(body[cursor]) {
			cursor++
		}
		if cursor >= len(body) || body[cursor] != '[' {
			searchFrom = afterName
			continue
		}

		statementStart := bytes.LastIndexByte(body[:start], ';') + 1
		statementEnd := len(body)
		if relativeEnd := bytes.IndexByte(body[cursor:], ';'); relativeEnd >= 0 {
			statementEnd = cursor + relativeEnd
		}
		if statementEnd-statementStart <= 2000 &&
			bytes.Contains(body[statementStart:statementEnd], []byte(".js")) {
			return true
		}
		searchFrom = afterName
	}
	return false
}

func isJSIdentifierByte(value byte) bool {
	return value == '_' || value == '$' ||
		value >= 'a' && value <= 'z' ||
		value >= 'A' && value <= 'Z' ||
		value >= '0' && value <= '9'
}

func isJSSpace(value byte) bool {
	return value == ' ' || value == '\t' || value == '\r' || value == '\n'
}

func usesIDHashTemplate(body []byte) bool {
	match := webpackUFunction.FindSubmatch(body)
	if len(match) != 3 {
		return false
	}
	identifier := regexp.QuoteMeta(string(match[1]))
	pattern := regexp.MustCompile(
		identifier + `\s*\+\s*["']\.["']\s*\+\s*\{`,
	)
	return pattern.Match(match[2])
}

func sameMapKeys(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key := range left {
		if _, exists := right[key]; !exists {
			return false
		}
	}
	return true
}

// hashScore grades how much a map's values look like content hashes: the
// fraction of values that are opaque tokens carrying at least one digit.
// Chunk names are readable words ("users", "admin") while chunk hashes are
// opaque and almost always carry a digit. Scoring instead of a boolean keeps
// the two-map form unambiguous and still accepts base64url hashes that a
// hex-only check would reject.
func hashScore(values map[string]string) float64 {
	if len(values) == 0 {
		return 0
	}
	scored := 0
	for _, value := range values {
		if !chunkHashToken.MatchString(value) {
			continue
		}
		if strings.ContainsAny(value, "0123456789") {
			scored++
		}
	}
	return float64(scored) / float64(len(values))
}

func sortedMapKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func ensureDirectoryURL(value *url.URL) *url.URL {
	cloned := *value
	if !strings.HasSuffix(cloned.Path, "/") {
		cloned.Path += "/"
	}
	return &cloned
}
