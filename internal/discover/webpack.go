package discover

import (
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
		`(?s)(?:__webpack_require__|[A-Za-z_$][\w$]*)\.u\s*=\s*\(?\s*([A-Za-z_$][\w$]*)\s*\)?\s*=>\s*([^;]{1,1000})`,
	)
	webpackObject = regexp.MustCompile(
		`(?s)\{(?:\s*["']?[A-Za-z0-9_-]+["']?\s*:\s*["'][^"']+["']\s*,?)+\s*\}`,
	)
	webpackPair = regexp.MustCompile(
		`["']?([A-Za-z0-9_-]+)["']?\s*:\s*["']([^"']+)["']`,
	)
	hashValue = regexp.MustCompile(`(?i)^[a-f0-9]{4,}$`)
)

// FromWebpack extracts bounded, resolved chunk URLs from common Webpack runtimes.
func FromWebpack(source *url.URL, body []byte, limit int) []Candidate {
	if source == nil || limit <= 0 {
		return nil
	}
	if !webpackEvidence.Match(body) {
		return nil
	}
	publicBase := source
	if match := webpackPublicPath.FindSubmatch(body); len(match) == 2 {
		if resolved, ok := resolveURL(source, string(match[1])); ok {
			publicBase = ensureDirectoryURL(resolved)
		}
	} else {
		publicBase = ensureDirectoryURL(source.ResolveReference(&url.URL{Path: "."}))
	}

	type chunkMap map[string]string
	maps := make([]chunkMap, 0)
	for _, object := range webpackObject.FindAll(body, -1) {
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
			if mapLooksHashed(names) && !mapLooksHashed(hashes) {
				names, hashes = hashes, names
			}
			if mapLooksHashed(names) || !mapLooksHashed(hashes) {
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
			if idHashTemplate && mapLooksHashed(values) {
				value = id + "." + value
			}
			if !strings.HasSuffix(strings.ToLower(value), ".js") {
				value += ".js"
			}
			filenames = append(filenames, value)
		}
	}

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

func mapLooksHashed(values map[string]string) bool {
	if len(values) == 0 {
		return false
	}
	for _, value := range values {
		if !hashValue.MatchString(value) {
			return false
		}
	}
	return true
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
