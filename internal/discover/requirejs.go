package discover

import (
	"net/url"
	"regexp"
	"strings"
)

var (
	requireBaseURL = regexp.MustCompile(`(?i)baseUrl\s*:\s*["']([^"']+)["']`)
	requirePaths   = regexp.MustCompile(`(?is)paths\s*:\s*\{([^}]*)\}`)
	requirePair    = regexp.MustCompile(
		`["']?([A-Za-z0-9_./-]+)["']?\s*:\s*["']([^"']+)["']`,
	)
	requireArray = regexp.MustCompile(
		`(?is)(?:define|require)\s*\(\s*\[([^\]]*)\]`,
	)
	requireModule = regexp.MustCompile(`["']([^"']+)["']`)
)

// FromRequireJS resolves configured RequireJS modules into bounded script URLs.
func FromRequireJS(source *url.URL, body []byte, limit int) []Candidate {
	if source == nil || limit <= 0 {
		return nil
	}

	base := ensureDirectoryURL(source.ResolveReference(&url.URL{Path: "."}))
	if match := requireBaseURL.FindSubmatch(body); len(match) == 2 {
		if resolved, ok := resolveURL(source, string(match[1])); ok {
			base = ensureDirectoryURL(resolved)
		}
	}

	aliases := make(map[string]string)
	if block := requirePaths.FindSubmatch(body); len(block) == 2 {
		for _, pair := range requirePair.FindAllSubmatch(block[1], -1) {
			aliases[string(pair[1])] = string(pair[2])
		}
	}

	result := make([]Candidate, 0)
	seen := make(map[string]struct{})
	for _, array := range requireArray.FindAllSubmatch(body, -1) {
		for _, match := range requireModule.FindAllSubmatch(array[1], -1) {
			if len(result) >= limit {
				return result
			}
			module := string(match[1])
			if module == "require" || module == "exports" || module == "module" {
				continue
			}
			if bang := strings.LastIndexByte(module, '!'); bang >= 0 {
				module = module[bang+1:]
			}
			if alias, exists := aliases[module]; exists {
				module = alias
			}
			if !hasJavaScriptExtension(module) {
				module += ".js"
			}
			resolved, ok := resolveURL(base, module)
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
	}
	return result
}

func hasJavaScriptExtension(raw string) bool {
	lower := strings.ToLower(raw)
	return strings.HasSuffix(lower, ".js") || strings.HasSuffix(lower, ".mjs")
}
