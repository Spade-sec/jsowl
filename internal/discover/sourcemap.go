package discover

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"path"
	"regexp"
	"strings"
)

// maxSourceMapSources bounds how many embedded sources one map contributes.
// 0 means no limit.
const maxSourceMapSources = 0

// sourceMappingURL matches the reference a bundle appends to point at its map,
// in both the "//# sourceMappingURL=" and "/*# sourceMappingURL=... */" forms.
var sourceMappingURL = regexp.MustCompile(
	`(?im)(?://[#@]\s*(?i:sourceMappingURL)=([^\s'"]+)|/\*[#@]\s*(?i:sourceMappingURL)=([^\s*'"]+)\s*\*/)`,
)

// isSourceMapPath reports whether a URL path ends in ".map".
func isSourceMapPath(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return strings.EqualFold(path.Ext(parsed.Path), ".map")
}

// SourceMapReference returns the source map a JavaScript body points at. An
// inline "data:application/json;base64,..." reference is decoded in place and
// returned as content; otherwise the raw reference is returned for the caller
// to resolve against the script URL.
func SourceMapReference(body []byte) (content []byte, reference string, ok bool) {
	match := sourceMappingURL.FindSubmatch(body)
	if len(match) != 3 {
		return nil, "", false
	}
	value := string(match[1])
	if value == "" {
		value = string(match[2])
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, "", false
	}
	if !strings.HasPrefix(strings.ToLower(value), "data:") {
		return nil, value, true
	}
	comma := strings.IndexByte(value, ',')
	if comma < 0 {
		return nil, "", false
	}
	header, payload := value[:comma], value[comma+1:]
	if !strings.Contains(strings.ToLower(header), "base64") {
		decoded, err := url.PathUnescape(payload)
		if err != nil {
			return nil, "", false
		}
		return []byte(decoded), "", true
	}
	// Padding is optional in the wild; accept both padded and raw payloads.
	decoded, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(
			strings.TrimRight(payload, "="),
		)
	}
	if err != nil {
		return nil, "", false
	}
	return decoded, "", true
}

// SourceFile is one original file recovered from a source map.
type SourceFile struct {
	Name    string
	Content string
}

// ParseSourceMap pairs a map's "sources" with the "sourcesContent" it embeds.
// Only names and text are read; the mappings table is not needed to recover
// the originals, which is exactly how shuji restores sources.
func ParseSourceMap(body []byte) []SourceFile {
	var raw struct {
		Sources        []string  `json:"sources"`
		SourcesContent []*string `json:"sourcesContent"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil
	}
	if len(raw.Sources) == 0 || len(raw.SourcesContent) == 0 {
		return nil
	}
	capacity := len(raw.Sources)
	if maxSourceMapSources > 0 && capacity > maxSourceMapSources {
		capacity = maxSourceMapSources
	}
	files := make([]SourceFile, 0, capacity)
	for index, name := range raw.Sources {
		if index >= len(raw.SourcesContent) {
			break
		}
		if maxSourceMapSources > 0 && len(files) >= maxSourceMapSources {
			break
		}
		content := raw.SourcesContent[index]
		if content == nil || *content == "" {
			continue
		}
		clean := CleanSourceName(name)
		if clean == "" {
			continue
		}
		files = append(files, SourceFile{Name: clean, Content: *content})
	}
	return files
}

// CleanSourceName turns a map's source reference into a safe relative path:
// scheme, query and traversal segments are dropped so a hostile map cannot
// escape the report directory.
func CleanSourceName(name string) string {
	value := name
	if index := strings.IndexAny(value, "?#"); index >= 0 {
		value = value[:index]
	}
	if index := strings.Index(value, "://"); index >= 0 {
		value = value[index+3:]
		if slash := strings.Index(value, "/"); slash >= 0 {
			value = value[slash+1:]
		} else {
			value = ""
		}
	}
	segments := strings.Split(strings.ReplaceAll(value, "\\", "/"), "/")
	kept := make([]string, 0, len(segments))
	for _, segment := range segments {
		segment = strings.TrimSpace(segment)
		if segment == "" || segment == "." || segment == ".." {
			continue
		}
		if cleaned := cleanSourceSegment(segment); cleaned != "" {
			kept = append(kept, cleaned)
		}
	}
	if len(kept) == 0 {
		return ""
	}
	// Keep the tail: it carries the file name and its nearest folder.
	if len(kept) > 8 {
		kept = kept[len(kept)-8:]
	}
	return strings.Join(kept, "/")
}

func cleanSourceSegment(segment string) string {
	var b strings.Builder
	for _, char := range segment {
		switch {
		case char >= 'a' && char <= 'z',
			char >= 'A' && char <= 'Z',
			char >= '0' && char <= '9',
			char == '.', char == '-', char == '_', char == '@':
			b.WriteRune(char)
		default:
			b.WriteRune('_')
		}
	}
	return strings.Trim(b.String(), " .")
}
