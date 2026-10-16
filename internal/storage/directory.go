package storage

import (
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/cespare/xxhash/v2"
)

// invalidDirectoryCharacter matches the characters that cannot appear in a
// directory name on Windows; they are replaced so a host like "a:1" still
// yields a usable directory.
var invalidDirectoryCharacter = regexp.MustCompile(`[<>:"/\\|?*\x00-\x1f]`)

// TargetDirectory returns the report directory for one target: the output root
// plus the target's host, with a stable hash suffix when the target carries a
// path or a query so two targets on the same host never overwrite each other.
//
// It is the single derivation used by every writer (the CLI, the MCP server,
// the tools server) and by the pipeline, because everything belonging to one
// target — report.html, the split reports, the plain-text lists and the
// downloaded JavaScript — is written into this one directory.
func TargetDirectory(root, rawTarget string) (string, error) {
	parsed, err := url.Parse(rawTarget)
	if err != nil || parsed.Host == "" {
		return "", fmt.Errorf("derive report directory for %q", rawTarget)
	}
	name := strings.Trim(invalidDirectoryCharacter.ReplaceAllString(parsed.Host, "_"), " .")
	if name == "" {
		return "", errors.New("target host produced an empty report directory")
	}
	if (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" {
		// The fragment never reaches a request, so it must not split two
		// otherwise identical targets into different directories.
		parsed.Fragment = ""
		name += fmt.Sprintf("-%08x", uint32(xxhash.Sum64String(parsed.String())))
	}
	return filepath.Join(root, name), nil
}
