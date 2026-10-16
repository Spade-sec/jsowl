package extract

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/joeguo/tldextract"
	"golang.org/x/net/idna"
)

// pslSnapshot is the Public Suffix List shipped with the binary. It is the
// upstream file verbatim (including its MPL-2.0 header), so the data's licence
// and provenance travel with it; see psl/README.md for version, commit and
// hash. Embedding it is what keeps a scan fully offline.
//
//go:embed psl/public_suffix_list.dat
var pslSnapshot []byte

// pslSanityHost is the probe run against a freshly initialized splitter. If
// the cache file were truncated or otherwise unusable, the library would keep
// returning "malformed" for everything instead of failing, so the resolver
// verifies one well-known name before it is handed out.
const pslSanityHost = "example.com"

// ErrPSLUnavailable reports that suffix splitting could not be initialized.
// Callers keep the validated candidate and mark its hierarchy as unresolved
// instead of dropping it.
var ErrPSLUnavailable = errors.New("public suffix list unavailable")

// SuffixSplit is the result of splitting one ASCII host.
type SuffixSplit struct {
	// Recognized is true only when the snapshot matched a suffix rule and a
	// registrable domain could be derived.
	Recognized bool
	// SuffixOnly is true when the host is itself a public suffix ("co.uk"),
	// which by definition has no registrable domain.
	SuffixOnly bool
	Subdomain  string
	// Registrable is the registrable domain ("example.co.uk" for
	// "api.example.co.uk"); empty unless Recognized.
	Registrable string
	// Suffix is the public suffix ("co.uk"); empty unless Recognized or
	// SuffixOnly.
	Suffix string
}

// Resolver splits hosts with one shared, read-only Public Suffix List
// instance. It is safe for concurrent use: the underlying library is read-only
// after initialization, and splitting is memoized.
type Resolver struct {
	splitter *tldextract.TLDExtract
	version  string
	commit   string
	// memo caches splits per host. Hosts repeat heavily across a bundle farm,
	// and the trie walk is the only non-trivial cost in classification.
	memo sync.Map
}

// PSLInfo describes the snapshot in use, for diagnostics and documentation.
type PSLInfo struct {
	Version string
	Commit  string
	Path    string
	// Converted counts rules rewritten to punycode, Skipped counts rules left
	// untouched because their labels could not be converted.
	Converted int
	Skipped   int
}

var (
	defaultOnce     sync.Once
	defaultResolver *Resolver
	defaultErr      error
	defaultInfo     PSLInfo
)

// DefaultResolver returns the process-wide resolver, initializing it on first
// use. Initialization is serialized: it writes the cache file (when needed)
// and configures the splitter once, before any concurrent scan work starts.
// A failure is returned rather than fatal.
func DefaultResolver() (*Resolver, error) {
	defaultOnce.Do(func() {
		defaultResolver, defaultInfo, defaultErr = newResolver()
	})
	return defaultResolver, defaultErr
}

// PSLSnapshotInfo reports the version of the embedded snapshot without
// initializing the splitter.
func PSLSnapshotInfo() PSLInfo {
	version, commit := snapshotVersion(pslSnapshot)
	return PSLInfo{Version: version, Commit: commit}
}

func newResolver() (*Resolver, PSLInfo, error) {
	normalized, info, err := normalizeSnapshot(pslSnapshot)
	if err != nil {
		return nil, info, fmt.Errorf("normalize public suffix list: %w", err)
	}
	path, err := ensureSnapshotFile(normalized, cacheDirs())
	if err != nil {
		return nil, info, fmt.Errorf("%w: %v", ErrPSLUnavailable, err)
	}
	info.Path = path
	splitter, err := newSplitter(path)
	if err != nil {
		return nil, info, err
	}
	resolver := &Resolver{
		splitter: splitter,
		version:  info.Version,
		commit:   info.Commit,
	}
	if !resolver.probe() {
		return nil, info, fmt.Errorf("%w: snapshot failed its self-check", ErrPSLUnavailable)
	}
	return resolver, info, nil
}

// newSplitter initializes the Public Suffix List splitter.
//
// The library reads the cache file and, when it is missing, downloads the list
// from publicsuffix.org; ensureSnapshotFile guarantees the file exists first,
// so that path is never taken. Both switches skip preprocessing we do
// ourselves: the splitter only ever receives an already validated, lowercased,
// ASCII bare domain, so scheme stripping, '@'/':'/'?' cutting and ".html"
// suffix removal would only be able to corrupt it.
//
// A panic inside the library — which a malformed snapshot can provoke — is
// converted into an error, because a degraded report is acceptable and a
// crashed scan is not.
func newSplitter(path string) (splitter *tldextract.TLDExtract, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			splitter = nil
			err = fmt.Errorf("%w: splitter rejected the snapshot: %v", ErrPSLUnavailable, recovered)
		}
	}()
	extract, err := tldextract.New(path, false)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPSLUnavailable, err)
	}
	extract.SetNoValidate()
	extract.SetNoStrip()
	return extract, nil
}

// probe verifies the splitter actually resolves a known domain.
func (r *Resolver) probe() bool {
	split, ok := r.split(pslSanityHost)
	return ok && split.Suffix == "com" && split.Registrable == pslSanityHost
}

// Version returns the Public Suffix List version and commit of the snapshot.
func (r *Resolver) Version() (version, commit string) {
	if r == nil {
		return "", ""
	}
	return r.version, r.commit
}

// Split returns the suffix split for one already validated ASCII host. The
// boolean is false when no suffix rule matched (or when the resolver is
// unavailable), which callers report as an unknown hierarchy — never as a
// made-up registrable domain.
func (r *Resolver) Split(asciiHost string) (SuffixSplit, bool) {
	if r == nil {
		return SuffixSplit{}, false
	}
	return r.split(asciiHost)
}

func (r *Resolver) split(asciiHost string) (SuffixSplit, bool) {
	if cached, ok := r.memo.Load(asciiHost); ok {
		split := cached.(SuffixSplit)
		return split, split.Recognized
	}
	result := r.splitter.Extract(asciiHost)
	split := SuffixSplit{}
	switch {
	case result != nil && result.Flag == tldextract.Domain && result.Tld != "" && result.Root != "":
		registrable := result.Root
		if result.Tld != "" {
			registrable = result.Root + "." + result.Tld
		}
		split = SuffixSplit{
			Recognized:  true,
			Subdomain:   result.Sub,
			Registrable: registrable,
			Suffix:      result.Tld,
		}
	default:
		// The host may be a public suffix itself. Adding one label makes the
		// splitter report that label as the registrable part and the original
		// host as the suffix — the signature of a suffix-only value.
		if probe := r.splitter.Extract("x." + asciiHost); probe != nil &&
			probe.Flag == tldextract.Domain && probe.Tld == asciiHost && probe.Root == "x" {
			split = SuffixSplit{SuffixOnly: true, Suffix: asciiHost}
		}
	}
	r.memo.Store(asciiHost, split)
	return split, split.Recognized
}

// ensureSnapshotFile writes the normalized snapshot into a cache directory and
// returns the path the library should read. It tries the user cache directory
// first and falls back to the temporary directory; a directory that cannot be
// created or written is skipped rather than fatal. An already-current file is
// reused, and a stale or corrupted one is rewritten.
func ensureSnapshotFile(data []byte, directories []string) (string, error) {
	name := "public_suffix_list-" + shortHash(data) + ".dat"
	var lastErr error
	for _, directory := range directories {
		path := filepath.Join(directory, name)
		if existing, err := os.ReadFile(path); err == nil && bytes.Equal(existing, data) {
			return path, nil
		}
		if err := os.MkdirAll(directory, 0o700); err != nil {
			lastErr = err
			continue
		}
		if err := writeFileAtomic(path, data); err != nil {
			lastErr = err
			continue
		}
		return path, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no writable cache directory")
	}
	return "", lastErr
}

// cacheDirs lists where the snapshot may be written, most preferred first.
func cacheDirs() []string {
	dirs := make([]string, 0, 2)
	if base, err := os.UserCacheDir(); err == nil && base != "" {
		dirs = append(dirs, filepath.Join(base, "jsowl", "psl"))
	}
	dirs = append(dirs, filepath.Join(os.TempDir(), "jsowl-psl"))
	return dirs
}

// writeFileAtomic writes through a temporary file in the same directory and
// renames it into place, so a reader never observes a half-written snapshot.
func writeFileAtomic(path string, data []byte) error {
	directory := filepath.Dir(path)
	file, err := os.CreateTemp(directory, ".psl-*.tmp")
	if err != nil {
		return err
	}
	temp := file.Name()
	defer os.Remove(temp)
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Chmod(temp, 0o600); err != nil {
		return err
	}
	return os.Rename(temp, path)
}

func shortHash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:8])
}

// snapshotVersion reads the VERSION and COMMIT lines the Public Suffix List
// carries in its header.
func snapshotVersion(raw []byte) (version, commit string) {
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "// VERSION:"):
			version = strings.TrimSpace(strings.TrimPrefix(trimmed, "// VERSION:"))
		case strings.HasPrefix(trimmed, "// COMMIT:"):
			commit = strings.TrimSpace(strings.TrimPrefix(trimmed, "// COMMIT:"))
		}
		if version != "" && commit != "" {
			break
		}
	}
	return version, commit
}

// ruleProfile converts public suffix rules to the ASCII (punycode) form hosts
// are compared in. It mirrors the profile used for hosts, minus the length
// verification that does not apply to a single label.
var ruleProfile = idna.New(
	idna.MapForLookup(),
	idna.Transitional(false),
	idna.StrictDomainName(true),
	idna.BidiRule(),
)

// normalizeSnapshot rewrites the embedded snapshot into the form the splitter
// compares against.
//
// The Public Suffix List spells internationalized suffixes in Unicode (中国,
// рф, 公司 ...), while this package normalizes every host to ASCII before
// splitting. Feeding the rules through as-is would therefore miss every IDN
// suffix; converting each label to punycode keeps one consistent ASCII view.
// Comment and blank lines are preserved so the file's licence header stays
// with the copy written to the cache. Rules whose labels cannot be converted
// are kept verbatim and counted, never silently dropped.
func normalizeSnapshot(raw []byte) ([]byte, PSLInfo, error) {
	if len(raw) == 0 {
		return nil, PSLInfo{}, errors.New("embedded snapshot is empty")
	}
	version, commit := snapshotVersion(raw)
	info := PSLInfo{Version: version, Commit: commit}

	// Line endings are normalized first. The embedded file is checked out at
	// whatever line ending the platform uses, and the splitter library panics
	// on a line that is whitespace only (a CR left by CRLF is enough), so the
	// copy written to the cache is always LF.
	normalizedInput := strings.ReplaceAll(string(raw), "\r\n", "\n")
	normalizedInput = strings.ReplaceAll(normalizedInput, "\r", "\n")
	lines := strings.Split(normalizedInput, "\n")
	var out bytes.Buffer
	out.Grow(len(raw))
	for index, line := range lines {
		if index > 0 {
			out.WriteByte('\n')
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") {
			out.WriteString(line)
			continue
		}
		converted, ok := convertRuleLine(trimmed)
		if !ok {
			info.Skipped++
			out.WriteString(line)
			continue
		}
		if converted != trimmed {
			info.Converted++
		}
		out.WriteString(converted)
	}
	return out.Bytes(), info, nil
}

// convertRuleLine converts one rule ("中国", "*.ck", "!www.ck") to punycode
// labels, preserving the wildcard/exception marker.
func convertRuleLine(rule string) (string, bool) {
	prefix := ""
	switch {
	case strings.HasPrefix(rule, "!"):
		prefix, rule = "!", rule[1:]
	case strings.HasPrefix(rule, "*."):
		prefix, rule = "*.", rule[2:]
	}
	if rule == "" {
		return "", false
	}
	labels := strings.Split(rule, ".")
	converted := make([]string, 0, len(labels))
	for _, label := range labels {
		lowered := strings.ToLower(label)
		if isASCII(lowered) {
			converted = append(converted, lowered)
			continue
		}
		ascii, err := ruleProfile.ToASCII(lowered)
		if err != nil || ascii == "" {
			return "", false
		}
		converted = append(converted, ascii)
	}
	return prefix + strings.Join(converted, "."), true
}

func isASCII(value string) bool {
	for index := 0; index < len(value); index++ {
		if value[index] >= 0x80 {
			return false
		}
	}
	return true
}
