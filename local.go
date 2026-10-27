package jsowl

// Local JavaScript analysis. Local mode reads files instead of downloading
// remote documents, scripts or chunks, then reuses the live pipeline for
// endpoint resolution, source-map recovery, authorized API probing, response
// analysis, request templates and report finalization.

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/youmulijiang/jsowl/internal/model"
	"github.com/youmulijiang/jsowl/internal/pipeline"
	"github.com/youmulijiang/jsowl/internal/storage"
)

// localScriptExtensions lists the files a directory walk analyzes. An
// explicit file is always analyzed, whatever its extension, except a .map,
// which is parsed as a source map rather than as JavaScript.
var localScriptExtensions = map[string]struct{}{
	".js": {}, ".mjs": {}, ".cjs": {}, ".jsx": {}, ".ts": {}, ".tsx": {},
}

// AnalyzeLocation analyzes one local JavaScript file, or every JavaScript
// file under a directory, without a base URL. Relative API references then
// stay static: they have no host and are not requested.
func AnalyzeLocation(ctx context.Context, config Config, location string) (*Result, error) {
	return AnalyzeLocationWithBase(ctx, config, location, "")
}

// AnalyzeLocationWithBase analyzes local JavaScript and optionally requests the
// APIs it discovers. baseURL must be an absolute http(s) URL; it is the only
// resolution anchor for relative references. Absolute APIs written in the code
// are requested under the configured scope policy even without a base URL.
// Local mode never downloads remote scripts, chunks or source maps.
func AnalyzeLocationWithBase(
	ctx context.Context,
	config Config,
	location string,
	baseURL string,
) (*Result, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	location = strings.TrimSpace(location)
	if location == "" {
		return nil, errors.New("analysis location must not be empty")
	}
	baseURL, err := normalizeLocalBaseURL(baseURL)
	if err != nil {
		return nil, err
	}
	absolute, err := filepath.Abs(location)
	if err != nil {
		return nil, fmt.Errorf("resolve analysis location: %w", err)
	}
	info, err := os.Stat(absolute)
	if err != nil {
		return nil, fmt.Errorf("inspect analysis location: %w", err)
	}
	input, err := collectLocalInput(ctx, absolute, info)
	if err != nil {
		return nil, err
	}
	input.BaseURL = baseURL
	input.ReadSourceMap = readLocalSourceMap

	started := time.Now()
	reportDirectory, err := storage.LocationDirectory(
		config.Output.Directory, absolute, started,
	)
	if err != nil {
		return nil, err
	}
	scanner, err := New(config)
	if err != nil {
		return nil, err
	}
	return scanner.scanLocal(ctx, input, reportDirectory, started)
}

// normalizeLocalBaseURL validates the local --base-url value. A path-only
// prefix is rejected: without -u there is no target origin to resolve it
// against, and guessing one would request the wrong host.
func normalizeLocalBaseURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.User != nil || !parsed.IsAbs() ||
		parsed.Host == "" ||
		(parsed.Scheme != "http" && parsed.Scheme != "https") {
		return "", fmt.Errorf(
			"invalid local base URL %q; --location needs an absolute http(s) "+
				"--base-url because a relative path has no host without -u",
			raw,
		)
	}
	return parsed.String(), nil
}

// collectLocalInput reads the JavaScript bodies (or the explicit .map) the
// location names. One unreadable file becomes a diagnostic instead of
// discarding the rest of a directory.
func collectLocalInput(
	ctx context.Context,
	absolute string,
	info fs.FileInfo,
) (pipeline.LocalInput, error) {
	input := pipeline.LocalInput{Target: absolute}
	if !info.IsDir() && strings.EqualFold(filepath.Ext(absolute), ".map") {
		body, readErr := os.ReadFile(absolute)
		if readErr != nil {
			input.Diagnostics = append(input.Diagnostics, localReadIssue(absolute, readErr))
			return input, nil
		}
		input.SourceMaps = append(input.SourceMaps, pipeline.LocalFile{
			URL: localFileURL(absolute).String(), Body: body,
		})
		return input, nil
	}

	files, err := localJavaScriptFiles(absolute, info)
	if err != nil {
		return input, err
	}
	for _, file := range files {
		if err := ctx.Err(); err != nil {
			return input, err
		}
		body, readErr := os.ReadFile(file)
		if readErr != nil {
			input.Diagnostics = append(input.Diagnostics, localReadIssue(file, readErr))
			continue
		}
		input.Files = append(input.Files, pipeline.LocalFile{
			URL: localFileURL(file).String(), Body: body,
		})
	}
	return input, nil
}

func localReadIssue(path string, err error) model.Issue {
	return model.Issue{
		Code:    "js_read_failed",
		Stage:   "analyze",
		URL:     localFileURL(path).String(),
		Message: err.Error(),
	}
}

// localJavaScriptFiles resolves what to analyze: the explicit file, or every
// JavaScript file below a directory. Walking skips .git metadata but not
// node_modules: a directory the user points at is analyzed as it is.
func localJavaScriptFiles(absolute string, info fs.FileInfo) ([]string, error) {
	if !info.IsDir() {
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("analysis location %q is not a regular file", absolute)
		}
		return []string{absolute}, nil
	}
	var files []string
	err := filepath.WalkDir(absolute, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if entry.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if _, ok := localScriptExtensions[strings.ToLower(filepath.Ext(path))]; ok {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk analysis location: %w", err)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no JavaScript files found under %q", absolute)
	}
	sort.Strings(files)
	return files, nil
}

// localFileURL renders a stable file:// URL for a local path. Report sources
// and finding locations use it so every file has one identity, independent of
// the platform's separator.
func localFileURL(path string) *url.URL {
	slash := filepath.ToSlash(path)
	if !strings.HasPrefix(slash, "/") {
		slash = "/" + slash
	}
	return &url.URL{Scheme: "file", Path: slash}
}

// localPathFromFileURL converts a file:// URL back to the path the map loader
// reads. Only local files are accepted; a remote map is never downloaded.
func localPathFromFileURL(candidate *url.URL) (string, error) {
	if candidate == nil || candidate.Scheme != "file" || candidate.Host != "" {
		return "", errors.New("source map reference is not a local file")
	}
	value := candidate.Path
	if runtime.GOOS == "windows" && len(value) >= 3 &&
		value[0] == '/' && value[2] == ':' {
		// file:///D:/app.js.map -> D:\app.js.map
		value = value[1:]
	}
	if value == "" {
		return "", errors.New("source map reference has no path")
	}
	return filepath.FromSlash(value), nil
}

// readLocalSourceMap resolves a sourceMappingURL against the script that
// references it and reads the local file. Remote references never reach this
// loader; absorbLocalSourceMap records them as skipped.
func readLocalSourceMap(source *url.URL, reference string) (string, []byte, error) {
	reference = strings.TrimSpace(reference)
	parsed, err := url.Parse(reference)
	if err != nil {
		return "", nil, fmt.Errorf("parse source map reference: %w", err)
	}
	if parsed.IsAbs() || parsed.Host != "" {
		return "", nil, errors.New("remote source maps are not downloaded in local mode")
	}
	if source == nil {
		return "", nil, errors.New("source map reference has no source file")
	}
	resolved := source.ResolveReference(parsed)
	path, err := localPathFromFileURL(resolved)
	if err != nil {
		return "", nil, err
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return "", nil, fmt.Errorf("read source map %s: %w", path, err)
	}
	return resolved.String(), body, nil
}
