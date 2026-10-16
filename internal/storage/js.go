package storage

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/cespare/xxhash/v2"
	"github.com/youmulijiang/jsowl/internal/model"
)

var (
	invalidFilenameCharacters = regexp.MustCompile(`[<>:"/\\|?*\x00-\x1f]`)
	windowsReservedNames      = map[string]struct{}{
		"CON": {}, "PRN": {}, "AUX": {}, "NUL": {},
		"COM1": {}, "COM2": {}, "COM3": {}, "COM4": {}, "COM5": {},
		"COM6": {}, "COM7": {}, "COM8": {}, "COM9": {},
		"LPT1": {}, "LPT2": {}, "LPT3": {}, "LPT4": {}, "LPT5": {},
		"LPT6": {}, "LPT7": {}, "LPT8": {}, "LPT9": {},
	}
)

// SaveJS atomically stores a script or chunk under <reportDirectory>/js and
// returns a slash-separated path relative to that directory.
//
// The report directory is the target's own directory (see TargetDirectory), so
// downloaded JavaScript lives next to the report that references it and the
// recorded local path resolves inside the report folder, not in a sibling one.
func SaveJS(
	reportDirectory string,
	resource model.Resource,
	body []byte,
) (string, error) {
	return SaveJSIn(reportDirectory, "js", resource, body)
}

// SaveJSIn is SaveJS with a configurable JavaScript directory name.
func SaveJSIn(
	reportDirectory string,
	jsDirectory string,
	resource model.Resource,
	body []byte,
) (string, error) {
	if resource.Type != model.ResourceTypeScript &&
		resource.Type != model.ResourceTypeChunk {
		return "", errors.New("only script and chunk resources may be stored")
	}
	if strings.TrimSpace(reportDirectory) == "" {
		return "", errors.New("report directory must not be empty")
	}
	parsed, err := url.Parse(resource.URL)
	if err != nil {
		return "", fmt.Errorf("parse script URL: %w", err)
	}

	jsDirectory = sanitizeComponent(filepath.Base(jsDirectory))
	directoryParts := []string{reportDirectory, jsDirectory}
	if resource.Type == model.ResourceTypeChunk {
		directoryParts = append(directoryParts, "chunks")
	}
	directory := filepath.Join(directoryParts...)
	if err := os.MkdirAll(directory, 0o750); err != nil {
		return "", fmt.Errorf("create script directory: %w", err)
	}

	base := sanitizeComponent(filepath.Base(parsed.Path))
	if base == "" || base == "_" || base == "." {
		base = "script.js"
	}
	extension := filepath.Ext(base)
	if extension == "" {
		extension = ".js"
	}
	stem := strings.TrimSuffix(base, filepath.Ext(base))
	hash := fmt.Sprintf("%08x", uint32(xxhash.Sum64String(resource.URL)))
	filename := stem + "." + hash + extension
	absolute := filepath.Join(directory, filename)

	if existing, readErr := os.ReadFile(absolute); readErr == nil {
		if bytes.Equal(existing, body) {
			return relativeToRoot(reportDirectory, absolute)
		}
		// Re-scanning into an existing report directory rewrites the same
		// stable filename with fresh content. Replace it instead of failing;
		// os.Rename cannot overwrite on Windows, so remove it first.
		if err := os.Remove(absolute); err != nil {
			return "", fmt.Errorf("replace existing script: %w", err)
		}
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return "", fmt.Errorf("inspect script destination: %w", readErr)
	}

	temporary, err := os.CreateTemp(directory, ".jsowl-*.tmp")
	if err != nil {
		return "", fmt.Errorf("create temporary script: %w", err)
	}
	temporaryPath := temporary.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(temporaryPath)
		}
	}()
	if _, err := temporary.Write(body); err != nil {
		_ = temporary.Close()
		return "", fmt.Errorf("write script: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return "", fmt.Errorf("sync script: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return "", fmt.Errorf("close script: %w", err)
	}
	if err := os.Rename(temporaryPath, absolute); err != nil {
		return "", fmt.Errorf("publish script: %w", err)
	}
	cleanup = false
	return relativeToRoot(reportDirectory, absolute)
}

// LoadJS reads back a script previously saved under the report directory by its
// slash-separated relative path, rejecting paths that escape it.
func LoadJS(reportDirectory, relativePath string) ([]byte, error) {
	if filepath.IsAbs(relativePath) {
		return nil, errors.New("script path must be relative to the report directory")
	}
	absolute := filepath.Join(reportDirectory, filepath.FromSlash(relativePath))
	relative, err := filepath.Rel(reportDirectory, absolute)
	if err != nil || relative == ".." ||
		strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, errors.New("script path escaped report directory")
	}
	return os.ReadFile(absolute)
}

func sanitizeComponent(value string) string {
	value = invalidFilenameCharacters.ReplaceAllString(value, "_")
	value = strings.Trim(value, " .")
	if value == "" {
		return "_"
	}
	stem := strings.ToUpper(strings.TrimSuffix(value, filepath.Ext(value)))
	if _, reserved := windowsReservedNames[stem]; reserved {
		value = "_" + value
	}
	return value
}

func relativeToRoot(root, absolute string) (string, error) {
	relative, err := filepath.Rel(root, absolute)
	if err != nil {
		return "", fmt.Errorf("make script path relative: %w", err)
	}
	if relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", errors.New("script destination escaped report directory")
	}
	return filepath.ToSlash(relative), nil
}
