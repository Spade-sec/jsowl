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

// SaveJS atomically stores a script or chunk under <root>/<host>/js and
// returns a slash-separated path relative to root.
func SaveJS(
	root string,
	target *url.URL,
	resource model.Resource,
	body []byte,
) (string, error) {
	return SaveJSIn(root, target, "js", resource, body)
}

// SaveJSIn is SaveJS with a configurable JavaScript directory name.
func SaveJSIn(
	root string,
	target *url.URL,
	jsDirectory string,
	resource model.Resource,
	body []byte,
) (string, error) {
	if resource.Type != model.ResourceTypeScript &&
		resource.Type != model.ResourceTypeChunk {
		return "", errors.New("only script and chunk resources may be stored")
	}
	if target == nil || target.Host == "" {
		return "", errors.New("target URL must include a host")
	}
	parsed, err := url.Parse(resource.URL)
	if err != nil {
		return "", fmt.Errorf("parse script URL: %w", err)
	}

	hostDirectory := sanitizeComponent(target.Host)
	jsDirectory = sanitizeComponent(filepath.Base(jsDirectory))
	directoryParts := []string{root, hostDirectory, jsDirectory}
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
			return relativeToRoot(root, absolute)
		}
		return "", fmt.Errorf("script path collision at %s", absolute)
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
	return relativeToRoot(root, absolute)
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
		return "", errors.New("script destination escaped output root")
	}
	return filepath.ToSlash(relative), nil
}
