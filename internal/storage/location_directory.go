package storage

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

// LocationDirectory assigns one unique directory to an analysis of a
// local JavaScript file or directory. It mirrors ScanDirectory's shape
// (<identity>_<timestamp>_<token>) so report readers see the same layout, but
// the identity comes from the location's base name instead of a host.
func LocationDirectory(root, location string, started time.Time) (string, error) {
	clean := filepath.Clean(strings.TrimSpace(location))
	if clean == "" || clean == "." {
		return "", fmt.Errorf("invalid analysis location %q", location)
	}
	identity := sanitizeComponent(filepath.Base(clean))
	if identity == "_" || identity == "." {
		identity = "location"
	}
	var token [8]byte
	if _, err := rand.Read(token[:]); err != nil {
		return "", fmt.Errorf("create analysis id: %w", err)
	}
	stamp := started.In(time.FixedZone("Asia/Shanghai", 8*60*60)).Format("20060102-150405")
	return filepath.Join(root, "local-"+identity+"_"+stamp+"_"+hex.EncodeToString(token[:])), nil
}
