package storage

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ScanDirectory assigns one unique directory to a scan. Call once, then share
// the returned path across collection phases and report writers.
func ScanDirectory(ctx context.Context, root, rawTarget string, started time.Time) (string, error) {
	u, err := url.Parse(rawTarget)
	if err != nil || u.Hostname() == "" {
		return "", fmt.Errorf("invalid scan target %q", rawTarget)
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	if ip == nil {
		lookupCtx, cancel := context.WithTimeout(ctx, time.Second)
		addresses, _ := net.DefaultResolver.LookupIPAddr(lookupCtx, host)
		cancel()
		// Prefer IPv4 and stable lexical ordering when a domain has several IPs.
		sort.Slice(addresses, func(i, j int) bool {
			a, b := addresses[i].IP, addresses[j].IP
			if (a.To4() != nil) != (b.To4() != nil) {
				return a.To4() != nil
			}
			return a.String() < b.String()
		})
		if len(addresses) > 0 {
			ip = addresses[0].IP
		}
	}
	identity := "unresolved-" + sanitizeComponent(host)
	if ip != nil {
		identity = strings.ReplaceAll(ip.String(), ":", "_")
	}
	var token [8]byte
	if _, err := rand.Read(token[:]); err != nil {
		return "", fmt.Errorf("create scan id: %w", err)
	}
	stamp := started.In(time.FixedZone("Asia/Shanghai", 8*60*60)).Format("20060102-150405")
	return filepath.Join(root, identity+"_"+stamp+"_"+hex.EncodeToString(token[:])), nil
}
