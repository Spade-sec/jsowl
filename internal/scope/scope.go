package scope

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"path"
	"strings"

	"github.com/youmulijiang/jsowl/internal/model"
)

// Scope decides which normalized URLs may be fetched as scripts or probed as endpoints.
type Scope struct {
	root        *url.URL
	config      model.ScopeConfig
	allowExact  map[string]struct{}
	allowSuffix []string
	blocked     []string
}

// New builds an authorization scope rooted at one HTTP or HTTPS target.
func New(root *url.URL, config model.ScopeConfig) (*Scope, error) {
	if err := validateHTTPURL(root); err != nil {
		return nil, fmt.Errorf("root URL: %w", err)
	}

	s := &Scope{
		root:       cloneURL(root),
		config:     config,
		allowExact: make(map[string]struct{}, len(config.AllowDomains)),
	}
	for _, entry := range config.AllowDomains {
		host := strings.ToLower(strings.TrimSpace(entry))
		if host == "" || strings.ContainsAny(host, "/:@") {
			return nil, fmt.Errorf("invalid allowlist domain %q", entry)
		}
		host = strings.TrimSuffix(host, ".")
		if strings.HasPrefix(host, ".") {
			if len(host) == 1 {
				return nil, fmt.Errorf("invalid allowlist domain %q", entry)
			}
			s.allowSuffix = append(s.allowSuffix, host)
			continue
		}
		s.allowExact[host] = struct{}{}
	}
	for _, entry := range config.SuffixBlacklist {
		suffix := strings.ToLower(strings.TrimSpace(entry))
		if !strings.HasPrefix(suffix, ".") {
			suffix = "." + suffix
		}
		s.blocked = append(s.blocked, suffix)
	}
	return s, nil
}

// Resolve converts a URL reference to an absolute HTTP(S) URL and rejects credentials.
func (s *Scope) Resolve(raw string, base *url.URL) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("empty URL")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse URL: %w", err)
	}
	if parsed.User != nil {
		return nil, errors.New("URL credentials are not allowed")
	}
	if base == nil {
		base = s.root
	}
	resolved := base.ResolveReference(parsed)
	if err := validateHTTPURL(resolved); err != nil {
		return nil, err
	}
	return resolved, nil
}

// CanFetchScript reports whether a script URL is permitted by the external-script policy.
func (s *Scope) CanFetchScript(candidate *url.URL) bool {
	if validateHTTPURL(candidate) != nil {
		return false
	}
	return sameOrigin(s.root, candidate) || s.config.FetchExternalScripts
}

// CanProbe reports whether an endpoint URL is same-origin or explicitly authorized.
func (s *Scope) CanProbe(candidate *url.URL) bool {
	if validateHTTPURL(candidate) != nil {
		return false
	}
	if sameOrigin(s.root, candidate) || s.config.ProbeExternalEndpoints {
		return true
	}
	host := normalizedHostname(candidate)
	if _, ok := s.allowExact[host]; ok {
		return true
	}
	for _, suffix := range s.allowSuffix {
		if strings.HasSuffix(host, suffix) {
			return true
		}
	}
	return false
}

// IsSuffixBlocked reports whether the URL path ends in a configured
// case-insensitive suffix. Query parameters and fragments are ignored.
func (s *Scope) IsSuffixBlocked(candidate *url.URL) bool {
	if candidate == nil {
		return false
	}
	candidatePath := strings.ToLower(candidate.Path)
	for _, suffix := range s.blocked {
		if strings.HasSuffix(candidatePath, suffix) {
			return true
		}
	}
	return false
}

// Canonical returns a stable URL string for queue and result deduplication.
func Canonical(candidate *url.URL) string {
	if candidate == nil {
		return ""
	}
	canonical := cloneURL(candidate)
	canonical.Scheme = strings.ToLower(canonical.Scheme)
	canonical.Fragment = ""
	canonical.RawFragment = ""
	canonical.User = nil

	host := normalizedHostname(canonical)
	port := canonical.Port()
	if (canonical.Scheme == "https" && port == "443") ||
		(canonical.Scheme == "http" && port == "80") {
		port = ""
	}
	switch {
	case port != "":
		canonical.Host = net.JoinHostPort(host, port)
	case strings.Contains(host, ":"):
		canonical.Host = "[" + host + "]"
	default:
		canonical.Host = host
	}

	originalPath := canonical.Path
	if originalPath == "" {
		originalPath = "/"
	}
	canonical.Path = path.Clean(originalPath)
	if strings.HasSuffix(originalPath, "/") && canonical.Path != "/" {
		canonical.Path += "/"
	}
	canonical.RawPath = ""
	return canonical.String()
}

func validateHTTPURL(candidate *url.URL) error {
	if candidate == nil {
		return errors.New("URL is nil")
	}
	if candidate.User != nil {
		return errors.New("URL credentials are not allowed")
	}
	scheme := strings.ToLower(candidate.Scheme)
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("unsupported URL scheme %q", candidate.Scheme)
	}
	if candidate.Hostname() == "" {
		return errors.New("URL host is empty")
	}
	return nil
}

func sameOrigin(left, right *url.URL) bool {
	return strings.EqualFold(left.Scheme, right.Scheme) &&
		normalizedHostname(left) == normalizedHostname(right) &&
		effectivePort(left) == effectivePort(right)
}

func effectivePort(candidate *url.URL) string {
	if port := candidate.Port(); port != "" {
		return port
	}
	if strings.EqualFold(candidate.Scheme, "https") {
		return "443"
	}
	return "80"
}

func normalizedHostname(candidate *url.URL) string {
	return strings.TrimSuffix(strings.ToLower(candidate.Hostname()), ".")
}

func cloneURL(candidate *url.URL) *url.URL {
	cloned := *candidate
	return &cloned
}
