package collect

import (
	"net/http"
	"net/url"
	"strings"
)

var crossOriginSafeHeaders = map[string]struct{}{
	"accept":                    {},
	"accept-encoding":           {},
	"accept-language":           {},
	"cache-control":             {},
	"if-modified-since":         {},
	"if-none-match":             {},
	"origin":                    {},
	"pragma":                    {},
	"referer":                   {},
	"sec-ch-ua":                 {},
	"sec-ch-ua-mobile":          {},
	"sec-ch-ua-platform":        {},
	"sec-fetch-dest":            {},
	"sec-fetch-mode":            {},
	"sec-fetch-site":            {},
	"sec-fetch-user":            {},
	"upgrade-insecure-requests": {},
	"user-agent":                {},
}

// HeadersForURL preserves all target headers for same-origin requests and
// limits cross-origin requests to non-credential browser negotiation headers.
func HeadersForURL(
	headers http.Header,
	root *url.URL,
	target *url.URL,
) http.Header {
	if SameOrigin(root, target) {
		return headers.Clone()
	}
	filtered := make(http.Header)
	for name, values := range headers {
		if _, safe := crossOriginSafeHeaders[strings.ToLower(name)]; !safe {
			continue
		}
		filtered[name] = append([]string(nil), values...)
	}
	return filtered
}

// SameOrigin reports whether two URLs have the same scheme, host, and
// effective port.
func SameOrigin(left, right *url.URL) bool {
	if left == nil || right == nil {
		return false
	}
	return strings.EqualFold(left.Scheme, right.Scheme) &&
		strings.EqualFold(left.Hostname(), right.Hostname()) &&
		effectivePort(left) == effectivePort(right)
}

func effectivePort(target *url.URL) string {
	if port := target.Port(); port != "" {
		return port
	}
	if strings.EqualFold(target.Scheme, "https") {
		return "443"
	}
	return "80"
}
