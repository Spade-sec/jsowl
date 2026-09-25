package discover

import (
	"regexp"
	"strings"
)

// licenseHeadBytes bounds how much of a file is scanned for a banner. Library
// banners sit at the very top; scanning further only costs time.
const licenseHeadBytes = 8 * 1024

var (
	licenseBlockComment = regexp.MustCompile(`(?s)/\*.*?\*/`)
	licenseLineComment  = regexp.MustCompile(
		`(?im)^\s*//[^\n]*(?:@license|@preserve|copyright|licensed under)[^\n]*(?:\n\s*//[^\n]*){0,8}`,
	)
	licenseMarker = regexp.MustCompile(
		`(?i)@(?:license|preserve)|copyright|licensed under|license information`,
	)
)

// libraryBundleMarkers identifies a third-party library from its license
// banner. Application bundles that merely include a library rarely carry the
// upstream banner verbatim, so naming one of these is a strong signal.
var libraryBundleMarkers = []string{
	"jquery", "lodash", "underscore", "axios", "moment.js", "dayjs",
	"react", "vue.js", "angular", "svelte", "preact", "backbone", "ember",
	"bootstrap", "element ui", "element-plus", "ant design", "antd",
	"echarts", "chart.js", "d3.js", "three.js", "highcharts", "apexcharts",
	"core-js", "regenerator-runtime", "zone.js", "rxjs", "immutable",
	"popper.js", "hammer.js", "swiper", "video.js", "pdf.js", "xlsx",
	"crypto-js", "jsencrypt", "html2canvas", "sortable", "clipboard.js",
	"font-awesome", "highlight.js", "prism.js", "codemirror", "monaco",
	"vue-router", "vuex", "pinia", "redux", "mobx", "graphql", "socket.io",
}

// LicenseBanner returns the license comments found near the top of a script,
// the way StackPrism reads a bundle's copyright header.
func LicenseBanner(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	head := body
	if len(head) > licenseHeadBytes {
		head = head[:licenseHeadBytes]
	}
	var b strings.Builder
	for _, comment := range licenseBlockComment.FindAll(head, -1) {
		if IsLicenseComment(string(comment)) {
			b.Write(comment)
			b.WriteByte('\n')
		}
	}
	for _, comment := range licenseLineComment.FindAll(head, -1) {
		b.Write(comment)
		b.WriteByte('\n')
	}
	return strings.TrimSpace(b.String())
}

// IsLicenseComment reports whether a block comment is a license banner: either
// the "/*!" preserved-comment form or one that names a license.
func IsLicenseComment(comment string) bool {
	return strings.HasPrefix(comment, "/*!") || licenseMarker.MatchString(comment)
}

// IsThirdPartyBundle reports whether a script body is a third-party library
// rather than application code, judged from its license banner. Skipping those
// keeps the regex and AST pass on the code that actually describes the target.
func IsThirdPartyBundle(body []byte) bool {
	banner := LicenseBanner(body)
	if banner == "" {
		return false
	}
	lower := strings.ToLower(banner)
	for _, marker := range libraryBundleMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}
