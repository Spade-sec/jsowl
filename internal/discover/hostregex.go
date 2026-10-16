package discover

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/youmulijiang/jsowl/internal/extract"
	"github.com/youmulijiang/jsowl/internal/model"
)

// This file is the regex fallback for host discovery. It is used where the AST
// cannot help: text that is not JavaScript, embedded text inside a document,
// and bodies whose parse produced nothing. Every candidate it returns is
// validated by the shared classifier, so the regexes only have to find
// plausible spans, not decide what a host is.
//
// The patterns are deliberately bounded and boundary-checked. A loose
// `\d+\.\d+\.\d+\.\d+` would carve "99.1.2.3" out of the invalid "999.1.2.3";
// every match here is required to sit between non-identifier characters on
// both sides.

var (
	regexURLPattern = regexp.MustCompile(
		`(?i)(?:https?|wss?)://[^\s"'` + "`" + `<>(){}\[\]\\]{2,512}`,
	)
	regexProtocolRelativePattern = regexp.MustCompile(
		`//[a-z0-9][a-z0-9.\-]{0,253}(?::\d{1,5})?(?:[/?#][^\s"'` + "`" + `<>(){}\[\]\\]{0,256})?`,
	)
	regexEmailPattern = regexp.MustCompile(
		`[A-Za-z0-9._%+\-]+@([A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)+)`,
	)
	// Candidate-only IPv6 shape; netip decides whether it is an address.
	regexIPv6Pattern   = regexp.MustCompile(`(?i)(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?:%[0-9a-z]{1,16})?`)
	regexIPv4Pattern   = regexp.MustCompile(`\d{1,3}(?:\.\d{1,3}){3}`)
	regexDomainPattern = regexp.MustCompile(
		`(?i)[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)+`,
	)
)

// HostsFromText runs the regex fallback over a non-JavaScript or unparsed
// body: documents, plain-text resources and anything the AST could not read.
// It never scans more than extract.MaxRegexMatchesPerFile candidates.
func HostsFromText(source *url.URL, body []byte) []extract.Candidate {
	if len(body) == 0 {
		return nil
	}
	sourceURL := ""
	if source != nil {
		sourceURL = source.String()
	}
	return scanHostText(body, 0, string(body), sourceURL, "")
}

// scanHostText finds host candidates in textValue, which starts at byte
// textStart inside body. Positions are reported against body so evidence
// points at the real line of the file; note is attached to every candidate
// ("comment" for a comment node, empty otherwise).
func scanHostText(body []byte, textStart int, textValue, sourceURL, note string) []extract.Candidate {
	if textValue == "" {
		return nil
	}
	var out []extract.Candidate
	// claimed tracks spans already recorded, so a domain inside a URL or an
	// address inside another token is not counted twice.
	type span struct{ start, end int }
	var claimed []span

	add := func(start, end int, raw, context, method, extraNote string) {
		if len(out) >= extract.MaxRegexMatchesPerFile {
			return
		}
		// Trailing punctuation belongs to the surrounding prose ("see
		// https://a.example.com, then ..."), not to the value.
		raw = strings.TrimRight(strings.TrimSpace(raw), ".,;:!?)\"']}")
		if raw == "" || len(raw) > extract.MaxCandidateLen {
			return
		}
		for _, existing := range claimed {
			if start >= existing.start && start < existing.end {
				return
			}
		}
		// The span is claimed only when a candidate is actually kept, so a
		// rejected match cannot hide the host it merely contained.
		claimed = append(claimed, span{start, end})
		offset := textStart + start
		line, column := lineColumn(body, offset)
		combined := joinNotes(note, extraNote)
		out = append(out, extract.Candidate{
			Raw:          raw,
			Context:      context,
			Method:       method,
			Note:         combined,
			SourceURL:    sourceURL,
			Line:         line,
			Column:       column,
			ContextLines: extractContext(body, offset, contextSpanLines, raw),
		})
	}

	for _, match := range regexURLPattern.FindAllStringIndex(textValue, -1) {
		start, end := match[0], match[1]
		if !leftDelimited(textValue, start) {
			continue
		}
		add(start, end, textValue[start:end], extract.ContextURL, model.HostMethodRegex, "")
	}
	for _, match := range regexProtocolRelativePattern.FindAllStringIndex(textValue, -1) {
		start, end := match[0], match[1]
		if !leftDelimited(textValue, start) {
			continue
		}
		add(start, end, textValue[start:end], extract.ContextURL, model.HostMethodRegex, "")
	}
	// Emails are matched before domains so the address's domain part is
	// labelled as an email origin rather than as an anonymous domain.
	for _, match := range regexEmailPattern.FindAllStringSubmatchIndex(textValue, -1) {
		domainStart, domainEnd := match[2], match[3]
		if !leftDelimited(textValue, match[0]) {
			continue
		}
		add(domainStart, domainEnd, textValue[domainStart:domainEnd],
			extract.ContextEmail, model.HostMethodRegex, "email_domain")
	}
	for _, match := range regexIPv6Pattern.FindAllStringIndex(textValue, -1) {
		start, end := match[0], match[1]
		if !leftDelimited(textValue, start) || !rightDelimited(textValue, end) {
			continue
		}
		add(start, end, textValue[start:end], extract.ContextLiteral, model.HostMethodRegex, "")
	}
	for _, match := range regexIPv4Pattern.FindAllStringIndex(textValue, -1) {
		start, end := match[0], match[1]
		// Digits or dots on either side mean this is a fragment of a bigger
		// number, not an address: 999.1.2.3 must not yield 99.1.2.3.
		if !leftIPDelimited(textValue, start) || !rightIPDelimited(textValue, end) {
			continue
		}
		add(start, end, textValue[start:end], extract.ContextLiteral, model.HostMethodRegex, "")
	}
	for _, match := range regexDomainPattern.FindAllStringIndex(textValue, -1) {
		start, end := match[0], match[1]
		if !leftDelimited(textValue, start) || !rightDelimited(textValue, end) {
			continue
		}
		add(start, end, textValue[start:end], extract.ContextLiteral, model.HostMethodRegex, "")
	}
	return out
}

// delimiterByte reports whether a byte may not be part of a host token.
func delimiterByte(char byte) bool {
	switch {
	case char >= 'a' && char <= 'z', char >= 'A' && char <= 'Z':
		return false
	case char >= '0' && char <= '9':
		return false
	case char == '.', char == '-', char == '_':
		return false
	}
	return true
}

func leftDelimited(text string, start int) bool {
	return start <= 0 || delimiterByte(text[start-1])
}

func rightDelimited(text string, end int) bool {
	return end >= len(text) || delimiterByte(text[end])
}

// IP boundaries additionally exclude dots: "1.2.3.4.5" must not yield
// "1.2.3.4", and "999.1.2.3" must not yield "99.1.2.3".
func leftIPDelimited(text string, start int) bool {
	if start <= 0 {
		return true
	}
	char := text[start-1]
	return char != '.' && !(char >= '0' && char <= '9')
}

func rightIPDelimited(text string, end int) bool {
	if end >= len(text) {
		return true
	}
	char := text[end]
	return char != '.' && !(char >= '0' && char <= '9')
}

func joinNotes(existing, extra string) string {
	switch {
	case existing == "":
		return extra
	case extra == "":
		return existing
	default:
		return existing + "," + extra
	}
}
