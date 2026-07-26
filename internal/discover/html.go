package discover

import (
	"bytes"
	"net/url"
	"regexp"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

var metaRefreshURL = regexp.MustCompile(`(?i);\s*url\s*=\s*['"]?([^'"\s]+)`)

// FromHTML extracts resolved resources, inline scripts, and SPA evidence from HTML.
func FromHTML(pageURL *url.URL, body []byte) HTMLResult {
	document, err := goquery.NewDocumentFromReader(bytes.NewReader(body))
	if err != nil {
		return HTMLResult{}
	}

	baseURL := pageURL
	if rawBase, exists := document.Find("base[href]").First().Attr("href"); exists {
		if resolved, ok := resolveURL(pageURL, rawBase); ok {
			baseURL = resolved
		}
	}

	result := HTMLResult{}
	seen := make(map[string]struct{})
	add := func(raw string, kind Kind, resolutionBase *url.URL) {
		resolved, ok := resolveURL(resolutionBase, raw)
		if !ok {
			return
		}
		key := string(kind) + "\x00" + resolved.String()
		if _, duplicate := seen[key]; duplicate {
			return
		}
		seen[key] = struct{}{}
		result.Candidates = append(result.Candidates, Candidate{
			Raw: resolved.String(), Kind: kind, SourceURL: pageURL.String(),
		})
	}

	document.Find("script").Each(func(_ int, selection *goquery.Selection) {
		if source, exists := selection.Attr("src"); exists {
			add(source, KindScript, baseURL)
			return
		}
		if inline := strings.TrimSpace(selection.Text()); inline != "" {
			result.InlineScripts = append(result.InlineScripts, inline)
		}
	})

	document.Find("link[href]").Each(func(_ int, selection *goquery.Selection) {
		href, _ := selection.Attr("href")
		rel, _ := selection.Attr("rel")
		as, _ := selection.Attr("as")
		rel = strings.ToLower(rel)
		kind := KindAsset
		if strings.Contains(rel, "modulepreload") ||
			(strings.Contains(rel, "preload") && strings.EqualFold(as, "script")) {
			kind = KindScript
		}
		add(href, kind, baseURL)
	})

	document.Find("img[src],source[src],video[src],audio[src]").Each(
		func(_ int, selection *goquery.Selection) {
			source, _ := selection.Attr("src")
			add(source, KindAsset, pageURL)
		},
	)
	document.Find("a[href]").Each(func(_ int, selection *goquery.Selection) {
		href, _ := selection.Attr("href")
		add(href, KindRoute, pageURL)
	})
	document.Find("form[action]").Each(func(_ int, selection *goquery.Selection) {
		action, _ := selection.Attr("action")
		add(action, KindEndpoint, pageURL)
	})
	document.Find(`meta[http-equiv]`).Each(func(_ int, selection *goquery.Selection) {
		equiv, _ := selection.Attr("http-equiv")
		if !strings.EqualFold(equiv, "refresh") {
			return
		}
		content, _ := selection.Attr("content")
		match := metaRefreshURL.FindStringSubmatch(content)
		if len(match) == 2 {
			add(match[1], KindRoute, pageURL)
		}
	})

	result.SPA.RootNode = document.Find(
		`#app,#root,[ng-app],[data-reactroot],[data-v-app]`,
	).Length() > 0
	return result
}

func resolveURL(base *url.URL, raw string) (*url.URL, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || base == nil {
		return nil, false
	}
	reference, err := url.Parse(raw)
	if err != nil {
		return nil, false
	}
	resolved := base.ResolveReference(reference)
	if resolved.Scheme != "http" && resolved.Scheme != "https" {
		return nil, false
	}
	resolved.Fragment = ""
	return resolved, true
}
