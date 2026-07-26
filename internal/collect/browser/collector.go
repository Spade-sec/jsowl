package browser

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
	"github.com/youmulijiang/jsowl/internal/collect"
	"github.com/youmulijiang/jsowl/internal/model"
)

//go:embed assets/collect_resource_urls.js
var embeddedCollectorScript string

// ErrBrowserNotFound indicates that no explicitly usable local browser exists.
var ErrBrowserNotFound = errors.New("Chromium-compatible browser not found")

// Collector renders entry pages with Rod and records runtime resource URLs.
type Collector struct {
	config  model.BrowserConfig
	request model.RequestConfig
	script  string
}

// New constructs a Rod collector without launching or downloading a browser.
func New(
	config model.BrowserConfig,
	request ...model.RequestConfig,
) (*Collector, error) {
	script := embeddedCollectorScript
	if config.CollectorScript != "" {
		data, err := os.ReadFile(config.CollectorScript)
		if err != nil {
			return nil, fmt.Errorf("read browser collector script: %w", err)
		}
		script += "\n" + string(data)
	}
	var requestConfig model.RequestConfig
	if len(request) > 0 {
		requestConfig = request[0]
	}
	return &Collector{
		config: config, request: requestConfig, script: script,
	}, nil
}

// Collect renders target, waits for network quiet plus the configured grace
// period, and combines CDP, DOM, performance, fetch, and XHR observations.
func (c *Collector) Collect(
	ctx context.Context,
	target *url.URL,
	headers http.Header,
) (collect.BrowserResult, error) {
	bin, err := resolveBrowserPath(c.config.Path)
	if err != nil {
		return collect.BrowserResult{}, err
	}

	timeout := c.config.Timeout
	if timeout <= 0 {
		timeout = 45 * time.Second
	}
	scanContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	userDataDir, err := os.MkdirTemp("", "jsowl-rod-*")
	if err != nil {
		return collect.BrowserResult{}, fmt.Errorf("create browser profile: %w", err)
	}
	defer os.RemoveAll(userDataDir)

	control, browserLauncher, err := launch(
		scanContext, c.config, c.request.Proxy, bin, userDataDir,
	)
	if err != nil {
		return collect.BrowserResult{}, err
	}
	defer browserLauncher.Cleanup()
	defer browserLauncher.Kill()

	rodBrowser := rod.New().
		Context(scanContext).
		ControlURL(control).
		NoDefaultDevice()
	if err := rodBrowser.Connect(); err != nil {
		return collect.BrowserResult{}, fmt.Errorf("connect to browser: %w", err)
	}
	defer rodBrowser.Close()

	page, err := rodBrowser.Page(proto.TargetCreateTarget{})
	if err != nil {
		return collect.BrowserResult{}, fmt.Errorf("create browser page: %w", err)
	}
	defer page.Close()

	if userAgent := headers.Get("User-Agent"); userAgent != "" {
		if err := page.SetUserAgent(&proto.NetworkSetUserAgentOverride{
			UserAgent: userAgent,
		}); err != nil {
			return collect.BrowserResult{}, fmt.Errorf("set browser User-Agent: %w", err)
		}
	}
	if err := setBrowserCookies(page, target, headers); err != nil {
		return collect.BrowserResult{}, err
	}
	extraHeaders := flattenHeaders(headers, "User-Agent", "Cookie")
	restoreHeaders, err := page.SetExtraHeaders(extraHeaders)
	if err != nil {
		return collect.BrowserResult{}, fmt.Errorf("set browser headers: %w", err)
	}
	defer restoreHeaders()

	headerRouter, err := installHeaderIsolation(page, target)
	if err != nil {
		return collect.BrowserResult{}, err
	}
	go headerRouter.Run()
	defer headerRouter.Stop()

	if !c.config.DisableInjection {
		removeScript, injectErr := page.EvalOnNewDocument(c.script)
		if injectErr != nil {
			return collect.BrowserResult{}, fmt.Errorf("inject collector script: %w", injectErr)
		}
		defer removeScript()
	}

	var networkMu sync.Mutex
	network := make(map[string]collect.NetworkRecord)
	eventPage, stopEvents := page.WithCancel()
	waitEvents := eventPage.EachEvent(func(event *proto.NetworkResponseReceived) {
		if event.Response == nil || event.Response.URL == "" {
			return
		}
		networkMu.Lock()
		network[event.Response.URL] = collect.NetworkRecord{
			URL:          event.Response.URL,
			StatusCode:   int(event.Response.Status),
			ContentType:  event.Response.MIMEType,
			ResourceType: string(event.Type),
		}
		networkMu.Unlock()
	})
	go waitEvents()
	defer stopEvents()

	idle := c.config.Idle
	if idle <= 0 {
		idle = 800 * time.Millisecond
	}
	waitForIdle := page.WaitRequestIdle(idle, nil, nil, nil)
	if err := page.Navigate(target.String()); err != nil {
		return collect.BrowserResult{}, fmt.Errorf("navigate browser page: %w", err)
	}
	if err := page.WaitLoad(); err != nil {
		return collect.BrowserResult{}, fmt.Errorf("wait for page load: %w", err)
	}
	waitForIdle()
	if err := waitDuration(scanContext, c.config.Wait); err != nil {
		return collect.BrowserResult{}, err
	}

	html, err := page.HTML()
	if err != nil {
		return collect.BrowserResult{}, fmt.Errorf("read rendered HTML: %w", err)
	}
	injectedURLs, err := snapshotURLs(page, c.config.DisableInjection)
	if err != nil {
		return collect.BrowserResult{}, err
	}
	browserCookies, err := page.Cookies([]string{target.String()})
	if err != nil {
		return collect.BrowserResult{}, fmt.Errorf("read browser cookies: %w", err)
	}

	networkMu.Lock()
	records := make([]collect.NetworkRecord, 0, len(network))
	allURLs := make(map[string]struct{}, len(network)+len(injectedURLs))
	for _, record := range network {
		records = append(records, record)
		allURLs[record.URL] = struct{}{}
	}
	networkMu.Unlock()
	for _, discovered := range injectedURLs {
		allURLs[discovered] = struct{}{}
	}
	urls := make([]string, 0, len(allURLs))
	for discovered := range allURLs {
		urls = append(urls, discovered)
	}
	sort.Strings(urls)
	sort.Slice(records, func(i, j int) bool { return records[i].URL < records[j].URL })

	return collect.BrowserResult{
		HTML: []byte(html), URLs: urls, Network: records,
		Cookies: convertCookies(browserCookies),
	}, nil
}

func installHeaderIsolation(
	page *rod.Page,
	root *url.URL,
) (*rod.HijackRouter, error) {
	router := page.HijackRequests()
	err := router.Add("*", "", func(request *rod.Hijack) {
		requestURL := request.Request.URL()
		if collect.SameOrigin(root, requestURL) {
			request.ContinueRequest(&proto.FetchContinueRequest{})
			return
		}
		actual := make(http.Header)
		for name, value := range request.Request.Headers() {
			actual.Set(name, value.Str())
		}
		filtered := collect.HeadersForURL(actual, root, requestURL)
		entries := make([]*proto.FetchHeaderEntry, 0, len(filtered))
		for name, values := range filtered {
			for _, value := range values {
				entries = append(entries, &proto.FetchHeaderEntry{
					Name: name, Value: value,
				})
			}
		}
		request.ContinueRequest(&proto.FetchContinueRequest{Headers: entries})
	})
	if err != nil {
		_ = router.Stop()
		return nil, fmt.Errorf("isolate cross-origin browser headers: %w", err)
	}
	return router, nil
}

func launch(
	ctx context.Context,
	config model.BrowserConfig,
	proxy string,
	bin string,
	userDataDir string,
) (string, *launcher.Launcher, error) {
	browserLauncher := launcher.New().
		Context(ctx).
		Bin(bin).
		Leakless(false).
		Headless(config.Headless).
		UserDataDir(userDataDir)
	if proxy != "" {
		browserLauncher = browserLauncher.Proxy(proxy)
	}
	control, err := browserLauncher.Launch()
	if err != nil {
		return "", browserLauncher, fmt.Errorf("launch browser: %w", err)
	}
	return control, browserLauncher, nil
}

func convertCookies(browserCookies []*proto.NetworkCookie) []*http.Cookie {
	cookies := make([]*http.Cookie, 0, len(browserCookies))
	for _, cookie := range browserCookies {
		converted := &http.Cookie{
			Name: cookie.Name, Value: cookie.Value,
			Domain: cookie.Domain, Path: cookie.Path,
			Secure: cookie.Secure, HttpOnly: cookie.HTTPOnly,
			SameSite: sameSite(cookie.SameSite),
		}
		if !cookie.Session {
			converted.Expires = time.Unix(int64(cookie.Expires), 0)
		}
		cookies = append(cookies, converted)
	}
	return cookies
}

func sameSite(value proto.NetworkCookieSameSite) http.SameSite {
	switch value {
	case proto.NetworkCookieSameSiteStrict:
		return http.SameSiteStrictMode
	case proto.NetworkCookieSameSiteLax:
		return http.SameSiteLaxMode
	case proto.NetworkCookieSameSiteNone:
		return http.SameSiteNoneMode
	default:
		return http.SameSiteDefaultMode
	}
}

func resolveBrowserPath(configured string) (string, error) {
	if configured != "" {
		info, err := os.Stat(configured)
		if err != nil {
			return "", fmt.Errorf("%w: %s", ErrBrowserNotFound, configured)
		}
		if info.IsDir() {
			return "", fmt.Errorf("%w: %s is a directory", ErrBrowserNotFound, configured)
		}
		return configured, nil
	}
	if found, ok := launcher.LookPath(); ok {
		return found, nil
	}
	return "", ErrBrowserNotFound
}

func setBrowserCookies(
	page *rod.Page,
	target *url.URL,
	headers http.Header,
) error {
	request := &http.Request{Header: headers}
	cookies := request.Cookies()
	if len(cookies) == 0 {
		return nil
	}
	params := make([]*proto.NetworkCookieParam, 0, len(cookies))
	for _, cookie := range cookies {
		params = append(params, &proto.NetworkCookieParam{
			Name: cookie.Name, Value: cookie.Value, URL: target.String(),
		})
	}
	if err := page.SetCookies(params); err != nil {
		return fmt.Errorf("set browser cookies: %w", err)
	}
	return nil
}

func flattenHeaders(headers http.Header, excluded ...string) []string {
	flat := make([]string, 0, len(headers)*2)
	for name, values := range headers {
		if containsFold(excluded, name) {
			continue
		}
		for _, value := range values {
			flat = append(flat, name, value)
		}
	}
	return flat
}

func containsFold(values []string, candidate string) bool {
	for _, value := range values {
		if strings.EqualFold(value, candidate) {
			return true
		}
	}
	return false
}

func waitDuration(ctx context.Context, duration time.Duration) error {
	if duration <= 0 {
		return nil
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return fmt.Errorf("wait for asynchronous JavaScript: %w", ctx.Err())
	case <-timer.C:
		return nil
	}
}

func snapshotURLs(page *rod.Page, disabled bool) ([]string, error) {
	if disabled {
		return nil, nil
	}
	value, err := page.Eval(`() => window.__jsowlCollector ? window.__jsowlCollector.snapshot() : []`)
	if err != nil {
		return nil, fmt.Errorf("read injected collector results: %w", err)
	}
	var urls []string
	if err := value.Value.Unmarshal(&urls); err != nil {
		return nil, fmt.Errorf("decode injected collector results: %w", err)
	}
	return urls, nil
}
