package browser

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"hash/fnv"
	"math"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
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

var errPreNavigation = errors.New("browser failed before navigation")

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

	result, err := c.collectOnce(scanContext, target, headers, bin)
	if !isTransientPreNavigation(err) || scanContext.Err() != nil {
		return result, err
	}
	return c.collectOnce(scanContext, target, headers, bin)
}

func (c *Collector) collectOnce(
	ctx context.Context,
	target *url.URL,
	headers http.Header,
	bin string,
) (result collect.BrowserResult, err error) {
	navigationStarted := false
	defer func() {
		if err != nil && !navigationStarted {
			err = fmt.Errorf("%w: %w", errPreNavigation, err)
		}
	}()

	userDataDir, err := os.MkdirTemp("", "jsowl-rod-*")
	if err != nil {
		return collect.BrowserResult{}, fmt.Errorf("create browser profile: %w", err)
	}
	defer os.RemoveAll(userDataDir)

	control, browserLauncher, err := launch(
		ctx, c.config, c.request.Proxy, bin, userDataDir,
	)
	if err != nil {
		return collect.BrowserResult{}, err
	}
	defer browserLauncher.Cleanup()
	defer browserLauncher.Kill()

	rodBrowser := rod.New().
		Context(ctx).
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
	requests := make(map[string]collect.NetworkRecord)
	recordResponse := func(event *proto.NetworkResponseReceived) {
		if event.Response == nil || event.Response.URL == "" {
			return
		}
		networkMu.Lock()
		record := collect.NetworkRecord{
			URL:          event.Response.URL,
			StatusCode:   int(event.Response.Status),
			ContentType:  event.Response.MIMEType,
			ResourceType: string(event.Type),
		}
		if observed, ok := requests[event.Response.URL]; ok {
			record.Method = observed.Method
			record.InitiatorURL = observed.InitiatorURL
			record.Line = observed.Line
			record.Column = observed.Column
		}
		network[event.Response.URL] = record
		networkMu.Unlock()
	}
	recordRequest := func(event *proto.NetworkRequestWillBeSent) {
		if event.Request == nil || event.Request.URL == "" {
			return
		}
		observed := collect.NetworkRecord{
			Method:   event.Request.Method,
			PostData: event.Request.PostData,
		}
		if event.Initiator != nil && event.Initiator.Stack != nil {
			for _, frame := range event.Initiator.Stack.CallFrames {
				if frame.URL != "" {
					observed.InitiatorURL = frame.URL
					observed.Line = int(frame.LineNumber) + 1
					observed.Column = int(frame.ColumnNumber) + 1
					break
				}
			}
		}
		networkMu.Lock()
		requests[event.Request.URL] = observed
		if record, ok := network[event.Request.URL]; ok && record.Method == "" {
			record.Method = observed.Method
			record.InitiatorURL = observed.InitiatorURL
			record.Line = observed.Line
			record.Column = observed.Column
			network[event.Request.URL] = record
		}
		networkMu.Unlock()
	}

	eventPage, stopEvents := page.WithCancel()
	waitEvents := eventPage.EachEvent(recordResponse)
	go waitEvents()
	waitRequests := eventPage.EachEvent(recordRequest)
	go waitRequests()
	defer stopEvents()

	// Cross-origin iframes and workers are separate CDP targets: their
	// traffic never reaches the page session. Auto-attach plus a
	// browser-level subscription mirrors it into the same recorders.
	stopChildTargets := observeChildTargets(ctx, rodBrowser, page, recordResponse, recordRequest)
	defer stopChildTargets()

	idle := c.config.Idle
	if idle <= 0 {
		idle = 800 * time.Millisecond
	}
	waitForIdle := page.WaitRequestIdle(idle, nil, nil, nil)
	navigationStarted = true
	if err := page.Navigate(target.String()); err != nil {
		return collect.BrowserResult{}, fmt.Errorf("navigate browser page: %w", err)
	}
	if err := page.WaitLoad(); err != nil {
		return collect.BrowserResult{}, fmt.Errorf("wait for page load: %w", err)
	}
	abandonIdleWait(ctx, waitForIdle, c.config.IdleMax)
	if err := waitDuration(ctx, c.config.Wait); err != nil {
		return collect.BrowserResult{}, err
	}

	html, err := page.HTML()
	if err != nil {
		return collect.BrowserResult{}, fmt.Errorf("read rendered HTML: %w", err)
	}
	injectedURLs, injectedScripts, injectedRoutes, err := snapshotURLs(page, c.config.DisableInjection)
	if err != nil {
		return collect.BrowserResult{}, err
	}
	// Runtime interactions (form submit, event clicks) fire the requests
	// whose payloads feed the parameter report; they run after the passive
	// snapshot so the baseline observation is never disturbed.
	if c.config.AutoForm || c.config.TriggerEvents {
		interactions := map[string]struct{}{}
		c.interactOnce(page, interactions)
	}
	if c.config.CrawlRoutes && !c.config.DisableInjection {
		// Render every discovered route so each view's own requests are
		// observed: a front-end route guard is not authorization.
		crawled := c.crawlRouteViews(ctx, page, target, injectedRoutes,
			func() ([]string, []string, []collect.BrowserRoute, error) {
				return snapshotURLs(page, c.config.DisableInjection)
			})
		injectedURLs = append(injectedURLs, crawled.URLs...)
		injectedScripts = append(injectedScripts, crawled.Scripts...)
		injectedRoutes = append(injectedRoutes, crawled.Routes...)
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

	sort.Slice(injectedRoutes, func(i, j int) bool {
		return injectedRoutes[i].Path < injectedRoutes[j].Path
	})
	return collect.BrowserResult{
		HTML: []byte(html), URLs: urls, Scripts: injectedScripts,
		Routes: injectedRoutes, Network: records,
		Cookies: convertCookies(browserCookies),
	}, nil
}

func isTransientPreNavigation(err error) bool {
	if err == nil || !errors.Is(err, errPreNavigation) {
		return false
	}
	message := strings.ToLower(err.Error())
	for _, fragment := range []string{
		"closed network connection",
		"connection reset",
		"connection refused",
		"unexpected eof",
		"websocket: close",
	} {
		if strings.Contains(message, fragment) {
			return true
		}
	}
	return false
}

// routeCrawl accumulates what rendering extra framework-route views revealed.
type routeCrawl struct {
	URLs    []string
	Scripts []string
	Routes  []collect.BrowserRoute
	Visited int
}

// digitRun collapses volatile numbers (ids, timestamps) inside a rendered
// document before it is hashed into a view signature.
var digitRun = regexp.MustCompile(`[0-9]+`)

// viewSignature reduces a rendered document to a stable digest so two routes
// that render the same view are only walked once.
func viewSignature(html string) string {
	hash := fnv.New64a()
	_, _ = hash.Write([]byte(digitRun.ReplaceAllString(html, "0")))
	return strconv.FormatUint(hash.Sum64(), 16)
}

// normalizeRoutePath folds a route into a comparable key: query and fragment
// are dropped and instance segments collapse to ":id", so "/user/1" and
// "/user/2" count as one route instead of recursing forever.
func normalizeRoutePath(raw string) string {
	value := raw
	if index := strings.IndexAny(value, "?#"); index >= 0 {
		value = value[:index]
	}
	value = strings.Trim(value, "/")
	if value == "" {
		return ""
	}
	segments := strings.Split(value, "/")
	for index, segment := range segments {
		if isDynamicSegment(segment) {
			segments[index] = ":id"
		}
	}
	return strings.Join(segments, "/")
}

// isDynamicSegment reports whether one route segment is an instance value
// (numeric id, UUID, long token) rather than a stable path name.
func isDynamicSegment(segment string) bool {
	if segment == "" {
		return false
	}
	allDigits, letters := true, 0
	for _, char := range segment {
		switch {
		case char >= '0' && char <= '9':
		case char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z':
			allDigits = false
			letters++
		case char == '-' || char == '_' || char == '.':
			allDigits = false
		default:
			return false
		}
	}
	return allDigits || (letters > 0 && len(segment) >= 16)
}

// routeViewURL turns a discovered route into the URL to navigate to. Hash
// routers keep the route in the fragment, so it cannot be resolved as a path.
func routeViewURL(root *url.URL, route string) string {
	value := strings.TrimSpace(route)
	if value == "" {
		return ""
	}
	reference, err := url.Parse(value)
	if err != nil {
		return ""
	}
	if reference.IsAbs() {
		return reference.String()
	}
	if strings.Contains(value, "#") {
		origin := &url.URL{Scheme: root.Scheme, Host: root.Host}
		return origin.ResolveReference(reference).String()
	}
	return root.ResolveReference(reference).String()
}

// routerPathFor extracts the path a SPA router expects: hash routers keep it
// after "#", history routers use it directly.
func routerPathFor(route string) string {
	value := strings.TrimSpace(route)
	if index := strings.Index(value, "#"); index >= 0 {
		value = value[index+1:]
	}
	if value == "" {
		return ""
	}
	if !strings.HasPrefix(value, "/") {
		value = "/" + value
	}
	return value
}

// crawlRouteViews renders discovered framework routes so each view's own
// requests are observed. Front-end route guards are frequently not
// authorization, so navigating straight to a view often renders it and fires
// its API calls. Bounded by view count, total time and a normalised document
// signature so identical views are not walked twice.
func (c *Collector) crawlRouteViews(
	ctx context.Context,
	page *rod.Page,
	root *url.URL,
	seeds []collect.BrowserRoute,
	snapshot func() ([]string, []string, []collect.BrowserRoute, error),
) routeCrawl {
	result := routeCrawl{}
	deadline := time.Now().Add(c.crawlTimeout())
	maxRoutes := c.maxRoutes()
	seenPaths := make(map[string]struct{})
	seenViews := make(map[string]struct{})
	urls := make(map[string]struct{})
	scripts := make(map[string]struct{})
	routes := make(map[string]collect.BrowserRoute)
	queue := append([]collect.BrowserRoute(nil), seeds...)

	for len(queue) > 0 {
		if ctx.Err() != nil || result.Visited >= maxRoutes ||
			time.Now().After(deadline) {
			break
		}
		route := queue[0]
		queue = queue[1:]
		key := normalizeRoutePath(route.Path)
		if key == "" {
			continue
		}
		if _, seen := seenPaths[key]; seen {
			continue
		}
		seenPaths[key] = struct{}{}
		target := routeViewURL(root, route.Path)
		if target == "" || !c.navigateRoute(ctx, page, route.Path, target) {
			continue
		}
		result.Visited++

		html, err := page.HTML()
		if err != nil {
			continue
		}
		signature := viewSignature(html)
		if _, seen := seenViews[signature]; seen {
			// The view rendered identically to one already walked, so it
			// cannot expose new routes; skip it and its subtree.
			continue
		}
		seenViews[signature] = struct{}{}

		foundURLs, foundScripts, foundRoutes, err := snapshot()
		if err != nil {
			continue
		}
		if c.config.AutoForm || c.config.TriggerEvents {
			c.interactOnce(page, seenViews)
		}
		for _, raw := range foundURLs {
			urls[raw] = struct{}{}
		}
		for _, raw := range foundScripts {
			scripts[raw] = struct{}{}
		}
		for _, discovered := range foundRoutes {
			if discovered.Path == "" {
				continue
			}
			if _, seen := routes[discovered.Path]; seen {
				continue
			}
			routes[discovered.Path] = discovered
			queue = append(queue, discovered)
		}
	}

	for raw := range urls {
		result.URLs = append(result.URLs, raw)
	}
	for raw := range scripts {
		result.Scripts = append(result.Scripts, raw)
	}
	for _, route := range routes {
		result.Routes = append(result.Routes, route)
	}
	sort.Strings(result.URLs)
	sort.Strings(result.Scripts)
	sort.Slice(result.Routes, func(i, j int) bool {
		return result.Routes[i].Path < result.Routes[j].Path
	})
	return result
}

// navigateRoute switches to one route, preferring an in-page router push so
// the shell is not re-downloaded for every view.
func (c *Collector) navigateRoute(
	ctx context.Context,
	page *rod.Page,
	route string,
	target string,
) bool {
	if path := routerPathFor(route); path != "" {
		value, err := page.Eval(
			`(p) => window.__jsowlCollector && window.__jsowlCollector.navigate ? window.__jsowlCollector.navigate(p) : false`,
			path,
		)
		if err == nil && value.Value.Bool() {
			return waitDuration(ctx, c.routeViewWait()) == nil
		}
	}
	if err := page.Navigate(target); err != nil {
		return false
	}
	if err := page.WaitLoad(); err != nil {
		return false
	}
	return waitDuration(ctx, c.routeViewWait()) == nil
}

func (c *Collector) maxRoutes() int {
	if c.config.MaxRoutes > 0 {
		return c.config.MaxRoutes
	}
	// 0 means no cap: walk every route the deadline and view signatures
	// allow.
	return math.MaxInt
}

func (c *Collector) crawlTimeout() time.Duration {
	if c.config.CrawlTimeout > 0 {
		return c.config.CrawlTimeout
	}
	return 60 * time.Second
}

// routeViewWait is the grace period after switching views. It is deliberately
// shorter than the entry-page wait: crawling multiplies it by the route count.
func (c *Collector) routeViewWait() time.Duration {
	switch wait := c.config.Wait; {
	case wait <= 0:
		return 800 * time.Millisecond
	case wait > 2*time.Second:
		return 2 * time.Second
	default:
		return wait
	}
}

// observeChildTargets attaches to the cross-origin iframes and workers the
// page spawns and mirrors their Network events into the page-level recorders.
// Those targets run in their own CDP sessions, so without auto-attach the
// scripts and endpoints they load are invisible to the scan.
func observeChildTargets(
	ctx context.Context,
	browser *rod.Browser,
	page *rod.Page,
	onResponse func(*proto.NetworkResponseReceived),
	onRequest func(*proto.NetworkRequestWillBeSent),
) func() {
	// Attach on the page session so only targets related to this page — its
	// frames and workers — are followed, never unrelated browser tabs.
	if err := (proto.TargetSetAutoAttach{
		AutoAttach:             true,
		WaitForDebuggerOnStart: false,
		Flatten:                true,
	}).Call(page); err != nil {
		return func() {}
	}
	messages := browser.Event()
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-done:
				return
			case message, ok := <-messages:
				if !ok {
					return
				}
				switch message.Method {
				case "Target.attachedToTarget":
					event := &proto.TargetAttachedToTarget{}
					if message.Load(event) {
						// A session reports nothing until its Network
						// domain is enabled.
						_, _ = browser.Call(
							ctx, string(event.SessionID),
							"Network.enable", proto.NetworkEnable{},
						)
					}
				case "Network.responseReceived":
					event := &proto.NetworkResponseReceived{}
					if message.Load(event) {
						onResponse(event)
					}
				case "Network.requestWillBeSent":
					event := &proto.NetworkRequestWillBeSent{}
					if message.Load(event) {
						onRequest(event)
					}
				}
			}
		}
	}()
	return func() { close(done) }
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
		UserDataDir(userDataDir).
		NoSandbox(config.NoSandbox)
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

// abandonIdleWait caps the WaitRequestIdle phase at maxWait: polling SPAs
// never keep the network quiet for the idle duration, so waiting forever
// would run the browser session to Timeout. When maxWait elapses the wait
// is abandoned in the background and collection continues with what has
// already been observed. maxWait <= 0 restores the uncapped behavior.
func abandonIdleWait(ctx context.Context, waitForIdle func(), maxWait time.Duration) bool {
	if maxWait <= 0 {
		waitForIdle()
		return false
	}
	abandoned := make(chan struct{})
	go func() {
		waitForIdle()
		close(abandoned)
	}()
	timer := time.NewTimer(maxWait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-abandoned:
		return false
	case <-timer.C:
		return true
	}
}

func snapshotURLs(
	page *rod.Page,
	disabled bool,
) ([]string, []string, []collect.BrowserRoute, error) {
	if disabled {
		return nil, nil, nil, nil
	}
	value, err := page.Eval(`() => window.__jsowlCollector ? window.__jsowlCollector.snapshot() : {urls: [], scripts: [], routes: []}`)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read injected collector results: %w", err)
	}
	var snapshot struct {
		URLs    []string               `json:"urls"`
		Scripts []string               `json:"scripts"`
		Routes  []collect.BrowserRoute `json:"routes"`
	}
	if err := value.Value.Unmarshal(&snapshot); err != nil {
		return nil, nil, nil, fmt.Errorf("decode injected collector results: %w", err)
	}
	return snapshot.URLs, snapshot.Scripts, snapshot.Routes, nil
}
