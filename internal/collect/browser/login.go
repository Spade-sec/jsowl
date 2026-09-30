package browser

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
	"github.com/youmulijiang/jsowl/internal/model"
)

// loginRecycleAfter is how many collect runs one browser process serves
// before it is restarted with its cookies migrated. Long-lived Chrome
// processes bloat even without leaks (V8 heap fragmentation, GPU cache), and
// a multi-target --login scan can run for a long time in one window.
const loginRecycleAfter = 8

// relaunchTimeout bounds the browser restart inside cookie migration; it
// runs with the scan context possibly already cancelled.
const relaunchTimeout = 30 * time.Second

// LoginSession owns one headed browser the user signs into manually. All
// subsequent managed collections run inside that browser — same process,
// same profile — so the authenticated cookies, localStorage tokens and
// HttpOnly sessions the user established carry straight into the scan.
//
// The session reuses a single tab across collections and recycles the
// browser process every loginRecycleAfter collections, migrating cookies
// across the restart (session cookies included: they are exported before
// the kill and re-injected after the relaunch), so a many-target scan
// neither accumulates tabs nor degrades a bloated renderer.
type LoginSession struct {
	config      model.BrowserConfig
	request     model.RequestConfig
	bin         string
	userDataDir string

	mu       sync.Mutex
	launcher *launcher.Launcher
	browser  *rod.Browser
	page     *rod.Page
	collects int
	migrated []*proto.NetworkCookie
	closed   bool
}

// StartLogin launches a headed browser and hands control to the wait
// callback — typically a terminal "press Enter to continue" prompt with its
// own timeout. A non-nil target opens that page for the user to sign into; a
// nil target leaves the browser on a blank tab so the user can navigate
// wherever they like. The returned session must be Close()d; the browser
// lives until then.
func StartLogin(
	ctx context.Context,
	config model.BrowserConfig,
	request model.RequestConfig,
	target *url.URL,
	waitForUser func(context.Context) error,
) (*LoginSession, error) {
	bin, err := resolveBrowserPath(config.Path)
	if err != nil {
		return nil, err
	}
	// The profile directory lives for the whole session: killing it at scan
	// end, not per collect, is what keeps the login state alive.
	userDataDir, err := os.MkdirTemp("", "jsowl-login-*")
	if err != nil {
		return nil, fmt.Errorf("create login browser profile: %w", err)
	}
	session := &LoginSession{
		config: config, request: request, bin: bin, userDataDir: userDataDir,
	}
	if err := session.launch(ctx); err != nil {
		session.Close()
		return nil, err
	}
	// A nil target means "no page to open": leave the freshly created tab
	// blank and let the user navigate inside the visible browser.
	if target != nil {
		if err := session.page.Navigate(target.String()); err != nil {
			session.Close()
			return nil, fmt.Errorf("navigate login page: %w", err)
		}
	}
	if waitForUser != nil {
		if err := waitForUser(ctx); err != nil {
			session.Close()
			return nil, err
		}
	}
	return session, nil
}

// NewCollector builds a collector bound to this session: its collections run
// in the login browser instead of spawning their own.
func (s *LoginSession) NewCollector() (*Collector, error) {
	collector, err := New(s.config, s.request)
	if err != nil {
		return nil, err
	}
	collector.session = s
	return collector, nil
}

// Close tears the browser down and removes the profile directory.
func (s *LoginSession) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.teardownLocked()
	s.closed = true
	_ = os.RemoveAll(s.userDataDir)
}

// CurrentURL reports the URL the login tab is showing right now, so a
// --login run without an explicit target can adopt the page the user
// navigated to before confirming. It returns an error once the session is
// closed or when no tab is open.
func (s *LoginSession) CurrentURL() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return "", errors.New("login session is closed")
	}
	if s.page == nil {
		return "", errors.New("login session has no open page")
	}
	info, err := s.page.Info()
	if err != nil {
		return "", fmt.Errorf("read login tab URL: %w", err)
	}
	return info.URL, nil
}

// acquire returns the live browser and its reusable tab, relaunching both
// (and restoring migrated cookies) when the process was recycled or died.
func (s *LoginSession) acquire(ctx context.Context) (*rod.Browser, *rod.Page, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, nil, errors.New("login session is closed")
	}
	if s.browser != nil {
		if _, err := (proto.BrowserGetVersion{}).Call(s.browser); err == nil {
			return s.browser, s.page, nil
		}
		// The user closed the window or it crashed; relaunch below.
		s.teardownLocked()
	}
	if err := s.launch(ctx); err != nil {
		return nil, nil, err
	}
	if len(s.migrated) > 0 {
		if err := s.page.SetCookies(cookiesToParams(s.migrated)); err != nil {
			return nil, nil, fmt.Errorf("restore login cookies: %w", err)
		}
	}
	return s.browser, s.page, nil
}

// afterCollect runs at the end of every managed collection: it counts runs
// and, once the recycle threshold is hit, exports the cookie jar and tears
// the browser down so the next acquire relaunches fresh.
func (s *LoginSession) afterCollect() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.browser == nil {
		return
	}
	s.collects++
	if s.collects < loginRecycleAfter {
		return
	}
	s.collects = 0
	if cookies, err := (proto.StorageGetCookies{}).Call(s.browser); err == nil {
		s.migrated = cookies.Cookies
	}
	s.teardownLocked()
}

// launch starts the headed browser and opens its reusable blank tab. Caller
// holds the mutex.
func (s *LoginSession) launch(ctx context.Context) error {
	// Headed is the point of --login: force the window visible regardless
	// of the config layer, which defaults to headless for normal scans.
	headed := s.config
	headed.Headless = false
	control, browserLauncher, err := launch(
		ctx, headed, s.request.Proxy, s.bin, s.userDataDir,
	)
	if err != nil {
		return fmt.Errorf("launch login browser: %w", err)
	}
	rodBrowser := rod.New().
		Context(ctx).
		ControlURL(control).
		NoDefaultDevice()
	if err := rodBrowser.Connect(); err != nil {
		browserLauncher.Kill()
		browserLauncher.Cleanup()
		return fmt.Errorf("connect login browser: %w", err)
	}
	page, err := rodBrowser.Page(proto.TargetCreateTarget{})
	if err != nil {
		_ = rodBrowser.Close()
		browserLauncher.Kill()
		browserLauncher.Cleanup()
		return fmt.Errorf("create login tab: %w", err)
	}
	s.launcher = browserLauncher
	s.browser = rodBrowser
	s.page = page
	return nil
}

// teardownLocked closes the browser and its launcher but keeps the profile
// directory and the session itself alive for relaunch. Caller holds the
// mutex.
func (s *LoginSession) teardownLocked() {
	if s.page != nil {
		_ = s.page.Close()
		s.page = nil
	}
	if s.browser != nil {
		_ = s.browser.Close()
		s.browser = nil
	}
	if s.launcher != nil {
		s.launcher.Kill()
		s.launcher.Cleanup()
		s.launcher = nil
	}
}

// cookiesToParams converts browser-level cookies into injectable params.
// Domain and Path are replayed as-is so scoped cookies land where the login
// put them, including across the recycle restart.
func cookiesToParams(cookies []*proto.NetworkCookie) []*proto.NetworkCookieParam {
	params := make([]*proto.NetworkCookieParam, 0, len(cookies))
	for _, cookie := range cookies {
		if cookie.Name == "" {
			continue
		}
		param := &proto.NetworkCookieParam{
			Name:     cookie.Name,
			Value:    cookie.Value,
			Domain:   cookie.Domain,
			Path:     cookie.Path,
			Secure:   cookie.Secure,
			HTTPOnly: cookie.HTTPOnly,
			SameSite: cookie.SameSite,
		}
		if !cookie.Session {
			param.Expires = cookie.Expires
		}
		params = append(params, param)
	}
	return params
}
