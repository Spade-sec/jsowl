package browser

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
	"github.com/youmulijiang/jsowl/internal/model"
)

// CheckItem records one ordered browser integrity check.
type CheckItem struct {
	Name    string `json:"name"`
	Passed  bool   `json:"passed"`
	Message string `json:"message"`
}

// CheckReport is the machine-readable result returned by the browser checker.
type CheckReport struct {
	Passed bool        `json:"passed"`
	Path   string      `json:"path,omitempty"`
	Checks []CheckItem `json:"checks"`
}

// Check verifies path resolution, launch, CDP connectivity, and JavaScript
// execution without invoking Rod's browser downloader.
func Check(ctx context.Context, config model.BrowserConfig) CheckReport {
	report := checkOnce(ctx, config)
	if report.Passed || ctx.Err() != nil || !hasTransientFailure(report) {
		return report
	}
	return checkOnce(ctx, config)
}

func checkOnce(ctx context.Context, config model.BrowserConfig) CheckReport {
	report := CheckReport{Path: config.Path, Checks: make([]CheckItem, 0, 7)}
	bin, err := resolveBrowserPath(config.Path)
	if err != nil {
		report.Checks = append(report.Checks, CheckItem{
			Name: "browser_path", Message: err.Error(),
		})
		return report
	}
	report.Path = bin
	report.Checks = append(report.Checks, CheckItem{
		Name: "browser_path", Passed: true, Message: bin,
	})
	sandboxMessage := "browser sandbox enabled"
	if config.NoSandbox {
		sandboxMessage = "browser sandbox disabled by configuration"
	}
	report.Checks = append(report.Checks, CheckItem{
		Name: "sandbox", Passed: true, Message: sandboxMessage,
	})

	timeout := config.Timeout
	if timeout <= 0 || timeout > 15*time.Second {
		timeout = 15 * time.Second
	}
	checkContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	userDataDir, err := os.MkdirTemp("", "jsowl-check-*")
	if err != nil {
		return appendFailure(report, "launch", err)
	}
	defer os.RemoveAll(userDataDir)

	checkConfig := config
	checkConfig.Headless = true
	control, browserLauncher, err := launch(
		checkContext, checkConfig, "", bin, userDataDir,
	)
	if err != nil {
		return appendFailure(report, "launch", err)
	}
	defer browserLauncher.Cleanup()
	defer browserLauncher.Kill()
	report.Checks = append(report.Checks, CheckItem{
		Name: "launch", Passed: true, Message: "browser process started",
	})

	rodBrowser := rod.New().Context(checkContext).ControlURL(control).NoDefaultDevice()
	if err := rodBrowser.Connect(); err != nil {
		return appendFailure(report, "cdp", err)
	}
	defer rodBrowser.Close()
	report.Checks = append(report.Checks, CheckItem{
		Name: "cdp", Passed: true, Message: "DevTools protocol connected",
	})
	browserVersion, err := proto.BrowserGetVersion{}.Call(rodBrowser)
	if err != nil {
		return appendFailure(report, "browser_version", err)
	}
	report.Checks = append(report.Checks, CheckItem{
		Name: "browser_version", Passed: true, Message: browserVersion.Product,
	})

	page, err := rodBrowser.Page(proto.TargetCreateTarget{})
	if err != nil {
		return appendFailure(report, "javascript", err)
	}
	defer page.Close()
	value, err := page.Eval(`() => 6 * 7`)
	if err != nil || value.Value.Int() != 42 {
		if err == nil {
			err = fmt.Errorf("unexpected JavaScript result %s", value.Value)
		}
		return appendFailure(report, "javascript", err)
	}
	report.Checks = append(report.Checks, CheckItem{
		Name: "javascript", Passed: true, Message: "JavaScript execution succeeded",
	})
	collector, err := New(config)
	if err != nil {
		return appendFailure(report, "collector", err)
	}
	removeScript, err := page.EvalOnNewDocument(collector.script)
	if err != nil {
		return appendFailure(report, "collector", err)
	}
	defer removeScript()
	if err := page.Navigate("data:text/html,<main id=\"app\"></main>"); err != nil {
		return appendFailure(report, "collector", err)
	}
	if err := page.WaitLoad(); err != nil {
		return appendFailure(report, "collector", err)
	}
	if _, err := snapshotURLs(page, false); err != nil {
		return appendFailure(report, "collector", err)
	}
	report.Checks = append(report.Checks, CheckItem{
		Name: "collector", Passed: true, Message: "resource collector snapshot succeeded",
	})
	report.Passed = true
	return report
}

func hasTransientFailure(report CheckReport) bool {
	for _, check := range report.Checks {
		message := strings.ToLower(check.Message)
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
	}
	return false
}

func appendFailure(report CheckReport, name string, err error) CheckReport {
	report.Checks = append(report.Checks, CheckItem{
		Name: name, Message: err.Error(),
	})
	return report
}
