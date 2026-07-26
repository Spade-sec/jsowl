package browser

import (
	"context"
	"fmt"
	"os"
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
	report := CheckReport{Path: config.Path, Checks: make([]CheckItem, 0, 4)}
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

	control, browserLauncher, err := launch(checkContext, config, bin, userDataDir)
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
	report.Passed = true
	return report
}

func appendFailure(report CheckReport, name string, err error) CheckReport {
	report.Checks = append(report.Checks, CheckItem{
		Name: name, Message: err.Error(),
	})
	return report
}
