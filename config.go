package jsowl

import (
	"context"

	"github.com/youmulijiang/jsowl/internal/collect/browser"
	"github.com/youmulijiang/jsowl/internal/model"
)

type Config = model.Config
type Mode = model.Mode
type RequestConfig = model.RequestConfig
type BrowserConfig = model.BrowserConfig
type ConcurrencyConfig = model.ConcurrencyConfig
type LimitsConfig = model.LimitsConfig
type ScopeConfig = model.ScopeConfig
type OutputConfig = model.OutputConfig
type RulesConfig = model.RulesConfig
type BrowserCheck = browser.CheckItem
type BrowserCheckReport = browser.CheckReport

const (
	ModeAuto    = model.ModeAuto
	ModeDirect  = model.ModeDirect
	ModeBrowser = model.ModeBrowser
)

// DefaultConfig returns a complete, bounded configuration suitable for auto mode.
func DefaultConfig() Config {
	return model.DefaultConfig()
}

// LoadConfig loads a strict YAML file on top of DefaultConfig and validates it.
func LoadConfig(path string) (Config, error) {
	return model.LoadConfig(path)
}

// CheckBrowser verifies the configured local browser without downloading one.
func CheckBrowser(
	ctx context.Context,
	config BrowserConfig,
) BrowserCheckReport {
	return browser.Check(ctx, config)
}
