package jsowl

import (
	"context"

	"github.com/youmulijiang/jsowl/internal/collect/browser"
	"github.com/youmulijiang/jsowl/internal/model"
)

// Config contains all reusable library and CLI scan settings.
type Config = model.Config

// Mode selects automatic, direct, or browser collection.
type Mode = model.Mode

// RequestConfig controls Surf requests and target-level timeouts.
type RequestConfig = model.RequestConfig

// BrowserConfig controls local Rod browser collection.
type BrowserConfig = model.BrowserConfig

// ConcurrencyConfig bounds target and per-target resource workers.
type ConcurrencyConfig = model.ConcurrencyConfig

// LimitsConfig bounds recursion, resource count, and response size.
type LimitsConfig = model.LimitsConfig

// ScopeConfig controls cross-origin script and API authorization.
type ScopeConfig = model.ScopeConfig

// OutputConfig controls reports and optional JavaScript storage.
type OutputConfig = model.OutputConfig

// RulesConfig enables custom extraction rules and built-in rule disabling.
type RulesConfig = model.RulesConfig

// BrowserCheck records one browser integrity check.
type BrowserCheck = browser.CheckItem

// BrowserCheckReport contains ordered browser integrity checks.
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

// LoadConfigOnto decodes a strict YAML file on top of base: fields the file
// leaves unspecified keep their base values, so configuration layers merge
// (for example a user-level file beneath a project file). It validates the
// result.
func LoadConfigOnto(base Config, path string) (Config, error) {
	return model.LoadConfigOnto(base, path)
}

// CheckBrowser verifies the configured local browser without downloading one.
func CheckBrowser(
	ctx context.Context,
	config BrowserConfig,
) BrowserCheckReport {
	return browser.Check(ctx, config)
}
