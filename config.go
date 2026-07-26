package jsowl

import "github.com/youmulijiang/jsowl/internal/model"

type Config = model.Config
type Mode = model.Mode
type RequestConfig = model.RequestConfig
type BrowserConfig = model.BrowserConfig
type ConcurrencyConfig = model.ConcurrencyConfig
type LimitsConfig = model.LimitsConfig
type ScopeConfig = model.ScopeConfig
type OutputConfig = model.OutputConfig
type RulesConfig = model.RulesConfig

const (
	ModeAuto    = model.ModeAuto
	ModeDirect  = model.ModeDirect
	ModeBrowser = model.ModeBrowser
)

func DefaultConfig() Config {
	return model.DefaultConfig()
}

func LoadConfig(path string) (Config, error) {
	return model.LoadConfig(path)
}
