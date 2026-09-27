package main

// The CLI surface lives here, Cobra-style: the options struct owns every
// user-supplied value, register() binds them to the flag set, and
// applyOverrides folds the changed flags into the merged configuration.
// root.go keeps only the command definition and its runtime.

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/youmulijiang/jsowl"
)

// options carries every CLI-supplied value. Zero values mean "not set"; only
// flags the user actually passed (Changed) override the configuration layers.
type options struct {
	urls            []string
	list            string
	config          string
	output          string
	mode            string
	proxy           string
	baseURL         string
	headers         []string
	scopes          []string
	threads         int
	silent          bool
	version         bool
	check           bool
	autoFormFill    bool
	maxInteractions int
}

// register binds all flags. The declaration order is the --help order.
// The browser-interaction flags sit together at the end: they all act
// through the same runtime-interaction engine and share the same
// write-path warning.
func (o *options) register(flags *pflag.FlagSet) {
	flags.StringArrayVarP(&o.urls, "url", "u", nil, "target URL (repeatable)")
	flags.StringVarP(&o.list, "list", "l", "", "file containing target URLs")
	flags.StringVarP(&o.config, "config", "c", "", configFlagHelp())
	flags.StringVarP(&o.output, "output", "o", "", "report output directory")
	flags.StringVarP(&o.mode, "mode", "m", "", "auto, direct, or browser")
	flags.StringVarP(&o.proxy, "proxy", "p", "", "HTTP(S) or SOCKS5 proxy URL")
	flags.StringVar(&o.baseURL, "base-url", "", "base URL for relative discoveries")
	flags.StringArrayVarP(&o.headers, "header", "H", nil, "request header Name: value")
	flags.StringArrayVar(&o.scopes, "scope", nil,
		"restrict crawling to these comma-separated domains (repeatable; root origin always allowed)")
	flags.IntVarP(&o.threads, "threads", "t", 0, "per-target resource concurrency")
	flags.BoolVarP(&o.silent, "silent", "s", false, "suppress successful result lines")
	flags.BoolVarP(&o.version, "version", "v", false, "print version")
	flags.BoolVar(&o.check, "check", false, "check config, rules, and browser")
	flags.BoolVar(&o.autoFormFill, "aff", false,
		"automatic form fill: fill and submit page forms AND click interactive elements at runtime (katana-style, may trigger write paths); enables browser.auto_form and browser.trigger_events together")
	flags.IntVar(&o.maxInteractions, "max-interactions", 0,
		"cap form submits plus event clicks per page (default 20)")
}

// applyOverrides folds the flags the user passed into the layered
// configuration. Flags that were not given leave the config value untouched.
func (o *options) applyOverrides(command *cobra.Command, config *jsowl.Config) error {
	if command.Flags().Changed("output") {
		config.Output.Directory = o.output
	}
	if command.Flags().Changed("mode") {
		config.Mode = jsowl.Mode(o.mode)
	}
	if command.Flags().Changed("threads") {
		config.Concurrency.ResourcesPerTarget = o.threads
	}
	if command.Flags().Changed("scope") {
		config.Scope.RestrictDomains = parseScopeDomains(o.scopes)
	}
	if command.Flags().Changed("proxy") {
		config.Request.Proxy = o.proxy
	}
	if command.Flags().Changed("aff") {
		config.Browser.AutoForm = o.autoFormFill
		config.Browser.TriggerEvents = o.autoFormFill
	}
	if command.Flags().Changed("max-interactions") {
		config.Browser.MaxInteractions = o.maxInteractions
	}
	if config.Request.Headers == nil {
		config.Request.Headers = make(map[string]string)
	}
	for _, raw := range o.headers {
		name, value, err := parseHeader(raw)
		if err != nil {
			return err
		}
		for existing := range config.Request.Headers {
			if strings.EqualFold(existing, name) {
				delete(config.Request.Headers, existing)
			}
		}
		config.Request.Headers[name] = value
	}
	return config.Validate()
}

// targets resolves the scan targets from -u repeats and the -l file.
func (o *options) targets() ([]jsowl.Target, error) {
	return loadTargets(o.urls, o.list)
}

// normalizeAffFlag rewrites the katana-style "-aff" token to "--aff":
// pflag only supports single-character shorthands, so "-aff" would otherwise
// parse as the cluster "-a -f -f" and fail.
func normalizeAffFlag(args []string) []string {
	normalized := make([]string, 0, len(args))
	for _, arg := range args {
		if arg == "-aff" {
			arg = "--aff"
		}
		normalized = append(normalized, arg)
	}
	return normalized
}

func applyBaseURL(targets []jsowl.Target, raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	base, err := url.Parse(raw)
	if err != nil || !base.IsAbs() || base.Host == "" ||
		(base.Scheme != "http" && base.Scheme != "https") ||
		base.User != nil {
		return fmt.Errorf("invalid base URL %q", raw)
	}
	for index := range targets {
		targets[index].BaseURL = base.String()
	}
	return nil
}

func parseHeader(raw string) (string, string, error) {
	name, value, found := strings.Cut(raw, ":")
	name = strings.TrimSpace(name)
	value = strings.TrimSpace(value)
	if !found || name == "" || !validHeaderName(name) {
		return "", "", fmt.Errorf("invalid header %q; expected Name: value", raw)
	}
	if strings.ContainsAny(value, "\r\n") {
		return "", "", fmt.Errorf("invalid newline in header %q", name)
	}
	return name, value, nil
}

func validHeaderName(name string) bool {
	const tokenSpecials = "!#$%&'*+-.^_`|~"
	for _, character := range name {
		if character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' ||
			strings.ContainsRune(tokenSpecials, character) {
			continue
		}
		return false
	}
	return name != ""
}

// loadTargets merges -u repeats with the -l file (comments and blanks
// skipped) and validates every URL; duplicates collapse silently.
func loadTargets(urls []string, listPath string) ([]jsowl.Target, error) {
	rawTargets := append([]string(nil), urls...)
	if listPath != "" {
		file, err := os.Open(listPath)
		if err != nil {
			return nil, fmt.Errorf("open target list: %w", err)
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 64*1024), 1024*1024)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				rawTargets = append(rawTargets, line)
			}
		}
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("read target list: %w", err)
		}
	}

	seen := make(map[string]struct{})
	targets := make([]jsowl.Target, 0, len(rawTargets))
	for _, raw := range rawTargets {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		parsed, err := url.ParseRequestURI(raw)
		if err != nil || parsed.Host == "" ||
			(parsed.Scheme != "http" && parsed.Scheme != "https") {
			return nil, fmt.Errorf("invalid target URL %q", raw)
		}
		if _, duplicate := seen[raw]; duplicate {
			continue
		}
		seen[raw] = struct{}{}
		targets = append(targets, jsowl.Target{URL: raw})
	}
	return targets, nil
}

// parseScopeDomains accepts both repeated flags and comma-separated values:
// --scope a.com --scope b.com and --scope a.com,b.com produce the same list.
func parseScopeDomains(values []string) []string {
	domains := make([]string, 0, len(values))
	for _, value := range values {
		for _, domain := range strings.Split(value, ",") {
			domain = strings.TrimSpace(domain)
			if domain != "" {
				domains = append(domains, domain)
			}
		}
	}
	return domains
}
