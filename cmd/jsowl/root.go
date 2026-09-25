package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/cespare/xxhash/v2"
	"github.com/spf13/cobra"
	"github.com/youmulijiang/jsowl"
)

// version is overridden at build time via -ldflags "-X ...version=v1.2.3".
var version = "dev"

type scanService interface {
	ScanBatch(context.Context, []jsowl.Target) <-chan jsowl.BatchItem
	SetProbeSink(chan<- jsowl.ProbeEvent)
}

type dependencies struct {
	stdout        io.Writer
	stderr        io.Writer
	defaultConfig func() jsowl.Config
	loadConfig    func(string) (jsowl.Config, error)
	newScanner    func(jsowl.Config) (scanService, error)
	writeJSON     func(string, *jsowl.Result) error
	writeHTML     func(string, *jsowl.Result) error
	writeText     func(string, *jsowl.Result) error
	check         func(context.Context, jsowl.BrowserConfig) jsowl.BrowserCheckReport
	ensureOutput  func(string) error
}

type options struct {
	urls    []string
	list    string
	config  string
	output  string
	mode    string
	proxy   string
	baseURL string
	headers []string
	scopes  []string
	threads int
	silent  bool
	version bool
	check   bool
}

// newRootCommand constructs JsOwl's root-only command.
func newRootCommand(deps dependencies) *cobra.Command {
	deps = completeDependencies(deps)
	opts := &options{}
	command := &cobra.Command{
		Use:           "jsowl",
		Short:         "Collect and analyze JavaScript security information",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(command *cobra.Command, _ []string) error {
			if opts.version {
				_, err := fmt.Fprintf(deps.stdout, "JsOwl %s\n", version)
				return err
			}
			config, err := loadConfiguration(deps, opts.config)
			if err != nil {
				return err
			}
			if err := applyOverrides(command, opts, &config); err != nil {
				return err
			}
			if opts.check {
				if _, err := deps.newScanner(config); err != nil {
					return fmt.Errorf("validate rules and configuration: %w", err)
				}
				return runCheck(command.Context(), deps, config)
			}
			targets, err := loadTargets(opts.urls, opts.list)
			if err != nil {
				return err
			}
			if len(targets) == 0 {
				return errors.New("at least one target is required; use -u or -l")
			}
			if err := applyBaseURL(targets, opts.baseURL); err != nil {
				return err
			}
			return runScans(
				command.Context(), deps, config, targets, opts.silent,
			)
		},
	}
	command.SetOut(deps.stdout)
	command.SetErr(deps.stderr)
	flags := command.Flags()
	flags.StringArrayVarP(&opts.urls, "url", "u", nil, "target URL (repeatable)")
	flags.StringVarP(&opts.list, "list", "l", "", "file containing target URLs")
	flags.StringVarP(&opts.config, "config", "c", "", "YAML configuration file")
	flags.StringVarP(&opts.output, "output", "o", "", "report output directory")
	flags.StringVarP(&opts.mode, "mode", "m", "", "auto, direct, or browser")
	flags.StringVarP(&opts.proxy, "proxy", "p", "", "HTTP(S) or SOCKS5 proxy URL")
	flags.StringVar(&opts.baseURL, "base-url", "", "base URL for relative discoveries")
	flags.StringArrayVarP(&opts.headers, "header", "H", nil, "request header Name: value")
	flags.StringArrayVar(&opts.scopes, "scope", nil,
		"restrict crawling to these comma-separated domains (repeatable; root origin always allowed)")
	flags.IntVarP(&opts.threads, "threads", "t", 0, "per-target resource concurrency")
	flags.BoolVarP(&opts.silent, "silent", "s", false, "suppress successful result lines")
	flags.BoolVarP(&opts.version, "version", "v", false, "print version")
	flags.BoolVar(&opts.check, "check", false, "check config, rules, and browser")
	return command
}

func completeDependencies(deps dependencies) dependencies {
	if deps.stdout == nil {
		deps.stdout = os.Stdout
	}
	if deps.stderr == nil {
		deps.stderr = os.Stderr
	}
	if deps.defaultConfig == nil {
		deps.defaultConfig = jsowl.DefaultConfig
	}
	if deps.loadConfig == nil {
		deps.loadConfig = jsowl.LoadConfig
	}
	if deps.newScanner == nil {
		deps.newScanner = func(config jsowl.Config) (scanService, error) {
			return jsowl.New(config)
		}
	}
	if deps.writeJSON == nil {
		deps.writeJSON = jsowl.WriteJSONReport
	}
	if deps.writeHTML == nil {
		deps.writeHTML = jsowl.WriteHTMLReport
	}
	if deps.writeText == nil {
		deps.writeText = jsowl.WriteTextReports
	}
	if deps.check == nil {
		deps.check = jsowl.CheckBrowser
	}
	if deps.ensureOutput == nil {
		deps.ensureOutput = ensureWritableDirectory
	}
	return deps
}

func ensureWritableDirectory(path string) error {
	if err := os.MkdirAll(path, 0o750); err != nil {
		return err
	}
	probe, err := os.CreateTemp(path, ".jsowl-write-check-*")
	if err != nil {
		return err
	}
	probePath := probe.Name()
	if err := probe.Close(); err != nil {
		_ = os.Remove(probePath)
		return err
	}
	return os.Remove(probePath)
}

func loadConfiguration(deps dependencies, explicit string) (jsowl.Config, error) {
	if explicit != "" {
		config, err := deps.loadConfig(explicit)
		if err != nil {
			return jsowl.Config{}, err
		}
		return config, nil
	}
	if info, err := os.Stat("config.yml"); err == nil && !info.IsDir() {
		return deps.loadConfig("config.yml")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return jsowl.Config{}, fmt.Errorf("inspect optional config.yml: %w", err)
	}
	return deps.defaultConfig(), nil
}

func applyOverrides(
	command *cobra.Command,
	opts *options,
	config *jsowl.Config,
) error {
	if command.Flags().Changed("output") {
		config.Output.Directory = opts.output
	}
	if command.Flags().Changed("mode") {
		config.Mode = jsowl.Mode(opts.mode)
	}
	if command.Flags().Changed("threads") {
		config.Concurrency.ResourcesPerTarget = opts.threads
	}
	if command.Flags().Changed("scope") {
		config.Scope.RestrictDomains = parseScopeDomains(opts.scopes)
	}
	if command.Flags().Changed("proxy") {
		config.Request.Proxy = opts.proxy
	}
	if config.Request.Headers == nil {
		config.Request.Headers = make(map[string]string)
	}
	for _, raw := range opts.headers {
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

func runCheck(
	ctx context.Context,
	deps dependencies,
	config jsowl.Config,
) error {
	if err := deps.ensureOutput(config.Output.Directory); err != nil {
		return fmt.Errorf("check output directory: %w", err)
	}
	_, _ = fmt.Fprintln(deps.stdout, "[ok] configuration and rules")
	_, _ = fmt.Fprintln(deps.stdout, "[ok] output directory")
	report := deps.check(ctx, config.Browser)
	for _, item := range report.Checks {
		status := "fail"
		if item.Passed {
			status = "ok"
		}
		_, _ = fmt.Fprintf(
			deps.stdout, "[%s] %s: %s\n",
			status, item.Name, item.Message,
		)
	}
	if !report.Passed {
		return errors.New("browser integrity check failed")
	}
	return nil
}

func runScans(
	ctx context.Context,
	deps dependencies,
	config jsowl.Config,
	targets []jsowl.Target,
	silent bool,
) error {
	if err := deps.ensureOutput(config.Output.Directory); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	scanner, err := deps.newScanner(config)
	if err != nil {
		return err
	}
	// Producer-consumer printing: the scanner (producer) pushes one probe
	// event per completed API probe into a buffered channel; a dedicated
	// printer goroutine (consumer) drains it so report writing and further
	// scanning are never blocked. A slow terminal only drops events. Both
	// the printer and the batch loop write to stdout, so they share a
	// synchronized writer to keep lines from interleaving.
	probeEvents := make(chan jsowl.ProbeEvent, 256)
	printable := &synchronizedWriter{writer: deps.stdout}
	if !silent {
		scanner.SetProbeSink(probeEvents)
	}
	printerDone := startProbePrinter(printable, probeEvents, silent)
	failures := 0
	for item := range scanner.ScanBatch(ctx, targets) {
		if item.Result != nil {
			if status := item.Result.BrowserStatus; status.Degraded {
				// Keep the degradation visible even with --silent: the scan
				// still succeeds, but runtime extraction was lost.
				_, _ = fmt.Fprintf(
					deps.stderr, "%s: browser degraded, keeping direct results: %s\n",
					item.Target.URL, status.Reason,
				)
			}
			if reportErr := writeReports(deps, config, item.Target, item.Result); reportErr != nil {
				failures++
				_, _ = fmt.Fprintf(deps.stderr, "%s: %v\n", item.Target.URL, reportErr)
			}
		}
		if item.Err != nil {
			failures++
			_, _ = fmt.Fprintf(deps.stderr, "%s: %v\n", item.Target.URL, item.Err)
			continue
		}
		if !silent {
			for _, line := range formatResultLines(item.Result) {
				_, _ = fmt.Fprintln(printable, line)
			}
		}
	}
	close(probeEvents)
	<-printerDone
	if failures > 0 {
		return fmt.Errorf("%d target or report task(s) failed", failures)
	}
	return nil
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

// synchronizedWriter serializes concurrent writes so probe lines from the
// printer goroutine never interleave with batch result lines mid-line.
type synchronizedWriter struct {
	mu     sync.Mutex
	writer io.Writer
}

func (writer *synchronizedWriter) Write(data []byte) (int, error) {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	return writer.writer.Write(data)
}

// startProbePrinter launches the consumer side of probe-event streaming. It
// returns a channel closed once the printer has drained every event, so the
// caller can guarantee all lines are flushed before exiting. In silent mode
// events are still drained (keeping the producer unblocked) but not printed.
func startProbePrinter(
	stdout io.Writer,
	events <-chan jsowl.ProbeEvent,
	silent bool,
) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		for event := range events {
			if silent {
				continue
			}
			_, _ = fmt.Fprintln(stdout, formatProbeLine(event))
		}
	}()
	return done
}

func formatProbeLine(event jsowl.ProbeEvent) string {
	method := event.Method
	if method == "" {
		method = "GET"
	}
	return fmt.Sprintf("[%d] %s %s [%s]", event.StatusCode, method, event.URL, event.Evidence)
}

func formatResultLines(result *jsowl.Result) []string {
	if result == nil {
		return nil
	}
	lines := make([]string, 0, max(1, len(result.Resources)))
	for _, resource := range result.Resources {
		lines = append(lines, fmt.Sprintf(
			"%s [%d] [%d] [%s]",
			resource.URL,
			resource.Size,
			resource.StatusCode,
			resource.ContentType,
		))
	}
	if len(lines) == 0 {
		lines = append(lines, fmt.Sprintf("%s [0] [0] []", result.Target))
	}
	return lines
}

func writeReports(
	deps dependencies,
	config jsowl.Config,
	target jsowl.Target,
	result *jsowl.Result,
) error {
	directory, err := targetReportDirectory(config.Output.Directory, target.URL)
	if err != nil {
		return err
	}
	if config.Output.JSON {
		if err := deps.writeJSON(filepath.Join(directory, "report.json"), result); err != nil {
			return err
		}
	}
	if config.Output.HTML {
		if err := deps.writeHTML(filepath.Join(directory, "report.html"), result); err != nil {
			return err
		}
	}
	if deps.writeText != nil {
		if err := deps.writeText(directory, result); err != nil {
			return err
		}
	}
	if config.Output.HTML {
		if err := jsowl.WriteSplitReports(directory, result); err != nil {
			return err
		}
	}
	return nil
}

var invalidDirectoryCharacter = regexp.MustCompile(`[<>:"/\\|?*\x00-\x1f]`)

func targetReportDirectory(root, rawTarget string) (string, error) {
	parsed, err := url.Parse(rawTarget)
	if err != nil || parsed.Host == "" {
		return "", fmt.Errorf("derive report directory for %q", rawTarget)
	}
	name := strings.Trim(invalidDirectoryCharacter.ReplaceAllString(parsed.Host, "_"), " .")
	if name == "" {
		return "", errors.New("target host produced an empty report directory")
	}
	if (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" {
		parsed.Fragment = ""
		name += fmt.Sprintf("-%08x", uint32(xxhash.Sum64String(parsed.String())))
	}
	return filepath.Join(root, name), nil
}
