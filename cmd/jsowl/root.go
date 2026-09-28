package main

import (
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
	"github.com/youmulijiang/jsowl/internal/model"
)

// version is overridden at build time via -ldflags "-X ...version=v1.2.3".
var version = "dev"

type scanService interface {
	ScanBatch(context.Context, []jsowl.Target) <-chan jsowl.BatchItem
	SetProbeSink(chan<- jsowl.ProbeEvent)
}

type dependencies struct {
	stdout         io.Writer
	stderr         io.Writer
	defaultConfig  func() jsowl.Config
	loadConfig     func(string) (jsowl.Config, error)
	loadConfigOnto func(jsowl.Config, string) (jsowl.Config, error)
	userHomeDir    func() (string, error)
	newScanner     func(jsowl.Config) (scanService, error)
	writeJSON      func(string, *jsowl.Result) error
	writeHTML      func(string, *jsowl.Result) error
	writeText      func(string, *jsowl.Result) error
	check          func(context.Context, jsowl.BrowserConfig) jsowl.BrowserCheckReport
	ensureOutput   func(string) error
	// ensureUserRules seeds ~/.jsowl/rules.yaml on first run.
	ensureUserRules func(path string) (bool, error)
	// loadRules reads a rules file in either supported schema.
	loadRules func(path string) (model.RulesConfig, error)
}

// newRootCommand constructs JsOwl's root-only command. The flag surface and
// override rules live in options.go (options.register / options.applyOverrides).
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
			if err := opts.applyOverrides(command, &config); err != nil {
				return err
			}
			if opts.check {
				if _, err := deps.newScanner(config); err != nil {
					return fmt.Errorf("validate rules and configuration: %w", err)
				}
				return runCheck(command.Context(), deps, config)
			}
			targets, err := opts.targets()
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
	// pflag cannot parse the literal "-aff" (see normalizeAffFlag), so the
	// process arguments are rewritten before Cobra sees them.
	command.SetArgs(normalizeAffFlag(os.Args[1:]))
	opts.register(command.Flags())
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
	if deps.loadConfigOnto == nil {
		deps.loadConfigOnto = jsowl.LoadConfigOnto
	}
	if deps.userHomeDir == nil {
		deps.userHomeDir = os.UserHomeDir
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
	if deps.ensureUserRules == nil {
		deps.ensureUserRules = ensureUserRulesFile
	}
	if deps.loadRules == nil {
		deps.loadRules = model.LoadRulesFile
	}
	return deps
}

// configFlagHelp describes the -c flag and shows where the auto-created
// user-level config lives, so users can find it from --help alone.
func configFlagHelp() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "YAML configuration file"
	}
	return "YAML configuration file (user-level default: " + userConfigPath(home) + ")"
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

// loadConfiguration resolves the effective configuration. With -c the named
// file replaces everything below it. Otherwise the layers merge, each field
// taken from the highest layer that sets it: the project config.yml in the
// working directory, then the user-level ~/.jsowl/config.yml (auto-created
// with a commented template on first run, its path announced on stderr), then
// the built-in defaults. Rules resolve through their own chain: an explicit
// rules_file, then the project config/rules.yml, then ~/.jsowl/rules.yaml
// (seeded on first run), then the compiled-in defaults.
func loadConfiguration(deps dependencies, explicit string) (jsowl.Config, error) {
	if explicit != "" {
		config, err := deps.loadConfig(explicit)
		if err != nil {
			return jsowl.Config{}, err
		}
		return config, nil
	}
	config := deps.defaultConfig()
	home, err := deps.userHomeDir()
	hadHome := err == nil
	if hadHome {
		userPath := userConfigPath(home)
		created, err := ensureUserConfigFile(userPath)
		if err != nil {
			return jsowl.Config{}, err
		}
		if created {
			_, _ = fmt.Fprintf(deps.stderr, "created user config: %s\n", userPath)
		} else {
			_, _ = fmt.Fprintf(deps.stderr, "user config: %s\n", userPath)
		}
		config, err = deps.loadConfigOnto(config, userPath)
		if err != nil {
			return jsowl.Config{}, fmt.Errorf("load user config: %w", err)
		}
	}
	// Without a home directory there is no user-level config to consult;
	// continue with the project config and built-in defaults. The project
	// config lives in config/config.yml; a top-level ./config.yml is still
	// honoured for backward compatibility with existing layouts.
	projectConfig := ""
	for _, candidate := range []string{
		filepath.Join("config", "config.yml"),
		"config.yml",
	} {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			projectConfig = candidate
			break
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return jsowl.Config{}, fmt.Errorf("inspect optional %s: %w", candidate, err)
		}
	}
	if projectConfig != "" {
		config, err = deps.loadConfigOnto(config, projectConfig)
		if err != nil {
			return jsowl.Config{}, fmt.Errorf("load %s: %w", projectConfig, err)
		}
	}
	// Project rules layer: config/rules.yml next to the project config is the
	// editable rules document shipped with a checkout; it wins over the
	// user-level rules.yaml, mirroring how the project config wins over the
	// user config. An explicit rules_file (user config or project config)
	// always wins over both.
	if config.RulesFile == "" && rulesConfigEmpty(config.Rules) {
		projectRules := filepath.Join("config", "rules.yml")
		if info, err := os.Stat(projectRules); err == nil && !info.IsDir() {
			_, _ = fmt.Fprintf(deps.stderr, "project rules: %s\n", projectRules)
			rules, err := deps.loadRules(projectRules)
			if err != nil {
				return jsowl.Config{}, fmt.Errorf("load %s: %w", projectRules, err)
			}
			config.Rules = rules
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return jsowl.Config{}, fmt.Errorf("inspect optional %s: %w", projectRules, err)
		}
	}
	// Default rules layer: when no configuration layer chose a rules_file and
	// no project rules.yml exists, seed and load the user-level rules.yaml so
	// the sensitive rules live in an editable file instead of hard-coded
	// behavior.
	if hadHome && config.RulesFile == "" && rulesConfigEmpty(config.Rules) {
		rulesPath := userRulesPath(home)
		created, err := deps.ensureUserRules(rulesPath)
		if err != nil {
			return jsowl.Config{}, err
		}
		if created {
			_, _ = fmt.Fprintf(deps.stderr, "created user rules: %s\n", rulesPath)
		}
		rules, err := deps.loadRules(rulesPath)
		if err != nil {
			return jsowl.Config{}, fmt.Errorf("load user rules: %w", err)
		}
		config.Rules = rules
	}
	return config, nil
}

// rulesConfigEmpty reports whether no rule source reached the config: any
// explicit rules_file, include, disabled entry, or custom rule disables the
// default user-level rules layer.
func rulesConfigEmpty(rules model.RulesConfig) bool {
	return len(rules.Include) == 0 && len(rules.Disabled) == 0 &&
		len(rules.Custom) == 0
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
