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
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/youmulijiang/jsowl"
	"github.com/youmulijiang/jsowl/internal/model"
)

// version is overridden at build time via -ldflags "-X ...version=v1.2.3".
var version = "dev"

type scanService interface {
	ScanBatch(context.Context, []jsowl.Target) <-chan jsowl.BatchItem
	SetRequestSink(chan<- jsowl.RequestEvent)
}

type dependencies struct {
	stdout         io.Writer
	stderr         io.Writer
	stdin          io.Reader
	defaultConfig  func() jsowl.Config
	loadConfig     func(string) (jsowl.Config, error)
	loadConfigOnto func(jsowl.Config, string) (jsowl.Config, error)
	userHomeDir    func() (string, error)
	newScanner     func(jsowl.Config) (scanService, error)
	writeJSON      func(string, *jsowl.Result) error
	writeHTML      func(string, *jsowl.Result) error
	writeText      func(string, *jsowl.Result) error
	// analyzeLocation runs the local JavaScript analyzer for --location. The
	// last argument is the optional base URL relative API references resolve
	// against; it must be absolute http(s) or empty.
	analyzeLocation func(context.Context, jsowl.Config, string, string) (*jsowl.Result, error)
	check           func(context.Context, jsowl.BrowserConfig) jsowl.BrowserCheckReport
	ensureOutput    func(string) error
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
			if len(opts.location) > 0 {
				if err := validateLocalOptions(opts); err != nil {
					return err
				}
				return runLocalScans(
					command.Context(), deps, config, opts.location,
					opts.baseURL, opts.silent,
				)
			}
			targets, err := opts.targets()
			if err != nil {
				return err
			}
			// --login can run without targets: it opens a browser for manual
			// sign-in and then scans whatever page the user navigates to.
			if len(targets) == 0 && !opts.login {
				return errors.New("at least one target is required; use -u or -l")
			}
			if err := applyBaseURL(targets, opts.baseURL); err != nil {
				return err
			}
			return runScans(
				command.Context(), deps, config, targets, opts.silent, opts.login,
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
	if deps.stdin == nil {
		deps.stdin = os.Stdin
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
	if deps.analyzeLocation == nil {
		deps.analyzeLocation = jsowl.AnalyzeLocationWithBase
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
	login bool,
) error {
	if err := deps.ensureOutput(config.Output.Directory); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	scanner, err := deps.newScanner(config)
	if err != nil {
		return err
	}
	if login {
		targets, err = startLoginBeforeScan(ctx, deps, scanner, targets)
		if err != nil {
			return err
		}
		defer closeLoginAfterScan(scanner)
	}
	// A single consumer owns stdout. The bounded queue never drops requests.
	events := make(chan jsowl.RequestEvent, 256)
	if !silent {
		scanner.SetRequestSink(events)
	}
	printerDone := startRequestPrinter(deps.stdout, events, silent)
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
			} else if status := item.Result.BrowserStatus; status.LoadTimedOut {
				// The browser stage succeeded with a partial render: surface
				// it so incomplete runtime coverage is not mistaken for a
				// clean scan.
				_, _ = fmt.Fprintf(
					deps.stderr,
					"%s: browser load timeout, kept the rendered snapshot\n",
					item.Target.URL,
				)
			}
			if notice := completenessNotice(item.Result.Completeness); notice != "" {
				// A partial scan must never pass silently as a complete one.
				_, _ = fmt.Fprintf(deps.stderr, "%s: %s\n", item.Target.URL, notice)
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
		if incompleteScan(item.Result) {
			// Defensive: the pipeline returns an error with every incomplete
			// scan; a result that somehow reports incompleteness without one
			// still counts as a failure so the exit status stays honest.
			failures++
		}
	}
	close(events)
	<-printerDone
	if failures > 0 {
		return fmt.Errorf("%d target or report task(s) failed", failures)
	}
	return nil
}

// completenessNotice renders the one-line completeness status a partial scan
// must show. A nil completeness means the producer did not record one; the
// report stays silent about it instead of inventing a verdict.
func completenessNotice(completeness *model.Completeness) string {
	if completeness == nil {
		return ""
	}
	collection, analysis := completeness.Collection, completeness.Analysis
	switch {
	case !collection.Complete && analysis.Complete:
		return "采集不完整，已获取 JS 分析完成（详见报告 completeness 段与 issues）"
	case !collection.Complete && !analysis.Complete:
		return "采集不完整，且部分已获取 JS 未完成分析"
	case collection.Complete && !analysis.Complete:
		return "JS 分析不完整，已完成的结果已保留"
	}
	return ""
}

// incompleteScan reports whether a result declares an incomplete phase.
func incompleteScan(result *jsowl.Result) bool {
	if result == nil || result.Completeness == nil {
		return false
	}
	return !result.Completeness.Collection.Complete ||
		!result.Completeness.Analysis.Complete
}

// validateLocalOptions rejects scan flags that cannot apply to a local
// analysis. A target list or login browser has no local meaning. --base-url is
// allowed, but it must be absolute: without -u a path-only prefix has no host.
func validateLocalOptions(opts *options) error {
	if len(opts.urls) > 0 || opts.list != "" {
		return errors.New("--location analyzes local files and cannot be combined with -u or -l")
	}
	if opts.login {
		return errors.New("--location is local analysis and cannot be combined with --login")
	}
	if _, err := localBaseURL(opts.baseURL); err != nil {
		return err
	}
	return nil
}

// runLocalScans analyzes each --location and writes the same report set a live
// scan produces. A location counts as one unit, so one bad path does not stop
// the others; the count is reported at the end.
func runLocalScans(
	ctx context.Context,
	deps dependencies,
	config jsowl.Config,
	locations []string,
	baseURL string,
	silent bool,
) error {
	if err := deps.ensureOutput(config.Output.Directory); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	failures := 0
	for _, location := range locations {
		location = strings.TrimSpace(location)
		if location == "" {
			continue
		}
		result, err := deps.analyzeLocation(ctx, config, location, baseURL)
		if err != nil {
			failures++
			_, _ = fmt.Fprintf(deps.stderr, "%s: %v\n", location, err)
			continue
		}
		if reportErr := writeReports(
			deps, config, jsowl.Target{URL: location}, result,
		); reportErr != nil {
			failures++
			_, _ = fmt.Fprintf(deps.stderr, "%s: %v\n", location, reportErr)
			continue
		}
		if notice := completenessNotice(result.Completeness); notice != "" {
			_, _ = fmt.Fprintf(deps.stderr, "%s: %s\n", location, notice)
		}
		if !silent {
			_, _ = fmt.Fprintf(
				deps.stdout, "[local] %s: %d endpoints, %d findings -> %s\n",
				location, len(result.Endpoints), len(result.Findings),
				result.ReportDirectory,
			)
		}
	}
	if failures > 0 {
		return fmt.Errorf("%d local analysis task(s) failed", failures)
	}
	return nil
}

// loginSessionStarter is the optional capability a scanService exposes for
// manual-login scans; *jsowl.Scanner implements it.
type loginSessionStarter interface {
	StartLoginSession(ctx context.Context, targetURL string, waitForUser func(context.Context) error) error
	LoginSessionURL() (string, error)
	CloseLoginSession()
}

// loginWaitTimeout bounds how long the user may take signing in before the
// scan continues with whatever browser state exists.
const loginWaitTimeout = 5 * time.Minute

// startLoginBeforeScan opens the headed login browser and blocks until the
// user confirms (or times out), so every subsequent collection runs with the
// authenticated session. With targets it renders the first one; without any
// it opens a blank tab and, after the user confirms, adopts whatever page
// they navigated to as the single scan target. It returns the targets the
// batch should scan.
func startLoginBeforeScan(
	ctx context.Context,
	deps dependencies,
	scanner scanService,
	targets []jsowl.Target,
) ([]jsowl.Target, error) {
	starter, ok := scanner.(loginSessionStarter)
	if !ok {
		return nil, errors.New("--login is not supported by this scanner")
	}
	initial := ""
	if len(targets) > 0 {
		initial = targets[0].URL
		_, _ = fmt.Fprintf(deps.stderr,
			"[login] opening a visible browser for %s — sign in there, then press Enter here (timeout %s)\n",
			initial, loginWaitTimeout)
	} else {
		_, _ = fmt.Fprintf(deps.stderr,
			"[login] opening a visible browser — navigate to the target and sign in, then press Enter here (timeout %s)\n",
			loginWaitTimeout)
	}
	wait := func(waitCtx context.Context) error {
		entered := make(chan struct{})
		go func() {
			_, _ = bufio.NewReader(deps.stdin).ReadString('\n')
			close(entered)
		}()
		timer := time.NewTimer(loginWaitTimeout)
		defer timer.Stop()
		select {
		case <-entered:
			return nil
		case <-timer.C:
			_, _ = fmt.Fprintln(deps.stderr,
				"[login] wait timed out; continuing with the current browser state")
			return nil
		case <-waitCtx.Done():
			return waitCtx.Err()
		}
	}
	if err := starter.StartLoginSession(ctx, initial, wait); err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		current, err := starter.LoginSessionURL()
		if err != nil {
			return nil, err
		}
		target, err := loginTarget(current)
		if err != nil {
			return nil, err
		}
		targets = []jsowl.Target{target}
		_, _ = fmt.Fprintf(deps.stderr, "[login] scanning the page you are on: %s\n", target.URL)
	}
	_, _ = fmt.Fprintf(deps.stderr,
		"[login] scanning %d target(s) inside the authenticated browser\n", len(targets))
	return targets, nil
}

// loginTarget turns the login browser's current page into a scan target,
// rejecting anything that is not an absolute http(s) URL — a blank tab, a
// chrome:// page, or an about: page — so a --login run that never navigated
// anywhere fails with a clear message instead of scanning nothing.
func loginTarget(raw string) (jsowl.Target, error) {
	parsed, err := url.Parse(raw)
	if err != nil || !parsed.IsAbs() || parsed.Host == "" ||
		(parsed.Scheme != "http" && parsed.Scheme != "https") {
		return jsowl.Target{}, fmt.Errorf(
			"login browser is on %q, which is not an http(s) page; pass -u or navigate to the target before pressing Enter",
			raw,
		)
	}
	return jsowl.Target{URL: raw}, nil
}

// closeLoginAfterScan tears the login browser down once the batch finishes.
func closeLoginAfterScan(scanner scanService) {
	if starter, ok := scanner.(loginSessionStarter); ok {
		starter.CloseLoginSession()
	}
}

// startRequestPrinter drains all queued events before signaling completion.
func startRequestPrinter(stdout io.Writer, events <-chan jsowl.RequestEvent, silent bool) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		for event := range events {
			if !silent {
				_, _ = fmt.Fprintln(stdout, formatRequestLine(event))
			}
		}
	}()
	return done
}

func formatRequestLine(event jsowl.RequestEvent) string {
	method := event.Method
	if method == "" {
		method = "GET"
	}
	status := "faile"
	if event.Success {
		status = "success"
	}
	return fmt.Sprintf("[%s] [%s] [%s] [%d] [%d]", method, event.URL, status, event.StatusCode, event.Size)
}

func writeReports(
	deps dependencies,
	config jsowl.Config,
	target jsowl.Target,
	result *jsowl.Result,
) error {
	// A scan result carries the directory assigned for its target. A local
	// analysis is not addressable by URL, so it must be used as given; only a
	// legacy result without one falls back to deriving it from the target.
	directory := result.ReportDirectory
	if directory == "" {
		var err error
		directory, err = targetReportDirectory(config.Output.Directory, target.URL)
		if err != nil {
			return err
		}
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

// targetReportDirectory derives the per-target report directory. The
// derivation lives in storage because the pipeline saves that target's
// JavaScript into the same directory; both must agree.
func targetReportDirectory(root, rawTarget string) (string, error) {
	return jsowl.TargetReportDirectory(root, rawTarget)
}
