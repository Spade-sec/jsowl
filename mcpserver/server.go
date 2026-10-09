// Package mcpserver exposes JsOwl scans to LLM clients over the Model
// Context Protocol using the official Go SDK. Scans run in-process and their
// results stay in memory; report files are written alongside for reference.
package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	jsowl "github.com/youmulijiang/jsowl"
)

// Version is reported to MCP clients during initialization.
const Version = "0.1.0"

// Store keeps finished scans addressable by a short id so tools can query
// them without re-scanning.
type Store struct {
	mu    sync.Mutex
	next  int
	scans map[string]*jsowl.Result
	// Dir receives one sub-directory of report files per scan. Empty means a
	// per-process temporary directory.
	Dir string
	// Base is the starting scan configuration; nil means jsowl.DefaultConfig.
	// Per-scan tool inputs (mode, headers, timeout) override individual
	// fields on top of it.
	Base *jsowl.Config
}

// NewStore builds a Store whose scans start from the given configuration.
// A nil base means jsowl.DefaultConfig.
func NewStore(dir string, base *jsowl.Config) *Store {
	return &Store{scans: map[string]*jsowl.Result{}, Dir: dir, Base: base}
}

// Server builds the MCP server with all JsOwl tools registered.
func (s *Store) Server() *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{
		Name: "jsowl", Version: Version,
	}, nil)
	mcp.AddTool(server, &mcp.Tool{
		Name: "jsowl_scan",
		Description: "Scan one web target and collect exposed JavaScript, " +
			"API endpoints, and sensitive information. Returns a scan_id used " +
			"by the jsowl_endpoints / jsowl_sensitive / jsowl_parameters tools.",
	}, s.scanTool)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "jsowl_endpoints",
		Description: "List API endpoints from a finished scan, with HTTP method, evidence level, source location and code context.",
	}, s.endpointsTool)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "jsowl_sensitive",
		Description: "List sensitive-information findings (keys, tokens, credentials) from a finished scan.",
	}, s.sensitiveTool)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "jsowl_parameters",
		Description: "List request parameters observed in endpoint and resource URLs from a finished scan.",
	}, s.parametersTool)
	return server
}

// Run serves MCP over stdio until the context is cancelled.
func (s *Store) Run(ctx context.Context) error {
	return s.Server().Run(ctx, &mcp.StdioTransport{})
}

// RunHTTP serves MCP over Streamable HTTP (plus legacy SSE at /sse for older
// clients) on the given listen address, e.g. 127.0.0.1:8080. It runs until
// the context is cancelled, then drains in-flight requests.
func (s *Store) RunHTTP(ctx context.Context, listen string) error {
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", listen, err)
	}
	return s.Serve(ctx, listener)
}

// Serve serves MCP on an existing listener until the context is cancelled,
// then drains in-flight requests.
func (s *Store) Serve(ctx context.Context, listener net.Listener) error {
	server := s.Server()
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server {
		return server
	}, nil)
	mux := http.NewServeMux()
	mux.Handle("/", handler)
	mux.Handle("/sse", mcp.NewSSEHandler(func(*http.Request) *mcp.Server {
		return server
	}, nil))
	httpServer := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	serveErr := make(chan error, 1)
	go func() {
		fmt.Fprintf(os.Stderr, "jsowl-mcp: serving MCP on http://%s (streamable HTTP; SSE at /sse)\n", listener.Addr())
		serveErr <- httpServer.Serve(listener)
	}()
	select {
	case err := <-serveErr:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		// Close client sessions first so hanging event streams end;
		// Shutdown would otherwise wait on them indefinitely.
		for session := range server.Sessions() {
			session.Close()
		}
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return httpServer.Shutdown(shutdownCtx)
	}
}

type scanInput struct {
	URL            string            `json:"url" jsonschema:"target URL to scan, e.g. https://example.com"`
	Mode           string            `json:"mode,omitempty" jsonschema:"scan mode: auto (default), direct, or browser"`
	BaseURL        string            `json:"base_url,omitempty" jsonschema:"override base URL for resolving relative resources"`
	Headers        map[string]string `json:"headers,omitempty" jsonschema:"extra request headers, e.g. Authorization"`
	TimeoutSeconds int               `json:"timeout_seconds,omitempty" jsonschema:"per-target timeout in seconds (default 300)"`
}

type scanOutput struct {
	ScanID          string `json:"scan_id"`
	Target          string `json:"target"`
	Mode            string `json:"mode"`
	ReportDir       string `json:"report_dir"`
	Resources       int    `json:"resources"`
	Endpoints       int    `json:"endpoints"`
	Routes          int    `json:"routes"`
	Sensitive       int    `json:"sensitive_findings"`
	RuntimeEvidence int    `json:"runtime_endpoints"`
	FullURLEvidence int    `json:"full_url_endpoints"`
	// Browser collection outcome. Degraded means the browser phase failed
	// and the result carries direct-mode evidence only, so the caller knows
	// runtime extraction was lost.
	BrowserAttempted bool     `json:"browser_attempted"`
	BrowserUsed      bool     `json:"browser_used"`
	BrowserDegraded  bool     `json:"browser_degraded,omitempty"`
	BrowserReason    string   `json:"browser_reason,omitempty"`
	TopEndpoints     []string `json:"top_endpoints,omitempty"`
}

func (s *Store) scanTool(ctx context.Context, req *mcp.CallToolRequest, input scanInput) (*mcp.CallToolResult, scanOutput, error) {
	raw := strings.TrimSpace(input.URL)
	if raw == "" {
		return nil, scanOutput{}, fmt.Errorf("url is required")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return nil, scanOutput{}, fmt.Errorf("invalid url %q", raw)
	}

	config := jsowl.DefaultConfig()
	if s.Base != nil {
		config = *s.Base
	}
	if input.Mode != "" {
		config.Mode = jsowl.Mode(input.Mode)
	}
	config.Output.Directory = s.reportRoot()
	if s.Base == nil || input.TimeoutSeconds > 0 {
		config.Request.TargetTimeout = 5 * time.Minute
	}
	if input.TimeoutSeconds > 0 {
		config.Request.TargetTimeout = time.Duration(input.TimeoutSeconds) * time.Second
	}
	target := jsowl.Target{URL: raw, BaseURL: input.BaseURL}
	if len(input.Headers) > 0 {
		target.Headers = make(http.Header, len(input.Headers))
		for name, value := range input.Headers {
			target.Headers.Set(name, value)
		}
	}

	scanner, err := jsowl.New(config)
	if err != nil {
		return nil, scanOutput{}, fmt.Errorf("create scanner: %w", err)
	}
	result, err := scanner.Scan(ctx, target)
	if err != nil {
		return nil, scanOutput{}, fmt.Errorf("scan %s: %w", raw, err)
	}

	id := s.put(result)
	reportDir, reportErr := s.writeReports(id, result)

	output := scanOutput{
		ScanID: id, Target: result.Target, Mode: string(result.Mode),
		ReportDir: reportDir,
		Resources: len(result.Resources), Endpoints: len(result.Endpoints),
		Routes:           countRoutes(result),
		Sensitive:        countSensitive(result),
		RuntimeEvidence:  countEvidence(result, jsowl.EvidenceRuntime),
		FullURLEvidence:  countEvidence(result, jsowl.EvidenceFullURL),
		BrowserAttempted: result.BrowserStatus.Attempted,
		BrowserUsed:      result.BrowserStatus.Used,
		BrowserDegraded:  result.BrowserStatus.Degraded,
		BrowserReason:    result.BrowserStatus.Reason,
	}
	for _, endpoint := range result.Endpoints {
		if endpoint.Evidence == jsowl.EvidenceRuntime || endpoint.Evidence == jsowl.EvidenceFullURL {
			output.TopEndpoints = append(output.TopEndpoints,
				strings.TrimSpace(endpoint.Method+" "+endpoint.URL))
			if len(output.TopEndpoints) >= 10 {
				break
			}
		}
	}
	if reportErr != nil {
		output.ReportDir = ""
	}
	return nil, output, nil
}

type endpointsInput struct {
	ScanID   string `json:"scan_id" jsonschema:"scan id returned by jsowl_scan"`
	Evidence string `json:"evidence,omitempty" jsonschema:"filter: runtime, full-url, or static"`
	Method   string `json:"method,omitempty" jsonschema:"filter by HTTP method, e.g. POST"`
	Type     string `json:"type,omitempty" jsonschema:"filter: api (backend endpoints) or route (framework routes)"`
	Search   string `json:"search,omitempty" jsonschema:"substring match against URL"`
	WithCtx  bool   `json:"with_context,omitempty" jsonschema:"include surrounding source code lines"`
	Limit    int    `json:"limit,omitempty" jsonschema:"max rows to return (default 50)"`
}

type endpointRow struct {
	URL        string             `json:"url"`
	Method     string             `json:"method,omitempty"`
	Evidence   string             `json:"evidence,omitempty"`
	Type       string             `json:"type,omitempty"`
	Probe      string             `json:"probe,omitempty"`
	Source     string             `json:"source,omitempty"`
	Line       int                `json:"line,omitempty"`
	Status     int                `json:"status_code,omitempty"`
	BodyParams []string           `json:"body_params,omitempty"`
	Spec       *jsowl.RequestSpec `json:"spec,omitempty"`
	Context    []string           `json:"context,omitempty"`
}

func (s *Store) endpointsTool(ctx context.Context, req *mcp.CallToolRequest, input endpointsInput) (*mcp.CallToolResult, []endpointRow, error) {
	result, err := s.get(input.ScanID)
	if err != nil {
		return nil, nil, err
	}
	limit := input.Limit
	if limit <= 0 {
		limit = 50
	}
	rows := make([]endpointRow, 0, limit)
	for _, endpoint := range result.Endpoints {
		if input.Evidence != "" && endpoint.Evidence != input.Evidence {
			continue
		}
		if input.Method != "" && !strings.EqualFold(endpoint.Method, input.Method) {
			continue
		}
		if input.Type != "" && endpoint.Type != input.Type {
			continue
		}
		if input.Search != "" && !strings.Contains(strings.ToLower(endpoint.URL), strings.ToLower(input.Search)) {
			continue
		}
		row := endpointRow{
			URL: endpoint.URL, Method: endpoint.Method,
			Evidence: evidenceOr(endpoint.Evidence),
			Type:     endpoint.Type, Probe: endpoint.Probe,
			Source: endpoint.SourceURL, Line: endpoint.Line,
			Status: endpoint.StatusCode, BodyParams: endpoint.BodyParams,
			Spec: endpoint.Spec,
		}
		if input.WithCtx {
			for _, line := range endpoint.ContextLines {
				row.Context = append(row.Context,
					fmt.Sprintf("%4d | %s", line.LineNumber, line.Content))
			}
		}
		rows = append(rows, row)
		if len(rows) >= limit {
			break
		}
	}
	return nil, rows, nil
}

type sensitiveInput struct {
	ScanID      string `json:"scan_id" jsonschema:"scan id returned by jsowl_scan"`
	MinSeverity string `json:"min_severity,omitempty" jsonschema:"minimum severity: info, low, medium, high, critical"`
	Search      string `json:"search,omitempty" jsonschema:"substring match against rule name or value"`
	Limit       int    `json:"limit,omitempty" jsonschema:"max rows to return (default 50)"`
}

type sensitiveRow struct {
	Severity string `json:"severity"`
	Rule     string `json:"rule"`
	Value    string `json:"value"`
	Source   string `json:"source"`
	Line     int    `json:"line,omitempty"`
}

func (s *Store) sensitiveTool(ctx context.Context, req *mcp.CallToolRequest, input sensitiveInput) (*mcp.CallToolResult, []sensitiveRow, error) {
	result, err := s.get(input.ScanID)
	if err != nil {
		return nil, nil, err
	}
	minimum := severityRank(input.MinSeverity)
	limit := input.Limit
	if limit <= 0 {
		limit = 50
	}
	rows := make([]sensitiveRow, 0, limit)
	for _, finding := range result.Findings {
		if finding.Category != jsowl.RuleCategorySensitive {
			continue
		}
		if severityRank(string(finding.Severity)) < minimum {
			continue
		}
		if input.Search != "" {
			hay := strings.ToLower(finding.RuleName + " " + finding.RuleID + " " + finding.Value)
			if !strings.Contains(hay, strings.ToLower(input.Search)) {
				continue
			}
		}
		rows = append(rows, sensitiveRow{
			Severity: string(finding.Severity), Rule: finding.RuleName,
			Value: finding.Value, Source: finding.SourceURL, Line: finding.Line,
		})
		if len(rows) >= limit {
			break
		}
	}
	return nil, rows, nil
}

type parameterRowOut struct {
	Name      string   `json:"name"`
	Example   string   `json:"example,omitempty"`
	FirstSeen string   `json:"first_seen,omitempty"`
	// Scenarios lists how the name was recovered: object_property,
	// destructuring, nested_destructuring, function_param, variable,
	// api_request, url_query, config_object, route_param.
	Scenarios []string `json:"scenarios,omitempty"`
	// Vendor marks a name recovered from a third-party library bundle.
	Vendor bool `json:"vendor,omitempty"`
}

func (s *Store) parametersTool(ctx context.Context, req *mcp.CallToolRequest, input struct {
	ScanID string `json:"scan_id" jsonschema:"scan id returned by jsowl_scan"`
	Limit  int    `json:"limit,omitempty" jsonschema:"max rows to return (default 100)"`
}) (*mcp.CallToolResult, []parameterRowOut, error) {
	result, err := s.get(input.ScanID)
	if err != nil {
		return nil, nil, err
	}
	limit := input.Limit
	if limit <= 0 {
		limit = 100
	}
	type entryStruct struct {
		value     string
		source    string
		scenarios []string
		vendor    bool
	}
	params := map[string]entryStruct{}
	collect := func(raw string) {
		parsed, parseErr := url.Parse(raw)
		if parseErr != nil {
			return
		}
		for key, values := range parsed.Query() {
			if _, exists := params[key]; exists {
				continue
			}
			value := ""
			if len(values) > 0 {
				value = values[0]
			}
			params[key] = entryStruct{value: value, source: raw}
		}
	}
	for _, endpoint := range result.Endpoints {
		collect(endpoint.URL)
	}
	for _, resource := range result.Resources {
		collect(resource.URL)
	}
	// Merge the code-shape parameter inventory: names recovered from object
	// properties, destructuring, function signatures and friends, each with
	// its extraction scenario. Names found only in URLs carry no scenarios;
	// callers can treat a missing field as url_query.
	for _, hit := range result.Params {
		if hit.Name == "" {
			continue
		}
		entry, exists := params[hit.Name]
		if !exists {
			entry = entryStruct{}
		}
		duplicate := false
		for _, scenario := range entry.scenarios {
			if scenario == hit.Scenario {
				duplicate = true
				break
			}
		}
		if !duplicate {
			entry.scenarios = append(entry.scenarios, hit.Scenario)
		}
		if hit.Vendor {
			entry.vendor = true
		}
		if entry.source == "" && hit.SourceURL != "" {
			entry.source = hit.SourceURL
		}
		if entry.value == "" && hit.Value != "" {
			entry.value = hit.Value
		}
		params[hit.Name] = entry
	}
	names := make([]string, 0, len(params))
	for name := range params {
		names = append(names, name)
	}
	sort.Strings(names)
	if len(names) > limit {
		names = names[:limit]
	}
	rows := make([]parameterRowOut, 0, len(names))
	for _, name := range names {
		rows = append(rows, parameterRowOut{
			Name: name, Example: params[name].value, FirstSeen: params[name].source,
			Scenarios: params[name].scenarios, Vendor: params[name].vendor,
		})
	}
	return nil, rows, nil
}

func (s *Store) put(result *jsowl.Result) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.next++
	id := fmt.Sprintf("scan-%d", s.next)
	s.scans[id] = result
	return id
}

func (s *Store) get(id string) (*jsowl.Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	result, ok := s.scans[id]
	if !ok {
		return nil, fmt.Errorf("unknown scan_id %q (scans expire when this server restarts)", id)
	}
	return result, nil
}

// reportRoot returns the directory that holds per-scan report sub-directories.
func (s *Store) reportRoot() string {
	if s.Dir != "" {
		return s.Dir
	}
	dir, err := os.MkdirTemp("", "jsowl-mcp-*")
	if err != nil {
		return "."
	}
	return dir
}

func (s *Store) writeReports(id string, result *jsowl.Result) (string, error) {
	directory := filepath.Join(s.reportRoot(), id)
	if err := os.MkdirAll(directory, 0o750); err != nil {
		return "", err
	}
	if err := jsowl.WriteJSONReport(filepath.Join(directory, "report.json"), result); err != nil {
		return directory, err
	}
	if err := jsowl.WriteTextReports(directory, result); err != nil {
		return directory, err
	}
	return directory, nil
}

func countRoutes(result *jsowl.Result) int {
	count := 0
	for _, endpoint := range result.Endpoints {
		if endpoint.Type == "route" {
			count++
		}
	}
	return count
}

func countSensitive(result *jsowl.Result) int {
	count := 0
	for _, finding := range result.Findings {
		if finding.Category == jsowl.RuleCategorySensitive {
			count++
		}
	}
	return count
}

func countEvidence(result *jsowl.Result, evidence string) int {
	count := 0
	for _, endpoint := range result.Endpoints {
		if endpoint.Evidence == evidence {
			count++
		}
	}
	return count
}

func evidenceOr(evidence string) string {
	if evidence == "" {
		return jsowl.EvidenceStatic
	}
	return evidence
}

func severityRank(severity string) int {
	switch jsowl.Severity(strings.ToLower(severity)) {
	case jsowl.SeverityCritical:
		return 4
	case jsowl.SeverityHigh:
		return 3
	case jsowl.SeverityMedium:
		return 2
	case jsowl.SeverityLow:
		return 1
	default:
		return 0
	}
}
