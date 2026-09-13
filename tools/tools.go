// Package tools exposes JsOwl as a reusable library with a stable, typed
// tool interface. Every tool takes a JSON-serialisable input struct and
// returns a JSON-serialisable output struct, so hosts in any language can
// drive JsOwl through Dispatch with newline-delimited JSON, or import the
// package and call the typed functions directly.
//
// Available tools:
//
//	scan        run a scan and keep the result in memory (returns scan_id)
//	endpoints   list API endpoints with filters (evidence, method, type, search)
//	sensitive   list sensitive-information findings with severity filter
//	parameters  list request parameters aggregated from discovered URLs
//	routes      list framework routes and optional probe outcomes
//	scans       list finished scans held by this process
package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	jsowl "github.com/youmulijiang/jsowl"
	"github.com/youmulijiang/jsowl/internal/model"
)

// Request is the envelope accepted by Dispatch.
type Request struct {
	Tool      string          `json:"tool"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

// Response is the envelope returned by Dispatch.
type Response struct {
	OK     bool            `json:"ok"`
	Error  string          `json:"error,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
}

// Store keeps finished scans addressable by id for the query tools.
type Store struct {
	mu    sync.Mutex
	next  int
	scans map[string]*model.Result
	Dir   string // report output root; empty uses a per-process temp directory
}

// NewStore creates a tool store; dir receives per-scan report files.
func NewStore(dir string) *Store {
	return &Store{scans: map[string]*model.Result{}, Dir: dir}
}

// ---- jsowl_scan ----

type ScanInput struct {
	URL            string            `json:"url"`
	Mode           string            `json:"mode,omitempty"`
	BaseURL        string            `json:"base_url,omitempty"`
	Headers        map[string]string `json:"headers,omitempty"`
	TimeoutSeconds int               `json:"timeout_seconds,omitempty"`
	WriteReports   bool              `json:"write_reports,omitempty"`
}

type ScanOutput struct {
	ScanID          string   `json:"scan_id"`
	Target          string   `json:"target"`
	Mode            string   `json:"mode"`
	ReportDir       string   `json:"report_dir,omitempty"`
	Resources       int      `json:"resources"`
	Endpoints       int      `json:"endpoints"`
	Routes          int      `json:"routes"`
	Sensitive       int      `json:"sensitive_findings"`
	RuntimeEvidence int      `json:"runtime_endpoints"`
	FullURLEvidence int      `json:"full_url_endpoints"`
	TopEndpoints    []string `json:"top_endpoints,omitempty"`
}

// Scan runs one target scan and registers the result.
func (s *Store) Scan(ctx context.Context, input ScanInput) (ScanOutput, error) {
	raw := strings.TrimSpace(input.URL)
	if raw == "" {
		return ScanOutput{}, fmt.Errorf("url is required")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return ScanOutput{}, fmt.Errorf("invalid url %q", raw)
	}
	if input.Mode == "" {
		input.Mode = string(model.ModeAuto)
	}

	config := jsowl.DefaultConfig()
	config.Mode = model.Mode(input.Mode)
	config.Request.TargetTimeout = 5 * time.Minute
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
		return ScanOutput{}, fmt.Errorf("create scanner: %w", err)
	}
	result, err := scanner.Scan(ctx, target)
	if err != nil {
		return ScanOutput{}, fmt.Errorf("scan %s: %w", raw, err)
	}

	id := s.put(result)
	output := ScanOutput{
		ScanID: id, Target: result.Target, Mode: string(result.Mode),
		Resources: len(result.Resources), Endpoints: len(result.Endpoints),
		Routes:   countTyped(result, "route"),
		Sensitive: countSensitive(result),
		RuntimeEvidence: countEvidence(result, model.EvidenceRuntime),
		FullURLEvidence: countEvidence(result, model.EvidenceFullURL),
	}
	for _, endpoint := range result.Endpoints {
		if endpoint.Evidence == model.EvidenceRuntime ||
			endpoint.Evidence == model.EvidenceFullURL {
			output.TopEndpoints = append(output.TopEndpoints,
				strings.TrimSpace(endpoint.Method+" "+endpoint.URL))
			if len(output.TopEndpoints) >= 10 {
				break
			}
		}
	}
	if input.WriteReports {
		dir, reportErr := s.writeReports(id, result)
		output.ReportDir = dir
		if reportErr != nil {
			return output, fmt.Errorf("write reports: %w", reportErr)
		}
	}
	return output, nil
}

// ---- jsowl_endpoints ----

type EndpointsInput struct {
	ScanID   string `json:"scan_id"`
	Evidence string `json:"evidence,omitempty"`
	Method   string `json:"method,omitempty"`
	Type     string `json:"type,omitempty"`
	Search   string `json:"search,omitempty"`
	WithCtx  bool   `json:"with_context,omitempty"`
	Limit    int    `json:"limit,omitempty"`
}

type EndpointRow struct {
	URL        string   `json:"url"`
	Raw        string   `json:"raw,omitempty"`
	Method     string   `json:"method,omitempty"`
	Evidence   string   `json:"evidence,omitempty"`
	Type       string   `json:"type,omitempty"`
	Probe      string   `json:"probe,omitempty"`
	Source     string   `json:"source,omitempty"`
	Line       int      `json:"line,omitempty"`
	Status     int      `json:"status_code,omitempty"`
	BodyParams []string `json:"body_params,omitempty"`
	Context    []string `json:"context,omitempty"`
}

// Endpoints lists endpoints of one scan after applying filters.
func (s *Store) Endpoints(input EndpointsInput) ([]EndpointRow, error) {
	result, err := s.get(input.ScanID)
	if err != nil {
		return nil, err
	}
	limit := input.Limit
	if limit <= 0 {
		limit = 50
	}
	rows := make([]EndpointRow, 0, limit)
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
		if input.Search != "" && !strings.Contains(
			strings.ToLower(endpoint.URL), strings.ToLower(input.Search),
		) {
			continue
		}
		row := EndpointRow{
			URL: endpoint.URL, Raw: endpoint.Raw,
			Method: endpoint.Method, Evidence: evidenceOr(endpoint.Evidence),
			Type: endpoint.Type, Probe: endpoint.Probe,
			Source: endpoint.SourceURL, Line: endpoint.Line,
			Status: endpoint.StatusCode, BodyParams: endpoint.BodyParams,
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
	return rows, nil
}

// ---- jsowl_sensitive ----

type SensitiveInput struct {
	ScanID      string `json:"scan_id"`
	MinSeverity string `json:"min_severity,omitempty"`
	Search      string `json:"search,omitempty"`
	Limit       int    `json:"limit,omitempty"`
}

type SensitiveRow struct {
	Severity string `json:"severity"`
	Rule     string `json:"rule"`
	Value    string `json:"value"`
	Source   string `json:"source"`
	Line     int    `json:"line,omitempty"`
}

// Sensitive lists sensitive findings of one scan after applying filters.
func (s *Store) Sensitive(input SensitiveInput) ([]SensitiveRow, error) {
	result, err := s.get(input.ScanID)
	if err != nil {
		return nil, err
	}
	minimum := severityRank(input.MinSeverity)
	limit := input.Limit
	if limit <= 0 {
		limit = 50
	}
	rows := make([]SensitiveRow, 0, limit)
	for _, finding := range result.Findings {
		if finding.Category != model.RuleCategorySensitive {
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
		rows = append(rows, SensitiveRow{
			Severity: string(finding.Severity), Rule: finding.RuleName,
			Value: finding.Value, Source: finding.SourceURL, Line: finding.Line,
		})
		if len(rows) >= limit {
			break
		}
	}
	return rows, nil
}

// ---- jsowl_parameters ----

type ParameterRow struct {
	Name      string `json:"name"`
	Example   string `json:"example,omitempty"`
	FirstSeen string `json:"first_seen,omitempty"`
	Body      bool   `json:"body,omitempty"`
}

type ParametersInput struct {
	ScanID string `json:"scan_id"`
	Limit  int    `json:"limit,omitempty"`
}

// Parameters aggregates request parameters from one scan.
func (s *Store) Parameters(input ParametersInput) ([]ParameterRow, error) {
	result, err := s.get(input.ScanID)
	if err != nil {
		return nil, err
	}
	limit := input.Limit
	if limit <= 0 {
		limit = 100
	}
	type entry struct {
		value  string
		source string
		body   bool
	}
	params := map[string]entry{}
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
			params[key] = entry{value: value, source: raw}
		}
	}
	for _, endpoint := range result.Endpoints {
		collect(endpoint.URL)
		for _, name := range endpoint.BodyParams {
			if _, exists := params[name]; !exists {
				params[name] = entry{value: "(body)", source: endpoint.URL, body: true}
			}
		}
	}
	for _, resource := range result.Resources {
		collect(resource.URL)
	}
	names := make([]string, 0, len(params))
	for name := range params {
		names = append(names, name)
	}
	sort.Strings(names)
	if len(names) > limit {
		names = names[:limit]
	}
	rows := make([]ParameterRow, 0, len(names))
	for _, name := range names {
		rows = append(rows, ParameterRow{
			Name: name, Example: params[name].value,
			FirstSeen: params[name].source, Body: params[name].body,
		})
	}
	return rows, nil
}

// ---- jsowl_routes ----

type RouteRow struct {
	Path      string `json:"path"`
	Source    string `json:"source,omitempty"`
	Extractor string `json:"extractor,omitempty"`
	Probe     string `json:"probe,omitempty"`
	Status    int    `json:"status_code,omitempty"`
}

type RoutesInput struct {
	ScanID string `json:"scan_id"`
	Limit  int    `json:"limit,omitempty"`
}

// Routes lists framework routes of one scan.
func (s *Store) Routes(input RoutesInput) ([]RouteRow, error) {
	result, err := s.get(input.ScanID)
	if err != nil {
		return nil, err
	}
	limit := input.Limit
	if limit <= 0 {
		limit = 100
	}
	rows := make([]RouteRow, 0, limit)
	for _, endpoint := range result.Endpoints {
		if endpoint.Type != "route" {
			continue
		}
		rows = append(rows, RouteRow{
			Path: endpoint.URL, Source: endpoint.SourceURL,
			Extractor: endpoint.Source, Probe: endpoint.Probe,
			Status: endpoint.StatusCode,
		})
		if len(rows) >= limit {
			break
		}
	}
	return rows, nil
}

// ---- jsowl_scans ----

type ScanSummary struct {
	ScanID    string `json:"scan_id"`
	Target    string `json:"target"`
	Mode      string `json:"mode"`
	Endpoints int    `json:"endpoints"`
	Sensitive int    `json:"sensitive_findings"`
}

// Scans lists the scans held by this store.
func (s *Store) Scans() []ScanSummary {
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := make([]string, 0, len(s.scans))
	for id := range s.scans {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	summary := make([]ScanSummary, 0, len(ids))
	for _, id := range ids {
		result := s.scans[id]
		summary = append(summary, ScanSummary{
			ScanID: id, Target: result.Target, Mode: string(result.Mode),
			Endpoints: len(result.Endpoints), Sensitive: countSensitive(result),
		})
	}
	return summary
}

// ---- JSON dispatch ----

// Dispatch decodes one JSON request envelope, invokes the named tool and
// encodes the response. Unknown tools and tool errors come back as
// Response{OK:false, Error:...} with a nil error so hosts only need to
// handle transport failures.
func (s *Store) Dispatch(ctx context.Context, data []byte) []byte {
	var request Request
	var response Response
	if err := json.Unmarshal(data, &request); err != nil {
		return marshalResponse(Response{Error: "decode request: " + err.Error()})
	}
	switch request.Tool {
	case "scan":
		var input ScanInput
		if err := strictUnmarshal(request.Arguments, &input); err != nil {
			response.Error = err.Error()
			break
		}
		output, err := s.Scan(ctx, input)
		response.envelope(jsonMarshal(output, err))
	case "endpoints":
		var input EndpointsInput
		response.envelope(invokeSimple(request.Arguments, &input, s.Endpoints))
	case "sensitive":
		var input SensitiveInput
		response.envelope(invokeSimple(request.Arguments, &input, s.Sensitive))
	case "parameters":
		var input ParametersInput
		response.envelope(invokeSimple(request.Arguments, &input, s.Parameters))
	case "routes":
		var input RoutesInput
		response.envelope(invokeSimple(request.Arguments, &input, s.Routes))
	case "scans":
		scans := s.Scans()
		scansJSON, err := json.Marshal(scans)
		if err != nil {
			response.Error = err.Error()
			break
		}
		response.OK = true
		response.Result = scansJSON
	default:
		response = Response{Error: fmt.Sprintf("unknown tool %q", request.Tool)}
	}
	return marshalResponse(response)
}

func (response *Response) envelope(data json.RawMessage, err error) {
	if err != nil {
		response.Error = err.Error()
		return
	}
	response.OK = true
	response.Result = data
}

func invokeSimple[In any, Out any](
	raw json.RawMessage,
	input *In,
	run func(In) (Out, error),
) (json.RawMessage, error) {
	if err := strictUnmarshal(raw, input); err != nil {
		return nil, err
	}
	return jsonMarshal(run(*input))
}

func strictUnmarshal(raw json.RawMessage, target any) error {
	if len(raw) == 0 {
		return nil
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode arguments: %w", err)
	}
	return nil
}

func jsonMarshal(value any, err error) (json.RawMessage, error) {
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func marshalResponse(response Response) []byte {
	data, err := json.Marshal(response)
	if err != nil {
		return []byte(`{"ok":false,"error":"encode response"}`)
	}
	return data
}

func (s *Store) put(result *model.Result) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.next++
	id := fmt.Sprintf("scan-%d", s.next)
	s.scans[id] = result
	return id
}

func (s *Store) get(id string) (*model.Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	result, ok := s.scans[id]
	if !ok {
		return nil, fmt.Errorf("unknown scan_id %q (scans expire when the host restarts)", id)
	}
	return result, nil
}

func (s *Store) writeReports(id string, result *model.Result) (string, error) {
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

func (s *Store) reportRoot() string {
	if s.Dir != "" {
		return s.Dir
	}
	dir, err := os.MkdirTemp("", "jsowl-tools-*")
	if err != nil {
		return "."
	}
	return dir
}

func countSensitive(result *model.Result) int {
	count := 0
	for _, finding := range result.Findings {
		if finding.Category == model.RuleCategorySensitive {
			count++
		}
	}
	return count
}

func countTyped(result *model.Result, endpointType string) int {
	count := 0
	for _, endpoint := range result.Endpoints {
		if endpoint.Type == endpointType {
			count++
		}
	}
	return count
}

func countEvidence(result *model.Result, evidence string) int {
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
		return model.EvidenceStatic
	}
	return evidence
}

func severityRank(severity string) int {
	switch model.Severity(strings.ToLower(severity)) {
	case model.SeverityCritical:
		return 4
	case model.SeverityHigh:
		return 3
	case model.SeverityMedium:
		return 2
	case model.SeverityLow:
		return 1
	default:
		return 0
	}
}
