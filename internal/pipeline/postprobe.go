package pipeline

import (
	"bytes"
	"context"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"

	"github.com/youmulijiang/jsowl/internal/analyze"
	"github.com/youmulijiang/jsowl/internal/collect"
	"github.com/youmulijiang/jsowl/internal/discover"
	"github.com/youmulijiang/jsowl/internal/model"
	"github.com/youmulijiang/jsowl/internal/scope"
)

type postProbe struct {
	endpointIndex int
	target        *url.URL
	body          []byte
	contentType   string
}

// probePostEndpoints sends one POST probe to every authorized endpoint the
// analysis recovered as a POST call. A GET cannot exercise a write endpoint,
// so without this probe the response status, JSON field names and sensitive
// values of such an interface are never observed.
//
// Probes share the collection concurrency bound; responses are merged on the
// coordinator after every probe finishes, so the run state is never mutated
// concurrently. skipURLs lists resources an earlier scan phase already probed,
// which keeps a combined direct+browser scan from writing twice.
func (p *Pipeline) probePostEndpoints(
	ctx context.Context,
	state *runState,
	headers http.Header,
	skipURLs []string,
) {
	if !p.options.Config.Scope.ProbePost {
		return
	}
	poster, ok := p.options.Getter.(collect.Poster)
	if !ok {
		return
	}
	skip := make(map[string]struct{}, len(skipURLs))
	for _, raw := range skipURLs {
		skip[raw] = struct{}{}
	}
	probes := make([]postProbe, 0)
	for index := range state.result.Endpoints {
		endpoint := &state.result.Endpoints[index]
		if _, seen := skip[endpoint.URL]; seen {
			continue
		}
		body, contentType, eligible := postProbeRequest(endpoint)
		if !eligible {
			continue
		}
		target, parseErr := url.Parse(endpoint.URL)
		if parseErr != nil {
			continue
		}
		probes = append(probes, postProbe{
			endpointIndex: index, target: target,
			body: body, contentType: contentType,
		})
	}
	if len(probes) == 0 {
		return
	}

	responses := make([]collect.Response, len(probes))
	errs := make([]error, len(probes))
	completed := make([]bool, len(probes))
	workers := min(p.options.Config.Concurrency.ResourcesPerTarget, len(probes))
	if workers <= 0 {
		workers = 1
	}
	next := make(chan int)
	var group sync.WaitGroup
	for range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			for position := range next {
				probeHeaders := collect.HeadersForURL(
					headers, state.root, probes[position].target,
				)
				if probeHeaders == nil {
					probeHeaders = make(http.Header)
				}
				probeHeaders.Set("Content-Type", probes[position].contentType)
				responses[position], errs[position] = poster.Post(
					ctx, probes[position].target, probeHeaders, probes[position].body,
				)
				completed[position] = true
			}
		}()
	}
dispatch:
	for position := range probes {
		select {
		case <-ctx.Done():
			break dispatch
		case next <- position:
		}
	}
	close(next)
	group.Wait()

	for position, probe := range probes {
		if !completed[position] {
			continue
		}
		if errs[position] != nil && ctx.Err() != nil {
			// The scan was cancelled while this probe was in flight; the
			// context error is not a finding about the endpoint.
			continue
		}
		p.applyPostProbe(state, probe.endpointIndex, responses[position], errs[position])
	}
}

// postProbeRequest derives the probe body and Content-Type for one endpoint.
// The body carries the shape the call site expects but none of its values:
// JSON gets {}, form encodings get the recovered keys with empty values, and
// multipart gets a boundary-correct form. Every other explicit type gets an
// empty body; an endpoint whose payload format is unknown is not probed,
// unless a recovered body implies the JSON serialization most clients use.
func postProbeRequest(endpoint *model.Endpoint) (body []byte, contentType string, ok bool) {
	if endpoint == nil || endpoint.Type != "api" || !endpoint.Authorized {
		return nil, "", false
	}
	if !strings.EqualFold(endpoint.Method, http.MethodPost) {
		return nil, "", false
	}
	spec := endpoint.Spec
	if spec == nil {
		return nil, "", false
	}
	rawContentType := strings.TrimSpace(spec.ContentType)
	if rawContentType == "" {
		// axios and most JSON clients serialize an object body without an
		// explicit header. A recovered body proves there is a payload to
		// probe; the format is JSON by client convention.
		if len(spec.Body) == 0 {
			return nil, "", false
		}
		return []byte("{}"), "application/json", true
	}
	mediaType := rawContentType
	if parsed, _, err := mime.ParseMediaType(rawContentType); err == nil {
		mediaType = parsed
	}
	lower := strings.ToLower(mediaType)
	switch {
	case strings.Contains(lower, "json"):
		return []byte("{}"), "application/json", true
	case strings.Contains(lower, "x-www-form-urlencoded"):
		return formProbeBody(spec.Body), rawContentType, true
	case strings.Contains(lower, "multipart/form-data"):
		return multipartProbeBody(spec.Body)
	default:
		return nil, rawContentType, true
	}
}

// formProbeBody renders the recovered body keys as key= pairs. Values are left
// empty: the probe exercises the endpoint's request shape without inventing
// application data.
func formProbeBody(params []model.Param) []byte {
	keys := probeKeys(params)
	if len(keys) == 0 {
		return nil
	}
	pairs := make([]string, len(keys))
	for index, key := range keys {
		pairs[index] = url.QueryEscape(key) + "="
	}
	return []byte(strings.Join(pairs, "&"))
}

// multipartProbeBody builds a form with one empty part per recovered field and
// returns the generated Content-Type, whose boundary matches the body. With no
// recovered fields the body is only the closing boundary, which is still a
// well-formed multipart payload.
func multipartProbeBody(params []model.Param) ([]byte, string, bool) {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for _, key := range probeKeys(params) {
		if err := writer.WriteField(key, ""); err != nil {
			return nil, "", false
		}
	}
	if err := writer.Close(); err != nil {
		return nil, "", false
	}
	return body.Bytes(), writer.FormDataContentType(), true
}

// probeKeys returns the unique non-empty body field names in source order.
func probeKeys(params []model.Param) []string {
	keys := make([]string, 0, len(params))
	seen := make(map[string]struct{}, len(params))
	for _, param := range params {
		if param.Key == "" {
			continue
		}
		if _, duplicate := seen[param.Key]; duplicate {
			continue
		}
		seen[param.Key] = struct{}{}
		keys = append(keys, param.Key)
	}
	return keys
}

// applyPostProbe folds one POST probe response into the endpoint: status,
// response field names, a streaming probe event, and the sensitive-rule pass.
// The last point is the reason the stage exists: a write endpoint's response
// body is otherwise never seen by the extractor.
func (p *Pipeline) applyPostProbe(
	state *runState,
	index int,
	response collect.Response,
	err error,
) {
	endpoint := &state.result.Endpoints[index]
	if err != nil {
		state.result.Issues = append(state.result.Issues, model.Issue{
			Code: "post_probe_failed", Stage: "collect", URL: endpoint.URL,
			Message: err.Error(), Retryable: true,
		})
		return
	}
	endpoint.StatusCode = response.StatusCode
	contentType := response.Header.Get("Content-Type")
	if strings.Contains(strings.ToLower(contentType), "json") {
		for _, name := range discover.JSONFieldNames(response.Body) {
			if !slices.Contains(endpoint.ResponseParams, name) {
				endpoint.ResponseParams = append(endpoint.ResponseParams, name)
			}
		}
	}
	state.emitProbe(model.ProbeEvent{
		Target:     scope.Canonical(state.root),
		URL:        endpoint.URL,
		Method:     http.MethodPost,
		StatusCode: response.StatusCode,
		Evidence:   endpoint.Evidence,
	})
	if !isTextualContentType(contentType) {
		return
	}
	sourceURL := response.URL
	if sourceURL == "" {
		sourceURL = endpoint.URL
	}
	findings, _ := p.options.Analyzer.Analyze(analyze.ResourceRef{
		URL:  sourceURL,
		Type: model.ResourceTypeAPI,
	}, response.Body)
	state.mergeFindings(findings)
}

// mergeFindings appends findings, deduplicating by rule, source and value so
// the same secret observed by a GET and a POST probe is reported once.
func (state *runState) mergeFindings(findings []model.Finding) {
	for _, finding := range findings {
		key := finding.RuleID + "\x00" + finding.SourceURL + "\x00" + finding.Value
		if _, duplicate := state.findingSeen[key]; duplicate {
			continue
		}
		state.findingSeen[key] = struct{}{}
		state.result.Findings = append(state.result.Findings, finding)
	}
}
