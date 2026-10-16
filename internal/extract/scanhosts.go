package extract

import (
	"net/url"
	"strings"

	"github.com/youmulijiang/jsowl/internal/model"
)

// Host roles recorded as evidence notes on scan-associated hosts, so a reader
// can tell how the scan came to touch a host.
const (
	HostRoleTarget        = "target"
	HostRoleResource      = "resource"
	HostRoleEndpoint      = "endpoint"
	HostRoleEndpointFrom  = "endpoint_source"
	HostRoleFindingSource = "finding_source"
)

// CollectScanHosts classifies the hosts the scan itself touched: the target,
// the resources it downloaded, the endpoints it found or probed, and the
// sources the findings came from.
//
// This is deliberately a separate population from hosts discovered inside
// content. Both are classified by the same rules and may overlap, but they
// answer different questions — "what does the application's code talk about"
// versus "what did this scan actually reach" — so the report can show both
// without blending them into one unexplained number.
func CollectScanHosts(
	result *model.Result,
	extractor *Extractor,
) ([]model.HostAsset, []Note) {
	if result == nil {
		return nil, nil
	}
	aggregator := NewAggregator(extractor, model.HostOriginScan)
	add := func(raw, role string) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return
		}
		host, ok := HostOfReference(raw)
		if !ok {
			return
		}
		aggregator.AddHost(host, Candidate{
			Context:       ContextURL,
			Method:        model.HostMethodURL,
			Note:          role,
			SourceURL:     raw,
			AssociatedURL: raw,
		})
	}

	add(result.Target, HostRoleTarget)
	for _, resource := range result.Resources {
		add(resource.URL, HostRoleResource)
	}
	for _, endpoint := range result.Endpoints {
		add(endpoint.URL, HostRoleEndpoint)
		add(endpoint.SourceURL, HostRoleEndpointFrom)
	}
	for _, finding := range result.Findings {
		add(finding.SourceURL, HostRoleFindingSource)
	}
	return aggregator.Assets(), aggregator.Notes()
}

// HostOfReference returns the host of one reference the scan recorded. It
// accepts the same schemes the extractor accepts; a reference without a scheme
// is only usable when it actually carries an authority, so a relative source
// path is never mistaken for a host.
func HostOfReference(raw string) (string, bool) {
	if host, ok := HostFromNetworkURL(raw); ok {
		return host, true
	}
	if strings.Contains(raw, "://") {
		// A scheme the extractor does not treat as a network URL (data:, blob:)
		// carries no host.
		return "", false
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return "", false
	}
	host := parsed.Hostname()
	return host, host != ""
}
