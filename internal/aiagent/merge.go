package aiagent

import (
	"net/url"
	"strings"

	"github.com/youmulijiang/jsowl/internal/analyze"
	"github.com/youmulijiang/jsowl/internal/model"
)

// validCompleteness / validRating / validTaintKind are the closed
// vocabularies the merge layer accepts; anything else is dropped so a
// drifting model cannot inject arbitrary labels into the report.
var (
	validCompleteness = map[string]bool{"complete": true, "missing-fields": true, "uncertain": true}
	validRating       = map[string]bool{"high": true, "medium": true, "low": true, "invalid": true}
	validTaintKind    = map[string]bool{model.TaintUpstream: true, model.TaintStorage: true, model.TaintRoute: true}
)

// Apply merges a final agent report into the scan result. Every write is
// advisory: literal parameter values, recovered keys and existing evidence
// labels are never modified, taint refinements only upgrade Kind=unknown
// placeholders, and every endpoint/finding reference is re-validated
// against the result itself — hallucinated identities are dropped. The
// returned stats summarize what survived validation.
func Apply(result *model.Result, final *FinalReport) model.AIAgentStats {
	stats := model.AIAgentStats{Status: StatusOK}
	if result == nil || final == nil {
		stats.Status = StatusFailed
		stats.Reason = "没有可合并的报告"
		return stats
	}
	stats.Reviews = applyReviews(result, final.Reviews)
	stats.Taints = applyTaints(result, final.Taints)
	stats.Ratings = applyRatings(result, final.Ratings)
	result.AI = &model.AISummary{
		Overview:   strings.TrimSpace(final.Summary.Overview),
		Priorities: applyPriorities(result, final.Summary.Priorities),
		Notes:      nonEmpty(final.Summary.Notes),
		Stats:      &stats,
	}
	return stats
}

// applyReviews attaches AI verdicts to endpoint templates. Templates are
// built on demand so agent mode works even with output.request_template
// disabled — the template lives in the report only if that switch is on,
// but the review needs the home either way.
func applyReviews(result *model.Result, reviews []TemplateReview) int {
	applied := 0
	for _, review := range reviews {
		if !validCompleteness[review.Completeness] && strings.TrimSpace(review.Assessment) == "" &&
			len(review.SuggestedParams) == 0 && len(review.FuzzPlans) == 0 {
			continue // nothing to say
		}
		endpoint := matchEndpoint(result, review.Endpoint, review.Method)
		if endpoint == nil {
			continue
		}
		if endpoint.Template == nil {
			endpoint.Template = analyze.BuildTemplate(endpoint)
			if endpoint.Template == nil {
				continue
			}
		}
		ai := &model.AIReview{Completeness: review.Completeness, Assessment: strings.TrimSpace(review.Assessment)}
		for _, param := range review.SuggestedParams {
			if name := strings.TrimSpace(param); name != "" {
				ai.SuggestedParams = append(ai.SuggestedParams, name)
			}
		}
		for _, plan := range review.FuzzPlans {
			if strings.TrimSpace(plan.Field) == "" {
				continue
			}
			if len(ai.FuzzPlans) >= 10 {
				break
			}
			ai.FuzzPlans = append(ai.FuzzPlans, model.FuzzPlan{
				Field:    strings.TrimSpace(plan.Field),
				Strategy: strings.TrimSpace(plan.Strategy),
				Values:   nonEmpty(plan.Values),
				Note:     strings.TrimSpace(plan.Note),
			})
		}
		endpoint.Template.AI = ai
		applied++
	}
	return applied
}

// applyTaints refines unknown placeholder origins. The upstream claim must
// suffix-match a discovered endpoint at a path-segment boundary, so a
// guessed "/user" cannot ride on "/admin/user".
func applyTaints(result *model.Result, taints []TaintFix) int {
	applied := 0
	for _, fix := range taints {
		if !validTaintKind[fix.Kind] {
			continue
		}
		endpoint := matchEndpoint(result, fix.Endpoint, "")
		if endpoint == nil || endpoint.Spec == nil {
			continue
		}
		if fix.Kind == model.TaintUpstream && !knownEndpoint(result, fix.Upstream) {
			continue // hallucinated upstream — keep the honest unknown
		}
		for _, list := range [][]model.Param{endpoint.Spec.Query, endpoint.Spec.Body} {
			for i := range list {
				param := &list[i]
				if param.Key != fix.Param || param.Taint == nil || param.Taint.Kind != model.TaintUnknown {
					continue
				}
				param.Taint.Kind = fix.Kind
				param.Taint.Upstream = strings.TrimSpace(fix.Upstream)
				param.Taint.UpstreamField = strings.TrimSpace(fix.Field)
				applied++
			}
		}
	}
	return applied
}

// applyRatings rates sensitive findings by rule id + value identity, with a
// unique-rule fallback when the model paraphrased the value.
func applyRatings(result *model.Result, ratings []FindingRating) int {
	applied := 0
	for _, rating := range ratings {
		if !validRating[rating.Rating] {
			continue
		}
		finding := matchFinding(result, rating.RuleID, rating.Value)
		if finding == nil {
			continue
		}
		finding.AI = &model.AIAssessment{
			Rating:     rating.Rating,
			Reason:     strings.TrimSpace(rating.Reason),
			Suggestion: strings.TrimSpace(rating.Suggestion),
		}
		applied++
	}
	return applied
}

// applyPriorities keeps only entries whose target resolves to a discovered
// endpoint or finding; unresolvable targets are dropped (prose belongs in
// notes), and the kind is normalized from what actually matched.
func applyPriorities(result *model.Result, priorities []PriorityOut) []model.AIPriority {
	out := make([]model.AIPriority, 0, len(priorities))
	for _, priority := range priorities {
		target := strings.TrimSpace(priority.Target)
		if target == "" {
			continue
		}
		var kind string
		if priority.Kind != "finding" && matchEndpoint(result, target, "") != nil {
			kind = "endpoint"
		}
		if kind == "" && priority.Kind != "endpoint" && matchFinding(result, "", target) != nil {
			kind = "finding"
		}
		if kind == "" {
			continue // names nothing in this scan
		}
		out = append(out, model.AIPriority{
			Target: target,
			Kind:   kind,
			Reason: strings.TrimSpace(priority.Reason),
			Tests:  nonEmpty(priority.Tests),
		})
	}
	return out
}

// matchEndpoint finds one endpoint by raw path. An exact raw match wins;
// otherwise the reference must suffix-match at a path-segment boundary
// ("/user" may stand for "/api/user" but not "/admin/user"), optionally
// constrained by method.
func matchEndpoint(result *model.Result, reference, method string) *model.Endpoint {
	reference = strings.Trim(strings.TrimSpace(reference), "/")
	if reference == "" {
		return nil
	}
	for i := range result.Endpoints {
		endpoint := &result.Endpoints[i]
		if strings.EqualFold(endpoint.Method, method) && model.SegmentEqual(endpoint.Raw, reference) {
			return endpoint
		}
	}
	// Exact raw match without method constraint.
	for i := range result.Endpoints {
		if model.SegmentEqual(result.Endpoints[i].Raw, reference) {
			return &result.Endpoints[i]
		}
	}
	// Segment-boundary suffix fallback.
	for i := range result.Endpoints {
		if strings.EqualFold(result.Endpoints[i].Method, method) && model.SegmentSuffixMatch(result.Endpoints[i].Raw, reference) {
			return &result.Endpoints[i]
		}
	}
	for i := range result.Endpoints {
		if model.SegmentSuffixMatch(result.Endpoints[i].Raw, reference) {
			return &result.Endpoints[i]
		}
	}
	return nil
}

// matchFinding locates a finding by rule id + value. The exact pair wins;
// a rule id shared by exactly one finding is accepted even when the model
// paraphrased the value, but an ambiguous id matches nothing.
func matchFinding(result *model.Result, ruleID, value string) *model.Finding {
	ruleID = strings.TrimSpace(ruleID)
	value = strings.TrimSpace(value)
	if ruleID == "" && value == "" {
		return nil
	}
	if ruleID != "" && value != "" {
		for i := range result.Findings {
			if result.Findings[i].RuleID == ruleID && strings.TrimSpace(result.Findings[i].Value) == value {
				return &result.Findings[i]
			}
		}
	}
	if ruleID == "" {
		// Value-only: a unique exact value match is accepted.
		var found *model.Finding
		for i := range result.Findings {
			if strings.TrimSpace(result.Findings[i].Value) != value {
				continue
			}
			if found != nil {
				return nil // ambiguous
			}
			found = &result.Findings[i]
		}
		return found
	}
	var found *model.Finding
	for i := range result.Findings {
		if result.Findings[i].RuleID != ruleID {
			continue
		}
		if found != nil {
			return nil // ambiguous rule id
		}
		found = &result.Findings[i]
	}
	return found
}

// knownEndpoint reports whether an upstream guess names a discovered
// endpoint at a path-segment boundary. Absolute URLs are compared by path.
func knownEndpoint(result *model.Result, guess string) bool {
	guess = strings.Trim(strings.TrimSpace(guess), "/")
	if guess == "" {
		return false
	}
	if parsed, err := url.Parse(guess); err == nil && parsed.Host != "" {
		guess = strings.Trim(parsed.Path, "/")
		if guess == "" {
			return false
		}
	}
	if idx := strings.IndexByte(guess, '?'); idx >= 0 {
		guess = guess[:idx]
	}
	for i := range result.Endpoints {
		endpoint := &result.Endpoints[i]
		if model.SegmentEqual(endpoint.Raw, guess) || model.SegmentSuffixMatch(endpoint.Raw, guess) ||
			model.SegmentEqual(endpoint.URL, guess) || model.SegmentSuffixMatch(endpoint.URL, guess) {
			return true
		}
	}
	return false
}

// nonEmpty drops blank strings from a model-provided list.
func nonEmpty(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
