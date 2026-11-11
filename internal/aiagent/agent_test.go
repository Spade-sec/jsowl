package aiagent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/youmulijiang/jsowl/internal/aiclient"
	"github.com/youmulijiang/jsowl/internal/model"
)

// fakeChat scripts the model's replies; each call pops the next one.
type fakeChat struct {
	replies []string
	errs    []error // optional per-call error, nil entries pass through
	calls   int
	systems []string
	users   []string
}

func (f *fakeChat) ChatWithOptions(_ context.Context, system, user string, _ aiclient.ChatOptions) (string, error) {
	f.calls++
	f.systems = append(f.systems, system)
	f.users = append(f.users, user)
	if f.calls-1 < len(f.errs) && f.errs[f.calls-1] != nil {
		return "", f.errs[f.calls-1]
	}
	return f.replies[f.calls-1], nil
}

func agentOver(t *testing.T, result *model.Result, client chatClient, opts Options) (*Agent, *Outcome) {
	t.Helper()
	agent := New(client, NewEvidence(result), opts)
	outcome := agent.Run(context.Background(), result)
	return agent, outcome
}

func TestAgentLoopToolThenFinal(t *testing.T) {
	result := &model.Result{
		ReportDirectory: t.TempDir(),
		Target:          "https://example.com",
		Endpoints:       []model.Endpoint{{Raw: "/api/login", Method: "POST", Type: "api"}},
		Findings:        []model.Finding{{RuleID: "ak", Value: "LTAI1", Severity: model.SeverityHigh}},
	}
	client := &fakeChat{replies: []string{
		`{"thought":"查一下接口","calls":[{"tool":"list_endpoints","args":{}}],"final":null}`,
		`{"thought":"够了","calls":[],"final":{"reviews":[{"endpoint":"/api/login","completeness":"complete","assessment":"参数完整"}],"summary":{"overview":"正常"}}}`,
	}}
	_, outcome := agentOver(t, result, client, Options{MaxSteps: 5, MaxRequests: 5})
	if outcome.Status != StatusOK || outcome.Final == nil {
		t.Fatalf("outcome = %+v", outcome)
	}
	if outcome.Steps != 2 || outcome.Requests != 2 {
		t.Fatalf("steps/requests = %d/%d", outcome.Steps, outcome.Requests)
	}
	// The briefing must reach the model and the tool result must come back
	// in the second turn's user message.
	if !strings.Contains(client.users[0], "list_endpoints") || !strings.Contains(client.users[0], "接口:") {
		t.Fatalf("briefing missing: %.200q", client.users[0])
	}
	if !strings.Contains(client.users[1], "[工具结果 list_endpoints]") {
		t.Fatalf("tool result not replayed: %.400q", client.users[1])
	}
	if !strings.Contains(client.users[1], "list_endpoints") {
		t.Fatalf("model plan not replayed: %.400q", client.users[1])
	}
	// Temperature must be pinned to 0.
	if client.calls != 2 {
		t.Fatalf("calls = %d", client.calls)
	}
}

func TestAgentWritesTranscript(t *testing.T) {
	result := &model.Result{
		ReportDirectory: t.TempDir(),
		Target:          "https://example.com",
		Endpoints:       []model.Endpoint{{Raw: "/api/x", Type: "api"}},
	}
	client := &fakeChat{replies: []string{
		`{"thought":"a","calls":[{"tool":"get_endpoint","args":{"index":0}}],"final":null}`,
		`{"thought":"b","calls":[],"final":{"summary":{"overview":"done"}}}`,
	}}
	_, outcome := agentOver(t, result, client, Options{})
	if outcome.Status != StatusOK {
		t.Fatalf("outcome = %+v", outcome)
	}
	data, err := os.ReadFile(outcome.TranscriptPath)
	if err != nil {
		t.Fatalf("read transcript: %v", err)
	}
	text := string(data)
	for _, want := range []string{`"role":"model"`, `"role":"tool_result"`, "get_endpoint", "final report accepted"} {
		if !strings.Contains(text, want) {
			t.Fatalf("transcript missing %q:\n%s", want, text)
		}
	}
}

func TestAgentParseErrorConsumesBudgetAndRetries(t *testing.T) {
	result := &model.Result{ReportDirectory: t.TempDir(),
		Endpoints: []model.Endpoint{{Raw: "/x", Type: "api"}}}
	client := &fakeChat{replies: []string{
		"这不是 JSON",
		`{"thought":"重试","calls":[],"final":{"summary":{"overview":"ok"}}}`,
	}}
	_, outcome := agentOver(t, result, client, Options{MaxSteps: 5, MaxRequests: 5})
	if outcome.Status != StatusOK {
		t.Fatalf("outcome = %+v", outcome)
	}
	if !strings.Contains(client.users[1], "无法解析") {
		t.Fatalf("parse feedback not fed back: %.400q", client.users[1])
	}
}

func TestAgentBudgetExhaustion(t *testing.T) {
	result := &model.Result{ReportDirectory: t.TempDir(),
		Endpoints: []model.Endpoint{{Raw: "/x", Type: "api"}}}
	// Every round asks for more evidence; MaxRequests=2 stops the loop.
	client := &fakeChat{replies: []string{
		`{"thought":"a","calls":[{"tool":"list_endpoints","args":{}}],"final":null}`,
		`{"thought":"b","calls":[{"tool":"list_endpoints","args":{}}],"final":null}`,
		`{"thought":"c","calls":[],"final":{"summary":{}}}`,
	}}
	_, outcome := agentOver(t, result, client, Options{MaxSteps: 10, MaxRequests: 2})
	if outcome.Status != StatusPartial || client.calls != 2 {
		t.Fatalf("outcome = %+v, calls = %d", outcome, client.calls)
	}
	if !strings.Contains(outcome.Reason, "预算") {
		t.Fatalf("reason = %q", outcome.Reason)
	}
}

func TestAgentStepLimit(t *testing.T) {
	result := &model.Result{ReportDirectory: t.TempDir(),
		Endpoints: []model.Endpoint{{Raw: "/x", Type: "api"}}}
	client := &fakeChat{replies: []string{
		`{"thought":"a","calls":[],"final":null}`, // invalid: empty plan without calls → parse error path
		`{"thought":"b","calls":[],"final":null}`,
	}}
	_, outcome := agentOver(t, result, client, Options{MaxSteps: 2, MaxRequests: 10})
	if outcome.Status != StatusPartial {
		t.Fatalf("outcome = %+v", outcome)
	}
	if client.calls > 3 {
		t.Fatalf("loop ran past its step budget: %d calls", client.calls)
	}
}

func TestAgentUpstreamFailure(t *testing.T) {
	result := &model.Result{ReportDirectory: t.TempDir(),
		Endpoints: []model.Endpoint{{Raw: "/x", Type: "api"}}}
	client := &fakeChat{errs: []error{errors.New("connection refused")}, replies: []string{""}}
	_, outcome := agentOver(t, result, client, Options{})
	if outcome.Status != StatusFailed || !strings.Contains(outcome.Reason, "connection refused") {
		t.Fatalf("outcome = %+v", outcome)
	}
}

func TestAgentContextBudgetDropsOldest(t *testing.T) {
	result := &model.Result{ReportDirectory: t.TempDir(),
		Endpoints: []model.Endpoint{{Raw: "/x", Type: "api"}}}
	// Three rounds with oversized tool results: round 1's payload must be
	// dropped from later turns. The stub returns a distinguishable payload
	// per call so the trim can be asserted.
	big1 := strings.Repeat("A", 45_000)
	big2 := strings.Repeat("B", 45_000)
	client := &fakeChat{replies: []string{
		`{"thought":"a","calls":[{"tool":"search_code","args":{"pattern":"x"}}],"final":null}`,
		`{"thought":"b","calls":[{"tool":"search_code","args":{"pattern":"y"}}],"final":null}`,
		`{"thought":"c","calls":[],"final":{"summary":{"overview":"ok"}}}`,
	}}
	// Stub the search tool so it returns the oversized payloads.
	agent := New(client, NewEvidence(result), Options{MaxSteps: 5, MaxRequests: 5})
	toolCalls := 0
	agent.tools.tools["search_code"] = Tool{Name: "search_code", Fn: func(json.RawMessage) string {
		toolCalls++
		if toolCalls == 1 {
			return big1
		}
		return big2
	}}
	outcome := agent.Run(context.Background(), result)
	if outcome.Status != StatusOK {
		t.Fatalf("outcome = %+v", outcome)
	}
	if strings.Contains(client.users[2], big1) {
		t.Fatal("round-1 payload should have been trimmed from later turns")
	}
	if !strings.Contains(client.users[2], big2) {
		t.Fatal("recent payload should survive trimming")
	}
}

func TestAgentTranscriptSkippedWithoutReportDir(t *testing.T) {
	result := &model.Result{Target: "https://example.com",
		Endpoints: []model.Endpoint{{Raw: "/x", Type: "api"}}}
	client := &fakeChat{replies: []string{`{"thought":"a","calls":[],"final":{"summary":{}}}`}}
	_, outcome := agentOver(t, result, client, Options{})
	if outcome.Status != StatusOK || outcome.TranscriptPath != "" {
		t.Fatalf("outcome = %+v", outcome)
	}
}

func TestBriefingCountsSeverities(t *testing.T) {
	result := &model.Result{
		Target: "https://example.com", Mode: model.ModeBrowser,
		Technologies: []string{"spa", "webpack"},
		Endpoints: []model.Endpoint{
			{Raw: "/a", Type: "api"}, {Raw: "/b", Type: "api"}, {Raw: "/c", Type: "route"},
		},
		Findings: []model.Finding{
			{Severity: model.SeverityHigh}, {Severity: model.SeverityHigh}, {Severity: model.SeverityLow},
		},
	}
	agent := New(&fakeChat{}, NewEvidence(result), Options{})
	brief := agent.briefing(result)
	for _, want := range []string{"接口: 3 (api 2 / 路由 1)", "敏感发现: 3", "high=2", "low=1", "spa, webpack"} {
		if !strings.Contains(brief, want) {
			t.Fatalf("briefing missing %q:\n%s", want, brief)
		}
	}
}

func TestApplyThenReportStats(t *testing.T) {
	// End-to-end through the loop: the final report's reviews land on the
	// result and the stats reflect them.
	result := &model.Result{
		ReportDirectory: filepath.Join(t.TempDir()),
		Target:          "https://example.com",
		Endpoints:       []model.Endpoint{{Raw: "/api/login", Method: "POST", Type: "api"}},
		Findings:        []model.Finding{{RuleID: "ak", Value: "LTAI1", Severity: model.SeverityHigh}},
	}
	client := &fakeChat{replies: []string{
		`{"thought":"a","calls":[],"final":{"reviews":[{"endpoint":"/api/login","completeness":"missing-fields","assessment":"缺字段"}],"ratings":[{"rule_id":"ak","value":"LTAI1","rating":"high","reason":"真key"}],"summary":{"overview":"总评"}}}`,
	}}
	_, outcome := agentOver(t, result, client, Options{})
	if outcome.Status != StatusOK {
		t.Fatalf("outcome = %+v", outcome)
	}
	stats := Apply(result, outcome.Final)
	stats.Steps, stats.Requests = outcome.Steps, outcome.Requests
	if stats.Reviews != 1 || stats.Ratings != 1 {
		t.Fatalf("stats = %+v", stats)
	}
	if result.Endpoints[0].Template.AI == nil {
		t.Fatal("review not merged onto template")
	}
	if result.AI == nil || result.AI.Overview != "总评" {
		t.Fatalf("summary = %+v", result.AI)
	}
}
