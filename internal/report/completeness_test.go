package report

import (
	"strings"
	"testing"
	"time"

	"github.com/youmulijiang/jsowl/internal/model"
)

// TestSummaryExpressesPartialScan pins the report contract: a scan whose
// collection budget ran out but which analyzed every fetched file is labeled
// "采集不完整（已获取 JS 分析完成）" — never wrapped as a complete success,
// and never with invented counts.
func TestSummaryExpressesPartialScan(t *testing.T) {
	result := &model.Result{
		Target: "https://example.test",
		Completeness: &model.Completeness{
			Collection: model.PhaseCompleteness{
				Complete: false,
				Reason:   "网络采集预算 request.target_timeout=5m0s 已耗尽",
			},
			Analysis: model.PhaseCompleteness{Complete: true},
			Coverage: model.Coverage{
				Discovered: 3, Fetched: 2, FetchFailed: 1, Analyzed: 2,
			},
		},
	}
	summary := buildSummary(result, time.Now())
	if summary.Completeness == nil {
		t.Fatal("summary omits the completeness record")
	}
	if got := summary.Completeness.Status; got != "采集不完整（已获取 JS 分析完成）" {
		t.Errorf("status = %q, want 采集不完整（已获取 JS 分析完成）", got)
	}
	if summary.Completeness.Complete {
		t.Error("summary.Complete should be false")
	}
	if got := summary.Completeness.Coverage.Discovered; got != 3 {
		t.Errorf("discovered = %d, want 3", got)
	}

	text := string(renderCompleteness(result))
	for _, want := range []string{
		"网络采集: 不完整", "JS 本地分析: 完成",
		"发现 JS: 3", "已获取 JS: 2", "获取失败 1",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("completeness text missing %q:\n%s", want, text)
		}
	}
	if !strings.Contains(text, "不代表该网站全部 JS") {
		t.Error("completeness text should state the discovered count is a lower bound")
	}
}

// TestSummaryOmitsUnrecordedCompleteness keeps older results and library
// callers honest: without a completeness record the report stays silent
// instead of inventing a verdict.
func TestSummaryOmitsUnrecordedCompleteness(t *testing.T) {
	result := &model.Result{Target: "https://example.test"}
	summary := buildSummary(result, time.Now())
	if summary.Completeness != nil {
		t.Errorf("summary should omit completeness, got %+v", summary.Completeness)
	}
	if text := string(renderCompleteness(result)); !strings.Contains(text, "未记录完整性状态") {
		t.Errorf("text should say the status was not recorded, got:\n%s", text)
	}
}

// TestCompletenessTextListsUnfinishedResources checks the unfinished list and
// its cap accounting render with stage, state and reason.
func TestCompletenessTextListsUnfinishedResources(t *testing.T) {
	result := &model.Result{
		Target: "https://example.test",
		Completeness: &model.Completeness{
			Collection: model.PhaseCompleteness{Complete: true},
			Analysis: model.PhaseCompleteness{
				Complete: false, Reason: "1 个已获取 JS 因调用方取消未完成分析",
			},
			Coverage: model.Coverage{
				Discovered: 1, Fetched: 1, AnalysisPending: 1,
				Unfinished: []model.UnfinishedResource{{
					URL: "https://example.test/app.js", Stage: "analyze",
					State: "analysis_pending", Reason: "调用方取消，未分析",
				}},
			},
		},
	}
	text := string(renderCompleteness(result))
	for _, want := range []string{
		"JS 本地分析: 不完整", "app.js", "analysis_pending", "调用方取消，未分析",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("completeness text missing %q:\n%s", want, text)
		}
	}
}
