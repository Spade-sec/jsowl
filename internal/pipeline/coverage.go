package pipeline

import (
	"sort"

	"github.com/youmulijiang/jsowl/internal/model"
	"github.com/youmulijiang/jsowl/internal/scheduler"
)

// Coverage states. Fetch and analysis each move a resource through exactly one
// terminal state; the snapshot maps any intermediate state onto the honest
// terminal one (a dispatched resource whose outcome never arrived counts as
// not attempted rather than as a success).
const (
	fetchDiscovered   = "discovered"    // seen as a candidate, no decision yet
	fetchDispatched   = "dispatched"    // handed to a collection worker
	fetchFetched      = "fetched"       // GET succeeded
	fetchFailed       = "fetch_failed"  // GET returned an error
	fetchSkipped      = "fetch_skipped" // policy excluded it before any request
	fetchNotAttempted = "not_attempted" // collection stopped before dispatch
	analysisNone      = ""              // fetched, analysis not decided yet
	analysisAnalyzed  = "analyzed"
	analysisFailed    = "analysis_failed"
	analysisSkipped   = "analysis_skipped"
	analysisPending   = "analysis_pending" // cancelled before its analysis ran
)

// coverageItem is the per-URL state of one discovered JavaScript resource.
type coverageItem struct {
	url            string
	fetch          string
	fetchReason    string
	analysis       string
	analysisReason string
}

// coverageTracker records what happened to every unique JavaScript resource
// (scripts and chunks) one target's run discovered, keyed by canonical URL so
// repeated discoveries never double count. It lives on the Pipeline, not on
// one runState, so the auto mode's second (browser) RunDetailed pass adds to
// the same tracker instead of re-counting what the direct pass already
// handled. Every method is called from the run coordinator goroutine only.
type coverageTracker struct {
	items map[string]*coverageItem
	order []string
}

func newCoverageTracker() *coverageTracker {
	return &coverageTracker{items: map[string]*coverageItem{}}
}

// isJavaScriptKind reports whether a scheduler item is a JS resource the
// coverage tracker follows. Documents, API probes and source maps are not.
func isJavaScriptKind(kind model.ResourceType) bool {
	return kind == model.ResourceTypeScript || kind == model.ResourceTypeChunk
}

func (t *coverageTracker) item(url string) *coverageItem {
	if url == "" {
		return nil
	}
	if existing, ok := t.items[url]; ok {
		return existing
	}
	created := &coverageItem{url: url, fetch: fetchDiscovered}
	t.items[url] = created
	t.order = append(t.order, url)
	return created
}

// discovered records a newly seen JS resource URL and reports whether the
// URL was new to the tracker. Already-known URLs are ignored, so the same
// resource discovered by the document, by an AST pass and by runtime
// observation counts once.
func (t *coverageTracker) discovered(url string) bool {
	before := len(t.items)
	t.item(url)
	return len(t.items) > before
}

// fetchSkipped records that policy excluded the resource before any request.
// Only a resource with no fetch decision yet can be skipped; one already
// fetched keeps its state.
func (t *coverageTracker) fetchSkipped(url, reason string) {
	item := t.item(url)
	if item == nil || item.fetch != fetchDiscovered {
		return
	}
	item.fetch = fetchSkipped
	item.fetchReason = reason
}

// dispatched records that the coordinator handed the resource to a worker.
func (t *coverageTracker) dispatched(url string) {
	item := t.item(url)
	if item == nil || item.fetch != fetchDiscovered {
		return
	}
	item.fetch = fetchDispatched
}

// fetched records a successful GET.
func (t *coverageTracker) fetched(url string) {
	item := t.item(url)
	if item == nil {
		return
	}
	item.fetch = fetchFetched
	item.fetchReason = ""
}

// fetchFailed records a failed GET with the error text.
func (t *coverageTracker) fetchFailed(url, reason string) {
	item := t.item(url)
	if item == nil || item.fetch == fetchFetched || item.fetch == fetchFailed {
		return
	}
	item.fetch = fetchFailed
	item.fetchReason = reason
}

// markNotDispatched walks queue leftovers (and, optionally, items still in
// flight) and records the resources collection stopped before fetching. The
// queued items are only ever marked when they carry no fetch decision, so
// repeated drain calls after the budget expired stay idempotent.
func (t *coverageTracker) markNotDispatched(queued []scheduler.Item, reason string) {
	for _, queuedItem := range queued {
		if !isJavaScriptKind(queuedItem.Kind) {
			continue
		}
		item := t.item(queuedItem.URL)
		if item == nil || item.fetch != fetchDiscovered {
			continue
		}
		item.fetch = fetchNotAttempted
		item.fetchReason = reason
	}
}

// markAbortedInFlight records dispatched resources whose outcome never
// arrived (caller cancelled while they ran). A resource the sweep already
// merged keeps its fetched/failed state.
func (t *coverageTracker) markAbortedInFlight(urls []string, reason string) {
	for _, url := range urls {
		item := t.item(url)
		if item == nil || item.fetch != fetchDispatched {
			continue
		}
		item.fetch = fetchFailed
		item.fetchReason = reason
	}
}

// analyzed records a successful extraction pass.
func (t *coverageTracker) analyzed(url string) {
	item := t.item(url)
	if item == nil {
		return
	}
	item.analysis = analysisAnalyzed
	item.analysisReason = ""
}

// analysisFailed records a fetched resource whose analysis errored.
func (t *coverageTracker) analysisFailed(url, reason string) {
	item := t.item(url)
	if item == nil {
		return
	}
	item.analysis = analysisFailed
	item.analysisReason = reason
}

// analysisSkipped records that policy (library-bundle skip) excluded the
// fetched resource from analysis.
func (t *coverageTracker) analysisSkipped(url, reason string) {
	item := t.item(url)
	if item == nil {
		return
	}
	item.analysis = analysisSkipped
	item.analysisReason = reason
}

// analysisPending records a fetched resource the run cancelled before its
// deferred analysis ran. Existing terminal states are never overwritten.
func (t *coverageTracker) analysisPending(url, reason string) {
	item := t.item(url)
	if item == nil || item.analysis != analysisNone {
		return
	}
	item.analysis = analysisPending
	item.analysisReason = reason
}

// snapshot folds the per-URL states into the report counts. Every discovered
// resource ends in exactly one fetch state and every fetched resource in
// exactly one analysis state, so the counts are auditable:
//
//	fetched + fetch_failed + fetch_skipped + fetch_not_attempted = discovered
//	analyzed + analysis_failed + analysis_skipped + analysis_pending = fetched
func (t *coverageTracker) snapshot() model.Coverage {
	coverage := model.Coverage{}
	unfinished := make([]model.UnfinishedResource, 0)
	for _, url := range t.order {
		item := t.items[url]
		coverage.Discovered++
		switch item.fetch {
		case fetchFetched:
			coverage.Fetched++
		case fetchFailed:
			coverage.FetchFailed++
			unfinished = append(unfinished, model.UnfinishedResource{
				URL: item.url, Stage: "collect",
				State: "fetch_failed", Reason: item.fetchReason,
			})
		case fetchSkipped:
			coverage.FetchSkipped++
			unfinished = append(unfinished, model.UnfinishedResource{
				URL: item.url, Stage: "collect",
				State: "fetch_skipped", Reason: item.fetchReason,
			})
		case fetchDispatched:
			// Defensive: the coordinator resolves every dispatched item; an
			// unobserved one counts as not attempted, never as success.
			coverage.FetchNotAttempted++
			unfinished = append(unfinished, model.UnfinishedResource{
				URL: item.url, Stage: "collect",
				State: "not_attempted", Reason: "采集停止时请求仍在途",
			})
		default:
			coverage.FetchNotAttempted++
			unfinished = append(unfinished, model.UnfinishedResource{
				URL: item.url, Stage: "collect",
				State: "not_attempted", Reason: "采集停止前未派发请求",
			})
		}
		if item.fetch != fetchFetched {
			continue
		}
		switch item.analysis {
		case analysisAnalyzed:
			coverage.Analyzed++
		case analysisFailed:
			coverage.AnalysisFailed++
			unfinished = append(unfinished, model.UnfinishedResource{
				URL: item.url, Stage: "analyze",
				State: "analysis_failed", Reason: item.analysisReason,
			})
		case analysisSkipped:
			coverage.AnalysisSkipped++
		case analysisPending:
			coverage.AnalysisPending++
			unfinished = append(unfinished, model.UnfinishedResource{
				URL: item.url, Stage: "analyze",
				State: "analysis_pending", Reason: item.analysisReason,
			})
		default:
			coverage.AnalysisPending++
			unfinished = append(unfinished, model.UnfinishedResource{
				URL: item.url, Stage: "analyze",
				State: "analysis_pending", Reason: "运行结束前未分析",
			})
		}
	}
	sort.SliceStable(unfinished, func(i, j int) bool {
		if unfinished[i].Stage != unfinished[j].Stage {
			return unfinished[i].Stage < unfinished[j].Stage
		}
		return unfinished[i].URL < unfinished[j].URL
	})
	if len(unfinished) > model.MaxUnfinishedList {
		coverage.UnfinishedOmitted = len(unfinished) - model.MaxUnfinishedList
		unfinished = unfinished[:model.MaxUnfinishedList]
	}
	coverage.Unfinished = unfinished
	return coverage
}
