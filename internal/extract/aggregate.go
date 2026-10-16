package extract

import (
	"strconv"
	"strings"

	"github.com/youmulijiang/jsowl/internal/model"
)

// Aggregator merges classified candidates into deduplicated assets.
//
// The dedup key is kind + normalized value, so one host spelled with different
// case, a trailing root dot or a different port collapses into a single asset,
// while every distinct source location is kept. It is not safe for concurrent
// use: each analysis goroutine builds its own aggregator and the results are
// merged afterwards, which keeps the aggregation data-race free without
// locking on the hot path.
type Aggregator struct {
	extractor *Extractor
	origin    string

	assets []model.HostAsset
	index  map[string]int

	notes      []Note
	candidates int
	// evidenceSkipped and assetsSkipped count what a cap dropped, so the
	// diagnostic can state the exact amount.
	evidenceSkipped int
	assetsSkipped   int
	capped          bool
}

// NewAggregator builds an aggregator for one origin (content or scan).
func NewAggregator(extractor *Extractor, origin string) *Aggregator {
	return &Aggregator{
		extractor: extractor,
		origin:    origin,
		index:     map[string]int{},
	}
}

// Add classifies one candidate and folds it into the aggregate. It returns
// true when the candidate became (or joined) an asset.
func (a *Aggregator) Add(candidate Candidate) bool {
	if a == nil || a.extractor == nil {
		return false
	}
	a.candidates++
	asset, ok := a.extractor.Classify(candidate)
	if !ok {
		return false
	}
	return a.merge(asset)
}

// AddHost classifies an already parsed host (a scan URL's authority) and folds
// it into the aggregate.
func (a *Aggregator) AddHost(host string, candidate Candidate) bool {
	if a == nil || a.extractor == nil {
		return false
	}
	a.candidates++
	asset, ok := a.extractor.ClassifyHost(host, candidate)
	if !ok {
		return false
	}
	return a.merge(asset)
}

// Merge folds assets that were aggregated elsewhere (a per-file aggregator, or
// another target's result) into this one.
func (a *Aggregator) Merge(assets []model.HostAsset) {
	if a == nil {
		return
	}
	for _, asset := range assets {
		a.merge(asset)
	}
}

func (a *Aggregator) merge(asset model.HostAsset) bool {
	asset.Origin = a.origin
	key := string(asset.Kind) + "\x00" + asset.Value
	existing, found := a.index[key]
	if !found {
		if len(a.assets) >= MaxAssetsPerTarget {
			a.assetsSkipped++
			a.capped = true
			return false
		}
		if asset.Sources == nil {
			asset.Sources = []model.HostEvidence{}
		}
		// Sources arriving from another aggregator were deduplicated there, so
		// their number is the occurrence count.
		asset.Occurrences = len(asset.Sources)
		a.index[key] = len(a.assets)
		a.assets = append(a.assets, asset)
		return true
	}
	target := &a.assets[existing]
	// A zone identifier is recorded even when it was absent from the first
	// sighting; it stays out of the dedup key either way.
	if target.Zone == "" {
		target.Zone = asset.Zone
	}
	if len(asset.Attributes) > 0 && len(target.Attributes) == 0 {
		target.Attributes = asset.Attributes
	}
	// Nothing is vendored unless every sighting is vendored.
	target.Vendor = target.Vendor && asset.Vendor
	for _, source := range asset.Sources {
		a.addEvidence(target, source)
	}
	return true
}

// addEvidence records one observation. An identical location already recorded
// for this asset is the same observation, not a new one; a location beyond the
// evidence cap still counts towards Occurrences, so the number stays truthful
// even when the kept list is truncated.
func (a *Aggregator) addEvidence(asset *model.HostAsset, source model.HostEvidence) {
	key := evidenceKey(source)
	for index := range asset.Sources {
		if evidenceKey(asset.Sources[index]) == key {
			mergeNotes(&asset.Sources[index], source.Note)
			return
		}
	}
	asset.Occurrences++
	if len(asset.Sources) >= MaxEvidencePerAsset {
		a.evidenceSkipped++
		a.capped = true
		return
	}
	asset.Sources = append(asset.Sources, source)
}

// evidenceKey identifies one observation of a host: the same value, found by
// the same method, at the same place. The note is deliberately excluded — two
// extractors reporting the same location are one observation — but it is
// merged into the kept entry instead of being discarded.
func evidenceKey(source model.HostEvidence) string {
	return strings.Join([]string{
		source.SourceURL,
		strconv.Itoa(source.Line),
		strconv.Itoa(source.Column),
		source.Method,
		source.Raw,
		source.AssociatedURL,
	}, "\x00")
}

// mergeNotes adds a note to an entry that already exists, keeping both
// origins visible without duplicating the observation.
func mergeNotes(target *model.HostEvidence, note string) {
	if note == "" {
		return
	}
	for _, existing := range strings.Split(target.Note, ",") {
		if strings.TrimSpace(existing) == note {
			return
		}
	}
	if target.Note == "" {
		target.Note = note
		return
	}
	target.Note += "," + note
}

// Note records a diagnostic. Duplicate codes collapse to one entry so a
// thousand bundles cannot flood the issue list.
func (a *Aggregator) Note(code, message, sourceURL string) {
	if a == nil {
		return
	}
	for _, note := range a.notes {
		if note.Code == code && note.Message == message {
			return
		}
	}
	a.notes = append(a.notes, Note{Code: code, Message: message, URL: sourceURL})
}

// Assets returns the aggregated assets in deterministic order. The returned
// slice is a copy: callers cannot mutate the aggregator's state.
func (a *Aggregator) Assets() []model.HostAsset {
	if a == nil {
		return nil
	}
	out := make([]model.HostAsset, len(a.assets))
	copy(out, a.assets)
	for index := range out {
		sources := make([]model.HostEvidence, len(out[index].Sources))
		copy(sources, out[index].Sources)
		out[index].Sources = sources
	}
	SortAssets(out)
	return out
}

// Notes returns the diagnostics raised while aggregating, including the ones
// derived from caps that fired.
func (a *Aggregator) Notes() []Note {
	if a == nil {
		return nil
	}
	notes := append([]Note{}, a.notes...)
	if a.extractor != nil {
		if _, _, err := a.extractor.PSLVersion(); err != nil {
			notes = append(notes, Note{
				Code: NotePSLUnavailable,
				Message: "公共后缀列表初始化失败，域名层级标记为未解析（候选本身仍保留）：" +
					err.Error(),
			})
		}
	}
	if a.assetsSkipped > 0 {
		notes = append(notes, Note{
			Code: NoteAssetsCapped,
			Message: "主机资产数量达到上限 " + strconv.Itoa(MaxAssetsPerTarget) +
				"，另有 " + strconv.Itoa(a.assetsSkipped) + " 个主机未记录。",
		})
	}
	if a.evidenceSkipped > 0 {
		notes = append(notes, Note{
			Code: NoteEvidenceCapped,
			Message: "单个主机的来源证据达到上限 " + strconv.Itoa(MaxEvidencePerAsset) +
				"，另有 " + strconv.Itoa(a.evidenceSkipped) + " 条证据未记录（出现次数仍然统计）。",
		})
	}
	return notes
}

// Candidates reports how many candidates were offered to Add/AddHost.
func (a *Aggregator) Candidates() int {
	if a == nil {
		return 0
	}
	return a.candidates
}
