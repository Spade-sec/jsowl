package pipeline

import (
	"sync"

	"github.com/youmulijiang/jsowl/internal/extract"
	"github.com/youmulijiang/jsowl/internal/model"
)

var (
	defaultExtractorOnce sync.Once
	defaultExtractor     *extract.Extractor
)

// defaultHostExtractor is the extractor used when a Result is finalized
// without a pipeline (external callers, merged results). The Public Suffix
// List behind it is initialized once per process.
func defaultHostExtractor() *extract.Extractor {
	defaultExtractorOnce.Do(func() {
		defaultExtractor = extract.NewExtractor(model.HostsConfig{})
	})
	return defaultExtractor
}

// recordHostNotes turns extraction diagnostics into issues, skipping any code
// and message already present. That keeps repeated calls to Finalize
// idempotent instead of appending the same diagnostics again.
func recordHostNotes(result *model.Result, notes []extract.Note) {
	if len(notes) == 0 {
		return
	}
	seen := make(map[string]struct{}, len(result.Issues))
	for _, issue := range result.Issues {
		seen[issue.Code+"\x00"+issue.Message] = struct{}{}
	}
	for _, note := range notes {
		key := note.Code + "\x00" + note.Message
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		result.Issues = append(result.Issues, model.Issue{
			Code:    note.Code,
			Stage:   "analyze",
			URL:     note.URL,
			Message: note.Message,
		})
	}
}
