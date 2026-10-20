package jsowl

import (
	_ "embed"
	"fmt"

	"github.com/youmulijiang/jsowl/internal/analyze"
)

// defaultRulesYAML embeds config/rules.yml, the single source of truth for
// sensitive-information rules (HaE native format). API/URL extraction rules
// live in internal/analyze.APIRules and are always compiled. The file on disk
// is what developers edit; the CLI additionally loads it at runtime through
// the project-rules layer, so edits take effect without rebuilding. The
// embedded copy backs first-run seeding of ~/.jsowl/rules.yaml and binaries
// run outside a checkout.
//
//go:embed config/rules.yml
var defaultRulesYAML []byte

func init() {
	if err := analyze.SetDefaultRulesYAML(defaultRulesYAML); err != nil {
		panic(fmt.Sprintf("jsowl: inject default rules: %v", err))
	}
}
