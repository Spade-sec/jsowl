package analyze

import (
	"os"
	"path/filepath"
	"testing"
)

// TestMain loads the default rules from the repository's config/rules.yml.
// Normal binaries receive the same bytes from the root jsowl package's
// go:embed (injected in its init), but this test binary does not import that
// package, so load the file directly from the source tree.
func TestMain(m *testing.M) {
	data, err := os.ReadFile(filepath.Join("..", "..", "config", "rules.yml"))
	if err != nil {
		panic("load default rules: " + err.Error())
	}
	if err := SetDefaultRulesYAML(data); err != nil {
		panic("install default rules: " + err.Error())
	}
	os.Exit(m.Run())
}
