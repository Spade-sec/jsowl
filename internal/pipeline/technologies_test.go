package pipeline

import (
	"testing"

	"github.com/youmulijiang/jsowl/internal/discover"
	"github.com/youmulijiang/jsowl/internal/model"
)

func TestApplyTechnologiesDeduplicatesAndSorts(t *testing.T) {
	result := &model.Result{Technologies: []string{"webpack", "spa", "spa"}}
	applyTechnologies(result, discover.SPAEvidence{
		DynamicImport: true, Webpack: true, RequireJS: true,
	})
	want := []string{"requirejs", "spa", "webpack"}
	if len(result.Technologies) != len(want) {
		t.Fatalf("technologies = %#v", result.Technologies)
	}
	for index, technology := range want {
		if result.Technologies[index] != technology {
			t.Fatalf("technologies = %#v", result.Technologies)
		}
	}
}

func TestApplyTechnologiesWithoutEvidenceAddsNothing(t *testing.T) {
	result := &model.Result{}
	applyTechnologies(result, discover.SPAEvidence{LargeBundle: true})
	if len(result.Technologies) != 0 {
		t.Fatalf("technologies = %#v", result.Technologies)
	}
}
