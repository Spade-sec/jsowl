package discover

import (
	"net/url"
	"reflect"
	"testing"
)

// TestAnalyzeBodyMatchesSeparateExtractors pins the shared-parse contract:
// reusing one syntax tree for the API and parameter passes must produce the
// same result as the two independent entry points.
func TestAnalyzeBodyMatchesSeparateExtractors(t *testing.T) {
	source, err := url.Parse("https://example.test/static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	bodies := []string{
		`fetch("/api/users");const user={userId:1,loginName:"a"}`,
		`function getUser(userId, token){return axios.get("/api/user",{params:{userId}})}`,
		`const {profile: {email}} = data; client_secret="DemoSecret_123=-"`,
		`import("/static/chunk.js");r.e("chunk-a")`,
		`not javascript at all {{{`,
		``,
		`中文变量 = "值"; fetch("/api/中文")`,
	}
	for _, body := range bodies {
		analysis, params := AnalyzeBody(source, []byte(body))
		wantAnalysis := AnalyzeJS(source, []byte(body))
		wantParams := ParamsFromAST(source, []byte(body))
		if !reflect.DeepEqual(analysis, wantAnalysis) {
			t.Fatalf("analysis mismatch for %q:\nshared=%#v\nseparate=%#v",
				body, analysis, wantAnalysis)
		}
		if !reflect.DeepEqual(params, wantParams) {
			t.Fatalf("params mismatch for %q:\nshared=%#v\nseparate=%#v",
				body, params, wantParams)
		}
	}
}
