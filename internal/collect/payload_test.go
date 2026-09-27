package collect

import (
	"strings"
	"testing"

	"github.com/youmulijiang/jsowl/internal/model"
)

func TestParseRequestPayloadJSON(t *testing.T) {
	spec := ParseRequestPayload("POST",
		"https://x.test/api/batch?page=2",
		`{"userId":1,"content":"hello","items":[{"id":7,"sku":"A"},{"id":8}],"flag":true,"meta":{"deep":{"x":1}}}`,
		"application/json")
	if spec == nil {
		t.Fatal("expected spec")
	}
	if spec.ContentType != "application/json" || spec.ContentTypeEvidence != model.EvidenceRuntime {
		t.Fatalf("content type = %+v", spec)
	}
	want := map[string]string{
		"page":        "2",
		"userId":      "1",
		"content":     "hello",
		"items[].id":  "7",
		"items[].sku": "A",
		"flag":        "true",
	}
	for key, value := range want {
		found := false
		for _, list := range [][]model.Param{spec.Query, spec.Body} {
			for _, param := range list {
				if param.Key == key && param.Value == value && param.Evidence == model.EvidenceRuntime {
					found = true
				}
			}
		}
		if !found {
			t.Fatalf("missing param %q=%q in %+v / %+v", key, value, spec.Query, spec.Body)
		}
	}
	// Depth cap: beyond 3 levels the container collapses, not the walk.
	if param := findPayloadParam(spec.Body, "meta.deep.x"); param == nil {
		t.Fatalf("nested dotted key missing: %+v", spec.Body)
	}
}

func TestParseRequestPayloadFormAndMultipart(t *testing.T) {
	spec := ParseRequestPayload("POST", "https://x.test/login",
		"username=admin&password=JsOwlP%40ssw0rd1", "application/x-www-form-urlencoded")
	if spec == nil || len(spec.Body) != 2 {
		t.Fatalf("form body = %+v", spec)
	}
	if param := findPayloadParam(spec.Body, "username"); param == nil || param.Value != "admin" {
		t.Fatalf("username = %+v", param)
	}
	if spec.ContentTypeEvidence != model.EvidenceRuntime {
		t.Fatalf("content type evidence = %+v", spec.ContentTypeEvidence)
	}
	multipart := ParseRequestPayload("POST", "https://x.test/upload",
		"--BOUND\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.png\"\r\n\r\nxx\r\n--BOUND--",
		"multipart/form-data; boundary=BOUND")
	// url.ParseQuery cannot read multipart, so no body params; spec may be nil.
	if multipart != nil && len(multipart.Body) > 1 {
		t.Fatalf("multipart should not produce bogus params: %+v", multipart.Body)
	}
}

func TestParseRequestPayloadEmpty(t *testing.T) {
	if spec := ParseRequestPayload("GET", "https://x.test/plain", "", ""); spec != nil {
		t.Fatalf("GET without query should be nil: %+v", spec)
	}
	if spec := ParseRequestPayload("GET", "https://x.test/?q=js", "", ""); spec == nil ||
		len(spec.Query) != 1 || spec.Query[0].Key != "q" {
		t.Fatalf("query-only spec = %+v", spec)
	}
}

func TestParseRequestPayloadValueTruncation(t *testing.T) {
	long := strings.Repeat("A", 500)
	spec := ParseRequestPayload("POST", "https://x.test/x",
		`{"blob":"`+long+`"}`, "application/json")
	if spec == nil {
		t.Fatal("expected spec")
	}
	value := spec.Body[0].Value
	if len(value) > 70 {
		t.Fatalf("value not truncated: %d chars", len(value))
	}
}

func findPayloadParam(params []model.Param, key string) *model.Param {
	for i := range params {
		if params[i].Key == key {
			return &params[i]
		}
	}
	return nil
}
