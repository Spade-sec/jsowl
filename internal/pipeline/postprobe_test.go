package pipeline

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/youmulijiang/jsowl/internal/model"
)

const pipelineTestJWT = "eyJhbGciOiJIUzI1NiJ9.abcdefghijklmno.abcdefghijklmnop"

type recordedProbe struct {
	method      string
	body        string
	contentType string
}

func TestPostProbeBuildsBodyFromContentType(t *testing.T) {
	var mutex sync.Mutex
	probes := make(map[string][]recordedProbe)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		if request.Method == http.MethodPost {
			mutex.Lock()
			probes[request.URL.Path] = append(probes[request.URL.Path], recordedProbe{
				method:      request.Method,
				body:        string(body),
				contentType: request.Header.Get("Content-Type"),
			})
			mutex.Unlock()
		}
		switch request.URL.Path {
		case "/":
			writer.Header().Set("Content-Type", "text/html")
			_, _ = writer.Write([]byte(`<div id="app"></div><script src="/app.js"></script>`))
		case "/app.js":
			writer.Header().Set("Content-Type", "application/javascript")
			_, _ = writer.Write([]byte(
				`axios.post('/api/login', {user: 'demo'});` +
					`axios.post('/api/form', {a: 1}, {headers: {'Content-Type': 'application/x-www-form-urlencoded'}});` +
					`axios.post('/api/upload', {file: 'x'}, {headers: {'Content-Type': 'multipart/form-data'}});`,
			))
		case "/api/login":
			writer.Header().Set("Content-Type", "application/json")
			if request.Method == http.MethodPost {
				_, _ = writer.Write([]byte(`{"token":"` + pipelineTestJWT + `","profile":{"id":7}}`))
				return
			}
			_, _ = writer.Write([]byte(`{"ok":true}`))
		default:
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(`{"accepted":true}`))
		}
	}))
	defer server.Close()

	config := model.DefaultConfig()
	config.Mode = model.ModeDirect
	pipeline := newTestPipeline(t, config, server)

	result, _, err := pipeline.RunDetailed(
		context.Background(), model.Target{URL: server.URL}, http.Header{}, nil, nil, nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	login := requirePostProbe(t, probes, "/api/login")
	if login.body != "{}" || login.contentType != "application/json" {
		t.Fatalf("JSON probe = %#v, want empty JSON object", login)
	}
	form := requirePostProbe(t, probes, "/api/form")
	if form.body != "a=" || !strings.HasPrefix(form.contentType, "application/x-www-form-urlencoded") {
		t.Fatalf("form probe = %#v, want recovered keys with empty values", form)
	}
	upload := requirePostProbe(t, probes, "/api/upload")
	if !strings.HasPrefix(upload.contentType, "multipart/form-data; boundary=") ||
		!strings.Contains(upload.body, `name="file"`) {
		t.Fatalf("multipart probe = %#v, want a boundary-correct form part", upload)
	}

	var endpoint *model.Endpoint
	for index := range result.Endpoints {
		if result.Endpoints[index].URL == server.URL+"/api/login" {
			endpoint = &result.Endpoints[index]
		}
	}
	if endpoint == nil {
		t.Fatalf("endpoint missing: %#v", result.Endpoints)
	}
	if endpoint.Method != http.MethodPost || endpoint.StatusCode != http.StatusOK {
		t.Fatalf("endpoint = %#v, want POST 200 from the probe", *endpoint)
	}
	if !containsString(endpoint.ResponseParams, "token") {
		t.Fatalf("response params = %#v, want the POST response fields", endpoint.ResponseParams)
	}

	var jwtFinding *model.Finding
	for index := range result.Findings {
		finding := &result.Findings[index]
		if finding.RuleID == "hae.密钥凭证.jwt-token" {
			jwtFinding = finding
		}
	}
	if jwtFinding == nil {
		t.Fatalf("JWT from the POST response was not extracted: %#v", result.Findings)
	}
	if jwtFinding.SourceURL != server.URL+"/api/login" {
		t.Fatalf("finding source = %q, want the POST response URL", jwtFinding.SourceURL)
	}
}

func requirePostProbe(
	t *testing.T,
	probes map[string][]recordedProbe,
	path string,
) recordedProbe {
	t.Helper()
	for _, probe := range probes[path] {
		if probe.method == http.MethodPost {
			return probe
		}
	}
	t.Fatalf("no POST probe for %s: %#v", path, probes[path])
	return recordedProbe{}
}

func TestPostProbeDisabledKeepsScanGetOnly(t *testing.T) {
	var mutex sync.Mutex
	var methods []string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/":
			writer.Header().Set("Content-Type", "text/html")
			_, _ = writer.Write([]byte(`<script src="/app.js"></script>`))
		case "/app.js":
			writer.Header().Set("Content-Type", "application/javascript")
			_, _ = writer.Write([]byte(`axios.post('/api/login', {user: 'demo'});`))
		case "/api/login":
			mutex.Lock()
			methods = append(methods, request.Method)
			mutex.Unlock()
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(`{"ok":true}`))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	config := model.DefaultConfig()
	config.Mode = model.ModeDirect
	config.Scope.ProbePost = false
	pipeline := newTestPipeline(t, config, server)

	if _, _, err := pipeline.RunDetailed(
		context.Background(), model.Target{URL: server.URL}, http.Header{}, nil, nil, nil,
	); err != nil {
		t.Fatal(err)
	}

	for _, method := range methods {
		if method != http.MethodGet {
			t.Fatalf("methods = %v, want GET only", methods)
		}
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if strings.EqualFold(value, want) {
			return true
		}
	}
	return false
}
