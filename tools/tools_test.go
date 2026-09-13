package tools

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestStore(t *testing.T) (*Store, ScanOutput) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/static/app.js":
			writer.Header().Set("Content-Type", "application/javascript")
			_, _ = writer.Write([]byte(
				`fetch('/api/users?page=1');` +
					`const token='eyJhbGciOiJIUzI1NiJ9.abcdefghijklmno.abcdefghijklmnop';` +
					`axios.post('/api/login', {username, password});`,
			))
		default:
			writer.Header().Set("Content-Type", "text/html")
			_, _ = writer.Write([]byte(
				`<div id="app"></div><script src="/static/app.js"></script>`,
			))
		}
	}))
	t.Cleanup(server.Close)

	store := NewStore(t.TempDir())
	scan, err := store.Scan(context.Background(), ScanInput{
		URL: server.URL, Mode: "direct", WriteReports: true,
	})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	return store, scan
}

func TestScanAndTypedQueries(t *testing.T) {
	store, scan := newTestStore(t)

	if scan.Endpoints == 0 || scan.Sensitive == 0 {
		t.Fatalf("scan summary = %#v", scan)
	}
	if scan.ReportDir == "" {
		t.Fatal("report dir missing despite write_reports")
	}

	endpoints, err := store.Endpoints(EndpointsInput{
		ScanID: scan.ScanID, Type: "api", Method: "POST", WithCtx: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(endpoints) == 0 || endpoints[0].Method != "POST" ||
		len(endpoints[0].BodyParams) != 2 {
		t.Fatalf("POST endpoints = %#v", endpoints)
	}

	sensitive, err := store.Sensitive(SensitiveInput{
		ScanID: scan.ScanID, MinSeverity: "high",
	})
	if err != nil || len(sensitive) == 0 || sensitive[0].Value == "" {
		t.Fatalf("sensitive = %#v, err %v", sensitive, err)
	}

	parameters, err := store.Parameters(ParametersInput{ScanID: scan.ScanID})
	if err != nil || len(parameters) == 0 || parameters[0].Name != "page" {
		t.Fatalf("parameters = %#v, err %v", parameters, err)
	}

	// The local scan has no SPA routes; the tool must return an empty list,
	// not an error.
	routes, err := store.Routes(RoutesInput{ScanID: scan.ScanID})
	if err != nil || len(routes) != 0 {
		t.Fatalf("routes = %#v, err %v", routes, err)
	}
}

func TestDispatchRoundTrip(t *testing.T) {
	store, scan := newTestStore(t)

	response := store.Dispatch(context.Background(), []byte(
		`{"tool":"endpoints","arguments":{"scan_id":"`+scan.ScanID+`","type":"api","limit":10}}`,
	))
	var envelope Response
	if err := json.Unmarshal(response, &envelope); err != nil {
		t.Fatal(err)
	}
	if !envelope.OK || !strings.Contains(string(envelope.Result), `"url"`) {
		t.Fatalf("dispatch response = %s", response)
	}

	response = store.Dispatch(context.Background(), []byte(`{"tool":"scans"}`))
	if !strings.Contains(string(response), scan.ScanID) {
		t.Fatalf("scans response = %s", response)
	}

	response = store.Dispatch(context.Background(), []byte(`{"tool":"nope"}`))
	if !strings.Contains(string(response), "unknown tool") {
		t.Fatalf("unknown tool response = %s", response)
	}

	response = store.Dispatch(context.Background(), []byte(
		`{"tool":"endpoints","arguments":{"scan_id":"`+scan.ScanID+`","bogus":1}}`,
	))
	if !strings.Contains(string(response), "decode arguments") {
		t.Fatalf("unknown field response = %s", response)
	}

	response = store.Dispatch(context.Background(), []byte(`{bad json`))
	if !strings.Contains(string(response), "decode request") {
		t.Fatalf("bad json response = %s", response)
	}

	response = store.Dispatch(context.Background(), []byte(
		`{"tool":"endpoints","arguments":{"scan_id":"missing"}}`,
	))
	if !strings.Contains(string(response), "unknown scan_id") {
		t.Fatalf("unknown scan response = %s", response)
	}
}
