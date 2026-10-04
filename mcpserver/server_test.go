package mcpserver

import (
	"context"
	"encoding/json"
	"net"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/youmulijiang/jsowl"
)

func sampleResult() *jsowl.Result {
	return &jsowl.Result{
		Target: "https://example.test",
		Mode:   jsowl.ModeAuto,
		Endpoints: []jsowl.Endpoint{
			{
				Raw: "/api/users", URL: "https://example.test/api/users?id=1",
				SourceURL: "https://example.test/app.js", Authorized: true,
				Method: "POST", Evidence: jsowl.EvidenceRuntime,
				Line: 42, Column: 9,
				ContextLines: []jsowl.ContextLine{
					{LineNumber: 41, Content: "const api = client;", MatchStart: -1, MatchEnd: -1},
					{LineNumber: 42, Content: "client.post(\"/api/users\", body)", MatchStart: 0, MatchEnd: 31},
				},
			},
			{
				Raw: "/v2/order", URL: "https://api.example.test/v2/order",
				SourceURL: "https://example.test/app.js", Authorized: false,
				Method: "GET", Evidence: jsowl.EvidenceFullURL,
				Line: 7, Column: 2,
			},
			{
				Raw: "/static/app.js", URL: "https://example.test/static/app.js",
				SourceURL: "https://example.test/index.html", Authorized: true,
				Evidence: jsowl.EvidenceStatic,
			},
		},
		Findings: []jsowl.Finding{
			{
				RuleID: "secret.token", RuleName: "Token",
				Category: jsowl.RuleCategorySensitive, Severity: jsowl.SeverityHigh,
				Value: "sk-live-123", SourceURL: "https://example.test/app.js", Line: 12,
			},
			{
				RuleID: "report.url.http", RuleName: "HTTP URL",
				Category: jsowl.RuleCategoryURL, Severity: jsowl.SeverityInfo,
				Value: "http://example.test/", SourceURL: "https://example.test/app.js", Line: 15,
			},
		},
	}
}

func TestServerListsAndCallsTools(t *testing.T) {
	store := NewStore(t.TempDir(), nil)
	id := store.put(sampleResult())

	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	server := store.Server()
	serverCtx, cancelServer := context.WithCancel(context.Background())
	defer cancelServer()
	go server.Run(serverCtx, serverTransport)

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0"}, nil)
	session, err := client.Connect(context.Background(), clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	tools, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, tool := range tools.Tools {
		names[tool.Name] = true
	}
	for _, want := range []string{"jsowl_scan", "jsowl_endpoints", "jsowl_sensitive", "jsowl_parameters"} {
		if !names[want] {
			t.Fatalf("tool %s missing from %v", want, names)
		}
	}

	endpoints := callTool[[]endpointRow](t, session, "jsowl_endpoints", map[string]any{
		"scan_id": id, "evidence": "runtime", "with_context": true,
	})
	if len(endpoints) != 1 || endpoints[0].Method != "POST" || endpoints[0].Line != 42 {
		t.Fatalf("runtime endpoints = %+v", endpoints)
	}
	if len(endpoints[0].Context) != 2 || endpoints[0].Context[0] != "  41 | const api = client;" {
		t.Fatalf("context = %+v", endpoints[0].Context)
	}

	sensitive := callTool[[]sensitiveRow](t, session, "jsowl_sensitive", map[string]any{
		"scan_id": id, "min_severity": "high",
	})
	if len(sensitive) != 1 || sensitive[0].Value != "sk-live-123" {
		t.Fatalf("sensitive rows = %+v", sensitive)
	}

	parameters := callTool[[]parameterRowOut](t, session, "jsowl_parameters", map[string]any{"scan_id": id})
	if len(parameters) != 1 || parameters[0].Name != "id" {
		t.Fatalf("parameter rows = %+v", parameters)
	}

	missing, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "jsowl_endpoints", Arguments: map[string]any{"scan_id": "missing"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !missing.IsError {
		t.Fatal("unknown scan_id should produce an error result")
	}
}

// callTool invokes a tool and decodes its structured output.
func callTool[Out any](t *testing.T, session *mcp.ClientSession, name string, args map[string]any) Out {
	t.Helper()
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: name, Arguments: args,
	})
	if err != nil {
		t.Fatalf("call %s: %v", name, err)
	}
	if result.IsError {
		t.Fatalf("call %s returned error content: %+v", name, result.Content)
	}
	var out Out
	data, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("decode %s output %s: %v", name, data, err)
	}
	return out
}

func TestServeHTTPTools(t *testing.T) {
	store := NewStore(t.TempDir(), nil)
	id := store.put(sampleResult())

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveDone := make(chan error, 1)
	go func() { serveDone <- store.Serve(ctx, listener) }()

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0"}, nil)
	transport := &mcp.StreamableClientTransport{
		Endpoint: "http://" + listener.Addr().String(),
	}
	session, err := client.Connect(context.Background(), transport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	endpoints := callTool[[]endpointRow](t, session, "jsowl_endpoints", map[string]any{
		"scan_id": id, "evidence": "full-url",
	})
	if len(endpoints) != 1 || endpoints[0].Method != "GET" {
		t.Fatalf("full-url endpoints = %+v", endpoints)
	}

	cancel()
	if err := <-serveDone; err != nil {
		t.Fatalf("Serve: %v", err)
	}
}
