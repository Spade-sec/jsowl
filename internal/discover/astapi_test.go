package discover

import (
	"net/url"
	"testing"

	"github.com/youmulijiang/jsowl/internal/model"
)

func astCandidates(t *testing.T, code string) []Candidate {
	t.Helper()
	source, err := url.Parse("https://example.test/app.js")
	if err != nil {
		t.Fatal(err)
	}
	return APIFromAST(source, []byte(code))
}

func findCandidate(candidates []Candidate, raw string) *Candidate {
	for i := range candidates {
		if candidates[i].Raw == raw {
			return &candidates[i]
		}
	}
	return nil
}

func TestAPIFromASTExtractsCallSites(t *testing.T) {
	candidates := astCandidates(t, `
		fetch("/api/session");
		fetch("/api/items?page=2", {method: "POST"});
		axios.get("/users/list");
		axios.post("/users/create", {name: "x"});
		axios.request({url: "/users/detail", method: "PUT"});
		$.ajax({url: "/legacy/endpoint", type: "DELETE"});
		xhr.open("put", "/users/update");
	`)
	if len(candidates) == 0 {
		t.Fatal("no candidates extracted")
	}
	cases := []struct {
		raw    string
		method string
	}{
		{"/api/session", "GET"},
		{"/api/items?page=2", "POST"},
		{"/users/list", "GET"},
		{"/users/create", "POST"},
		{"/users/detail", "PUT"},
		{"/legacy/endpoint", "DELETE"},
		{"/users/update", "PUT"},
	}
	for _, want := range cases {
		got := findCandidate(candidates, want.raw)
		if got == nil {
			t.Fatalf("missing candidate %q in %v", want.raw, candidates)
		}
		if got.Method != want.method {
			t.Errorf("%s method = %q, want %q", want.raw, got.Method, want.method)
		}
		if got.Evidence != model.EvidenceStatic {
			t.Errorf("%s evidence = %q, want static", want.raw, got.Evidence)
		}
		if got.Line <= 0 || got.Column <= 0 {
			t.Errorf("%s position = %d:%d", want.raw, got.Line, got.Column)
		}
	}
}

func TestAPIFromASTResolvesConstantsAndTemplates(t *testing.T) {
	candidates := astCandidates(t, `
		const BASE = "https://api.example.test";
		let suffix = "/v2";
		const client = axios.create({baseURL: BASE});
		client.get(suffix + "/users/" + id);
		var legacy = "https://legacy.example.test/rpc";
		fetch(legacy);
		fetch(` + "`" + `/inline/${id}/detail` + "`" + `);
	`)
	full := findCandidate(candidates, "https://legacy.example.test/rpc")
	if full == nil {
		t.Fatalf("missing full-url candidate in %v", candidates)
	}
	if full.Evidence != model.EvidenceFullURL {
		t.Errorf("legacy evidence = %q", full.Evidence)
	}
	joined := findCandidate(candidates, "/v2/users/{}")
	if joined == nil {
		t.Fatalf("missing folded concat candidate in %v", candidates)
	}
	template := findCandidate(candidates, "/inline/{}/detail")
	if template == nil {
		t.Fatalf("missing template candidate in %v", candidates)
	}
	if template.Evidence != model.EvidenceStatic {
		t.Errorf("template evidence = %q", template.Evidence)
	}
}

func TestAPIFromASTSkipsInvalidInput(t *testing.T) {
	candidates := astCandidates(t, "this is }}} not javascript")
	if len(candidates) != 0 {
		t.Fatalf("invalid input produced %v", candidates)
	}
}

func TestAPIFromASTSurvivesDegenerateNodes(t *testing.T) {
	candidates := astCandidates(t, `
		function f() {}
		;
		;;;
		if (ready) { fetch("/api/ready"); } else ;
		for (;;) { break; }
		do ; while (0);
		switch (x) { case 1: fetch("/api/one"); }
		try { fetch("/api/try"); } catch { } finally { }
		label: for (const k in obj) { axios.get("/api/" + k); }
		class A { static x = "/api/static"; run() { return fetch("/api/method"); } }
		new Worker("/worker.js");
	`)
	if findCandidate(candidates, "/api/ready") == nil ||
		findCandidate(candidates, "/api/method") == nil {
		t.Fatalf("missing candidates in %v", candidates)
	}
}

func TestAPIFromASTKeepsStaticAndAddsBaseURLFold(t *testing.T) {
	candidates := astCandidates(t, `
		const http = axios.create({baseURL: "https://api.example.com"});
		http.get("/user/list");
		http.post("/user/add", form);
		client.defaults.baseURL = "https://gw.example.test/v2";
		client.request({url: "/order/detail", method: "PUT"});
	`)
	static := findCandidate(candidates, "/user/list")
	if static == nil || static.Evidence != model.EvidenceStatic {
		t.Fatalf("static endpoint missing or wrong: %v", candidates)
	}
	folded := findCandidate(candidates, "https://api.example.com/user/list")
	if folded == nil || folded.Evidence != model.EvidenceFullURL {
		t.Fatalf("folded full-url endpoint missing or wrong: %v", candidates)
	}
	if folded.Method != "GET" {
		t.Errorf("folded method = %q", folded.Method)
	}
	post := findCandidate(candidates, "https://api.example.com/user/add")
	if post == nil || post.Method != "POST" {
		t.Fatalf("folded POST missing: %v", candidates)
	}
	if findCandidate(candidates, "/user/add") == nil {
		t.Fatalf("static POST variant was dropped: %v", candidates)
	}
	gateway := findCandidate(candidates, "https://gw.example.test/v2/order/detail")
	if gateway == nil || gateway.Evidence != model.EvidenceFullURL {
		t.Fatalf("defaults.baseURL fold missing: %v", candidates)
	}
}
