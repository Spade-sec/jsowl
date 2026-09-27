package discover

import (
	"net/url"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/youmulijiang/jsowl/internal/analyze"

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
		fetch(`+"`"+`/inline/${id}/detail`+"`"+`);
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
	if static == nil || static.Spec == nil || static.Spec.BaseURL != "https://api.example.com" ||
		static.Spec.BaseURLKind != model.EvidenceLiteral {
		t.Fatalf("static endpoint spec should carry literal baseURL: %+v", static)
	}
	if gateway.Spec == nil || gateway.Spec.BaseURL != "https://gw.example.test/v2" ||
		gateway.Spec.BaseURLKind != model.EvidenceLiteral {
		t.Fatalf("gateway spec should carry its baseURL: %+v", gateway)
	}
}

func TestAPIFromASTCapturesContextLines(t *testing.T) {
	candidates := astCandidates(t, "// lead line 1\n// lead line 2\n// lead line 3\nfetch(\"/api/context\");\n// tail line 1\n// tail line 2\n// tail line 3\n// tail line 4\n")
	got := findCandidate(candidates, "/api/context")
	if got == nil {
		t.Fatalf("candidate missing in %v", candidates)
	}
	if len(got.ContextLines) != 5 {
		t.Fatalf("context lines = %d, want 5", len(got.ContextLines))
	}
	if got.ContextLines[0].LineNumber != 2 ||
		got.ContextLines[4].LineNumber != 6 {
		t.Fatalf("context range = %d..%d", got.ContextLines[0].LineNumber, got.ContextLines[4].LineNumber)
	}
	if got.ContextLines[2].MatchStart < 0 {
		t.Fatalf("matched line not marked: %+v", got.ContextLines[2])
	}
	if !strings.Contains(got.ContextLines[1].Content, "lead line 3") {
		t.Fatalf("unexpected context content: %+v", got.ContextLines)
	}
}

// A minified bundle keeps everything on one physical line; the context must
// be trimmed around the call instead of dragging the whole file in.
func TestAPIFromASTTrimsMinifiedSingleLineContext(t *testing.T) {
	source := strings.Repeat("var x=1;", 300) +
		`fetch("/api/minified");` +
		strings.Repeat("var y=2;", 300)
	candidates := astCandidates(t, source)
	got := findCandidate(candidates, "/api/minified")
	if got == nil {
		t.Fatalf("candidate missing in %v", candidates)
	}
	if len(got.ContextLines) != 1 {
		t.Fatalf("context lines = %d, want 1", len(got.ContextLines))
	}
	line := got.ContextLines[0]
	runes := utf8.RuneCountInString(line.Content)
	if runes > 402 {
		t.Fatalf("context line = %d runes, want <= 402", runes)
	}
	if !strings.HasPrefix(line.Content, "…") {
		t.Fatalf("trimmed line should start with ellipsis: %q", line.Content[:8])
	}
	if line.MatchStart < 0 || line.MatchEnd <= line.MatchStart {
		t.Fatalf("match window = [%d,%d]", line.MatchStart, line.MatchEnd)
	}
}

func TestAPIFromASTExtractsBodyParameters(t *testing.T) {
	candidates := astCandidates(t, `
		axios.post("/login", {username, password});
		axios.put("/users/" + id, {nickname: name, avatar: url});
		axios.request({url: "/orders", method: "POST", data: {sku: sku, count: n}});
		fetch("/api/notes", {method: "POST", body: JSON.stringify({title, content})});
		axios.get("/users/list");
	`)
	login := findCandidate(candidates, "/login")
	if login == nil {
		t.Fatalf("missing /login in %v", candidates)
	}
	if strings.Join(login.BodyParams, ",") != "username,password" {
		t.Fatalf("login body params = %v", login.BodyParams)
	}
	update := findCandidate(candidates, "/users/{}")
	if update == nil {
		t.Fatalf("missing put concat URL in %v", candidates)
	}
	if strings.Join(update.BodyParams, ",") != "nickname,avatar" {
		t.Fatalf("put body params = %v", update.BodyParams)
	}
	orders := findCandidate(candidates, "/orders")
	if orders == nil || strings.Join(orders.BodyParams, ",") != "sku,count" {
		t.Fatalf("request data params = %+v", orders)
	}
	notes := findCandidate(candidates, "/api/notes")
	if notes == nil {
		t.Fatalf("missing fetch notes in %v", candidates)
	}
	if strings.Join(notes.BodyParams, ",") != "title,content" {
		t.Fatalf("fetch body params = %v", notes.BodyParams)
	}
	if get := findCandidate(candidates, "/users/list"); len(get.BodyParams) != 0 {
		t.Fatalf("GET should have no body params: %v", get.BodyParams)
	}
}

func TestAPIFromASTDecodesUnicodeStrings(t *testing.T) {
	candidates := astCandidates(t, `
		fetch("/api/用户");
		fetch("/emoji/\uD83D\uDE00");
		const 路径 = "/接口/详情";
		axios.get(路径);
		fetch(`+"`"+`/模板/${id}/\u8BE6\u60C5`+"`"+`);
	`)
	for _, raw := range []string{"/api/用户", "/emoji/😀", "/接口/详情", "/模板/{}/详情"} {
		if findCandidate(candidates, raw) == nil {
			t.Errorf("missing decoded Unicode candidate %q in %v", raw, candidates)
		}
	}
}

func TestAPIFromASTRecoversAroundSyntaxErrors(t *testing.T) {
	candidates := astCandidates(t, `
		fetch("/api/before-error");
		const broken = ;
		axios.get("/api/after-error");
	`)
	if findCandidate(candidates, "/api/before-error") == nil ||
		findCandidate(candidates, "/api/after-error") == nil {
		t.Fatalf("Tree-sitter did not recover valid calls: %v", candidates)
	}
}

func TestReactRouterRulesClassifyRoutes(t *testing.T) {
	source, _ := url.Parse("https://example.test/routes.js")
	engine, err := analyze.New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`createBrowserRouter([{path:"/react/dashboard",element:1},{path:"/react/settings",element:2}]);`)
	result := FromJavaScript(source, body, engine)
	routes := []string{}
	for _, candidate := range result.Candidates {
		if candidate.Kind == KindRoute {
			routes = append(routes, candidate.Raw)
		}
	}
	if len(routes) != 2 {
		t.Fatalf("react routes = %v", routes)
	}
}

func TestAPIFromASTFoldsConcatAndJoinURLs(t *testing.T) {
	candidates := astCandidates(t, `
		const base = "/api/v2/";
		fetch(base.concat("users/list"));
		fetch(["/api/v2/orders/", "detail"].join(""));
		fetch(base.concat(id));
	`)
	if len(candidates) == 0 {
		t.Fatal("no candidates extracted")
	}
	want := map[string]bool{
		"/api/v2/users/list":    false,
		"/api/v2/orders/detail": false,
		"/api/v2/{}":            false,
	}
	for _, candidate := range candidates {
		if _, ok := want[candidate.Raw]; ok {
			want[candidate.Raw] = true
		}
	}
	for raw, seen := range want {
		if !seen {
			t.Errorf("candidate %q missing; got %v", raw, candidates)
		}
	}
}

func findParam(params []model.Param, key string) *model.Param {
	for i := range params {
		if params[i].Key == key {
			return &params[i]
		}
	}
	return nil
}

func TestAPIFromASTSpecValuesAndEvidence(t *testing.T) {
	candidates := astCandidates(t, `
		const API_HOST = "https://api.test";
		axios.post("/login", {username: "admin", count: 3, active: true, scope: API_HOST, tenant: tenantID, page: "p-" + n});
	`)
	login := findCandidate(candidates, "/login")
	if login == nil || login.Spec == nil {
		t.Fatalf("missing /login spec in %v", candidates)
	}
	cases := []struct {
		key, value, evidence string
	}{
		{"username", "admin", model.EvidenceLiteral},
		{"count", "3", model.EvidenceLiteral},
		{"active", "true", model.EvidenceLiteral},
		{"scope", "https://api.test", model.EvidenceConstant},
		{"tenant", "{tenantID}", model.EvidencePlaceholder},
		{"page", "p-{}", model.EvidencePlaceholder},
	}
	for _, want := range cases {
		param := findParam(login.Spec.Body, want.key)
		if param == nil {
			t.Fatalf("missing body param %q in %+v", want.key, login.Spec.Body)
		}
		if param.Value != want.value || param.Evidence != want.evidence {
			t.Fatalf("param %q = %q/%q, want %q/%q", want.key,
				param.Value, param.Evidence, want.value, want.evidence)
		}
	}
}

func TestAPIFromASTSpecContentType(t *testing.T) {
	candidates := astCandidates(t, `
		axios.post("/json", {a: 1}, {headers: {"Content-Type": "application/json;charset=utf-8"}});
		fetch("/form", {method: "POST", body: new FormData()});
		$.ajax({url: "/legacy", contentType: "application/xml", data: {x: 1}});
		fetch("/query?page=1");
		axios.post("/stringify", JSON.stringify({b: 2}));
	`)
	jsonPost := findCandidate(candidates, "/json")
	if jsonPost == nil || jsonPost.Spec == nil ||
		jsonPost.Spec.ContentType != "application/json;charset=utf-8" ||
		jsonPost.Spec.ContentTypeEvidence != model.EvidenceLiteral {
		t.Fatalf("json post spec = %+v", jsonPost)
	}
	form := findCandidate(candidates, "/form")
	if form == nil || form.Spec == nil ||
		form.Spec.ContentType != "multipart/form-data" ||
		form.Spec.ContentTypeEvidence != model.EvidenceInferred {
		t.Fatalf("form spec = %+v", form)
	}
	legacy := findCandidate(candidates, "/legacy")
	if legacy == nil || legacy.Spec == nil || legacy.Spec.ContentType != "application/xml" {
		t.Fatalf("legacy spec = %+v", legacy)
	}
	stringify := findCandidate(candidates, "/stringify")
	if stringify == nil || stringify.Spec == nil ||
		stringify.Spec.ContentType != "application/json" ||
		stringify.Spec.ContentTypeEvidence != model.EvidenceInferred {
		t.Fatalf("stringify spec = %+v", stringify)
	}
	if get := findCandidate(candidates, "/query"); get != nil && get.Spec != nil && get.Spec.ContentType != "" {
		t.Fatalf("GET should carry no content type: %+v", get.Spec)
	}
}

func TestAPIFromASTSpecQueryAndNestedFlattening(t *testing.T) {
	candidates := astCandidates(t, `
		axios.get("/search", {params: {keyword: "js", page: 1, filter: {size: 10, order: "desc"}}});
	`)
	search := findCandidate(candidates, "/search")
	if search == nil || search.Spec == nil {
		t.Fatalf("missing /search spec in %v", candidates)
	}
	if len(search.Spec.Body) != 0 {
		t.Fatalf("params should land in Query, got body %+v", search.Spec.Body)
	}
	cases := map[string]string{
		"keyword":      "js",
		"page":         "1",
		"filter.size":  "10",
		"filter.order": "desc",
	}
	for key, want := range cases {
		param := findParam(search.Spec.Query, key)
		if param == nil || param.Value != want {
			t.Fatalf("query %q = %+v, want value %q", key, param, want)
		}
	}
}

func TestAPIFromASTKeepsSpecVariantsOfSamePath(t *testing.T) {
	candidates := astCandidates(t, `
		axios.post("/upload", JSON.stringify({a: 1}));
		axios.post("/upload", new FormData());
	`)
	jsonVariant, formVariant := 0, 0
	for _, candidate := range candidates {
		if candidate.Raw != "/upload" || candidate.Spec == nil {
			continue
		}
		switch candidate.Spec.ContentType {
		case "application/json":
			jsonVariant++
		case "multipart/form-data":
			formVariant++
		}
	}
	if jsonVariant != 1 || formVariant != 1 {
		t.Fatalf("expected one JSON and one multipart variant, got %d/%d in %v",
			jsonVariant, formVariant, candidates)
	}
}

func TestAPIFromASTFoldsNewURLConstructor(t *testing.T) {
	candidates := astCandidates(t, `
		const base = "https://api.test/v2";
		fetch(new URL("/users", base).href);
		const u = new URL("/orders/list", "https://api.test");
		fetch(u.href);
	`)
	// A rooted path attaches to the base origin, matching new URL semantics.
	findCandidate(candidates, "https://api.test/users")
	findCandidate(candidates, "https://api.test/orders/list")
}

func TestAPIFromASTSplitsConditionalURLs(t *testing.T) {
	candidates := astCandidates(t, `fetch(flag ? "/api/preview" : "/api/live");`)
	findCandidate(candidates, "/api/preview")
	findCandidate(candidates, "/api/live")
}

func TestAPIFromASTResolvesObjectConstantMembers(t *testing.T) {
	candidates := astCandidates(t, `
		const routes = {users: "/u/list", orders: "/o/list"};
		fetch(routes.users);
		fetch(routes["orders"]);
	`)
	findCandidate(candidates, "/u/list")
	findCandidate(candidates, "/o/list")
}

func TestAPIFromASTFoldsReplaceAndAtob(t *testing.T) {
	candidates := astCandidates(t, `
		fetch("/api/v1/x".replace("v1", "v2"));
		fetch(atob("L2FwaS91c2Vycw=="));
	`)
	candidates2 := astCandidates(t, `fetch("/a".replace("a", "b"));`)
	findCandidate(candidates, "/api/v2/x")
	findCandidate(candidates, "/api/users")
	findCandidate(candidates2, "/b")
}

func TestAPIFromASTFlattensArrayParams(t *testing.T) {
	candidates := astCandidates(t, `
		axios.post("/batch", {items: [{id: 1, sku: "A"}, {id: 2}], tags: ["x"]});
		axios.post("/list", [{qid: 9, pass: true}]);
		axios.get("/page", {params: {filter: {ids: [7, 8]}}});
	`)
	batch := findCandidate(candidates, "/batch")
	if batch == nil || batch.Spec == nil {
		t.Fatalf("missing /batch spec in %v", candidates)
	}
	cases := []struct{ key, value, evidence, paramType string }{
		{"items[].id", "1", model.EvidenceLiteral, "数字"},
		{"items[].sku", "A", model.EvidenceLiteral, "字符串"},
		{"tags[]", "x", model.EvidenceLiteral, "字符串"},
	}
	for _, want := range cases {
		param := findParam(batch.Spec.Body, want.key)
		if param == nil || param.Value != want.value || param.Evidence != want.evidence {
			t.Fatalf("body %q = %+v, want %q/%q", want.key, param, want.value, want.evidence)
		}
	}
	// Duplicate field names across elements collapse into one row.
	if id := findParam(batch.Spec.Body, "items[].id"); id.Value != "1" {
		t.Fatalf("duplicate array keys should dedupe, got %+v", id)
	}
	list := findCandidate(candidates, "/list")
	if list == nil || list.Spec == nil {
		t.Fatalf("missing /list spec in %v", candidates)
	}
	for key, want := range map[string]string{"[].qid": "9", "[].pass": "true"} {
		param := findParam(list.Spec.Body, key)
		if param == nil || param.Value != want {
			t.Fatalf("top-level array %q = %+v, want %q", key, param, want)
		}
	}
	page := findCandidate(candidates, "/page")
	if page == nil || page.Spec == nil {
		t.Fatalf("missing /page spec in %v", candidates)
	}
	ids := findParam(page.Spec.Query, "filter.ids[]")
	if ids == nil || ids.Value != "7" || ids.Evidence != model.EvidenceLiteral {
		t.Fatalf("nested array in query params = %+v", ids)
	}
}

func TestAPIFromASTMarksDynamicPayload(t *testing.T) {
	candidates := astCandidates(t, `
		function P(t){return Object(r["a"])({url:"drug/submit",method:"post",data:t,headers:{"Content-Type":"application/json"}})}
		function Q(e){return axios.post("/wrap", e.payload)}
		P({orderId: 7, status: "A"});
	`)
	submit := findCandidate(candidates, "drug/submit")
	if submit == nil || submit.Spec == nil {
		t.Fatalf("missing drug/submit spec in %v", candidates)
	}
	// The wrapper's own call site yields a keyless placeholder: the axios
	// slot name ("data") is a config protocol name, not a wire field.
	var placeholder *model.Param
	for i := range submit.Spec.Body {
		if submit.Spec.Body[i].Evidence == model.EvidencePlaceholder {
			placeholder = &submit.Spec.Body[i]
		}
	}
	if placeholder == nil || placeholder.Key != "" || placeholder.Value != "{t}" {
		t.Fatalf("dynamic payload param = %+v", submit.Spec.Body)
	}
	// The caller pass resolves the forwarded literal into real field keys.
	var orderID *model.Param
	for i := range candidates {
		if candidates[i].Raw != "drug/submit" || candidates[i].Spec == nil {
			continue
		}
		for _, p := range candidates[i].Spec.Body {
			if p.Key == "orderId" {
				p := p
				orderID = &p
			}
		}
	}
	if orderID == nil || orderID.Value != "7" || orderID.Evidence != model.EvidenceLiteral {
		t.Fatalf("caller literal should recover orderId: %+v", submit.Spec.Body)
	}
	wrap := findCandidate(candidates, "/wrap")
	if wrap == nil || wrap.Spec == nil || len(wrap.Spec.Body) != 1 ||
		wrap.Spec.Body[0].Key != "" || wrap.Spec.Body[0].Value != "{e.payload}" {
		t.Fatalf("member payload param = %+v", wrap)
	}
}

func TestAPIFromASTURLSearchParamsBuilder(t *testing.T) {
	candidates := astCandidates(t, `
		function pt(t){
			var e = new URLSearchParams;
			e.append("loginName", t.loginName);
			e.append("password", t.password);
			e.append("code", "wx");
			e.append("uuid", t.uuid);
			return Object(r["a"])({url:l+"/applet/login",method:"post",data:e,headers:{"Content-Type":"application/x-www-form-urlencoded"}})
		}
	`)
	login := findCandidate(candidates, "{}/applet/login")
	if login == nil || login.Spec == nil {
		t.Fatalf("missing /applet/login spec in %v", candidates)
	}
	if login.Spec.ContentType != "application/x-www-form-urlencoded" {
		t.Fatalf("content type = %q", login.Spec.ContentType)
	}
	for key, want := range map[string]string{"loginName": "{t.loginName}", "password": "{t.password}", "code": "wx"} {
		got := findParam(login.Spec.Body, key)
		if got == nil || got.Value != want {
			t.Fatalf("param %q = %+v, want value %q", key, got, want)
		}
	}
}

func TestAPIFromASTWrapperCallerBacktrack(t *testing.T) {
	candidates := astCandidates(t, `
		function dt(t){return Object(r["a"])({url:l+"/user/upwd",method:"post",data:t})}
		function caller(){
			var form = {oldPwd: "a", newPwd: "b"};
			dt(form);
		}
	`)
	upwd := findCandidate(candidates, "{}/user/upwd")
	if upwd == nil || upwd.Spec == nil {
		t.Fatalf("missing /user/upwd spec in %v", candidates)
	}
	var oldPwd *model.Param
	for i := range candidates {
		if !strings.HasSuffix(candidates[i].Raw, "/user/upwd") || candidates[i].Spec == nil {
			continue
		}
		for _, p := range candidates[i].Spec.Body {
			if p.Key == "oldPwd" {
				p := p
				oldPwd = &p
			}
		}
	}
	if oldPwd == nil || oldPwd.Value != "a" || oldPwd.Evidence != model.EvidenceLiteral {
		t.Fatalf("wrapper caller should recover oldPwd")
	}
}

func TestAPIFromASTHeuristicMemberWrites(t *testing.T) {
	// gitee 形态：对象分步构造，键散落在成员赋值里
	candidates := astCandidates(t, `
		function notice(){
			var o = {scope: t};
			"messages" == t ? o.message_ids = n : o.noti_ids = n;
			$.ajax({url: "/notifications/mark_dropdown", data: o, type: "PUT"});
		}
	`)
	mark := findCandidate(candidates, "/notifications/mark_dropdown")
	if mark == nil || mark.Spec == nil {
		t.Fatalf("missing mark_dropdown spec in %v", candidates)
	}
	// 原 call 保留占位符变体；启发式变体带真实键
	var variant *Candidate
	for i := range candidates {
		if candidates[i].Raw == "/notifications/mark_dropdown" && candidates[i].Spec != nil &&
			len(candidates[i].Spec.Body) >= 2 {
			variant = &candidates[i]
		}
	}
	if variant == nil {
		t.Fatalf("heuristic variant with real keys missing; candidates=%d", len(candidates))
	}
	for key, value := range map[string]string{"scope": "{t}", "message_ids": "{n}", "noti_ids": "{n}"} {
		got := findParam(variant.Spec.Body, key)
		if got == nil || got.Value != value {
			t.Fatalf("heuristic key %q = %+v, want %q", key, got, value)
		}
	}
}

func TestAPIFromASTHeuristicScopeIsolation(t *testing.T) {
	// 同名对象 o 在两个函数里分别构造 —— 键不得串
	candidates := astCandidates(t, `
		function sendA(){
			var o = {onlyA: 1};
			$.ajax({url: "/a", data: o, type: "POST"});
		}
		function sendB(){
			var o = {onlyB: 2};
			$.ajax({url: "/b", data: o, type: "POST"});
		}
	`)
	for raw, key := range map[string]string{"/a": "onlyA", "/b": "onlyB"} {
		var variant *Candidate
		for i := range candidates {
			if candidates[i].Raw == raw && candidates[i].Spec != nil && findParam(candidates[i].Spec.Body, key) != nil {
				variant = &candidates[i]
			}
		}
		if variant == nil {
			t.Fatalf("%s heuristic key %q missing", raw, key)
		}
		other := "onlyB"
		if key == "onlyB" {
			other = "onlyA"
		}
		if findParam(variant.Spec.Body, other) != nil {
			t.Fatalf("%s leaked key %q from the other scope", raw, other)
		}
	}
}

func TestAPIFromASTTaintUpstream(t *testing.T) {
	candidates := astCandidates(t, `
		function load(){ return Object(r["a"])({url:"/drug/list",method:"get"}) }
		function run(){
			load().then(function(res){
				axios.post("/drug/submit", res.data);
			});
		}
	`)
	submit := findCandidate(candidates, "/drug/submit")
	if submit == nil || submit.Spec == nil || len(submit.Spec.Body) != 1 {
		t.Fatalf("missing /drug/submit placeholder: %+v", submit)
	}
	ta := submit.Spec.Body[0].Taint
	if ta == nil || ta.Kind != model.TaintUpstream || ta.Upstream != "/drug/list" || ta.UpstreamField != "data" {
		t.Fatalf("upstream taint = %+v", ta)
	}
}

func TestAPIFromASTTaintStorage(t *testing.T) {
	candidates := astCandidates(t, `
		function send(){
			var org = sessionStorage.getItem("orgCode");
			axios.post("/dep/list", org);
		}
	`)
	list := findCandidate(candidates, "/dep/list")
	if list == nil || list.Spec == nil || len(list.Spec.Body) != 1 {
		t.Fatalf("missing /dep/list: %+v", list)
	}
	ta := list.Spec.Body[0].Taint
	if ta == nil || ta.Kind != model.TaintStorage {
		t.Fatalf("storage taint = %+v", ta)
	}
}

func TestAPIFromASTTaintUnknownCrossFunction(t *testing.T) {
	candidates := astCandidates(t, `
		function makePayload(){ return {a: 1}; }
		function send(){
			var p = makePayload();
			axios.post("/x", p);
		}
	`)
	x := findCandidate(candidates, "/x")
	if x == nil || x.Spec == nil || len(x.Spec.Body) != 1 {
		t.Fatalf("missing /x: %+v", x)
	}
	ta := x.Spec.Body[0].Taint
	if ta == nil || ta.Kind != model.TaintUnknown {
		t.Fatalf("cross-function taint must stay unknown: %+v", ta)
	}
}
