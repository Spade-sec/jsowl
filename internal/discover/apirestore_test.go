package discover

import (
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/youmulijiang/jsowl/internal/model"
)

// apiRestoreFixtureDir is the counterexample fixture directory the manual
// verification entry (examples/api-restore-check) also reads. The regression
// turns every fixture into exact assertions over the AST analysis alone: no
// regex fallback runs on this path, so a pass cannot be the text scanner
// recovering the same string.
const apiRestoreFixtureDir = "../../testdata/api-restore-counterexamples"

func rawSet(candidates []Candidate) []string {
	set := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		set = append(set, candidate.Raw)
	}
	sort.Strings(set)
	return set
}

func requireExactCandidates(t *testing.T, candidates []Candidate, want ...string) {
	t.Helper()
	got := rawSet(candidates)
	sort.Strings(want)
	if len(got) != len(want) {
		t.Fatalf("candidates = %v, want exactly %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("candidates = %v, want exactly %v", got, want)
		}
	}
}

func requireMissing(t *testing.T, candidates []Candidate, wrong ...string) {
	t.Helper()
	got := rawSet(candidates)
	for _, bad := range wrong {
		for _, raw := range got {
			if raw == bad {
				t.Fatalf("wrong candidate %q must not survive; got %v", bad, got)
			}
		}
	}
}

func requireCandidate(t *testing.T, candidates []Candidate, raw string) {
	t.Helper()
	if findCandidate(candidates, raw) == nil {
		t.Fatalf("candidate %q missing; got %v", raw, rawSet(candidates))
	}
}

// TestAPIRestoreCounterexamples pins every counterexample fixture and the
// positive control to its exact AST result set. Expected values are the ones
// a JavaScript runtime captures for the same files (see
// testdata/api-restore-counterexamples/runtime-results.txt), except case 06:
// the runtime value /runtime is injected by the harness and unknowable
// statically, so the requirement is only that the stale constant is dead and
// the path suffix survives.
func TestAPIRestoreCounterexamples(t *testing.T) {
	cases := []struct {
		file string
		want []string
	}{
		{"01-template.js", []string{"/api/v1/users"}},
		{"02-initializer.js", []string{"/api/users"}},
		{"03-alias.js", []string{"/api/users"}},
		{"04-scope.js", []string{"/api/users"}},
		// Case 05 additionally keeps the dynamic {base}/users template, so it
		// is asserted separately below instead of an exact set.
		{"07-branch.js", []string{"/api/users", "/admin/users"}},
		{"08-member.js", []string{"/api/users"}},
		{"09-conditional.js", []string{"/api/orders", "/api/users"}},
		{"10-number.js", []string{"/api/v1/users"}},
		{"11-replace.js", []string{"/users/x"}},
		{"12-url.js", []string{"http://127.0.0.1:9/users"}},
		{"13-control.js", []string{"/api/users"}},
	}
	for _, testCase := range cases {
		t.Run(testCase.file, func(t *testing.T) {
			body, err := os.ReadFile(filepath.Join(apiRestoreFixtureDir, testCase.file))
			if err != nil {
				t.Fatal(err)
			}
			source, _ := url.Parse("file:///" + testCase.file)
			requireExactCandidates(t, APIFromAST(source, body), testCase.want...)
		})
	}
}

func apiRestoreFixture(t *testing.T, name string) []byte {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(apiRestoreFixtureDir, name))
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// Case 05: the direct call resolves the parameter to /tenant/users; the
// wrapper's own site keeps the honest dynamic template; the outer /api
// constant must never leak through the shadowed parameter.
func TestAPIRestoreParameterPropagation(t *testing.T) {
	candidates := apiRestoreCandidates(t, "05-parameter.js")
	requireCandidate(t, candidates, "/tenant/users")
	requireMissing(t, candidates, "/api/users")
	requireCandidate(t, candidates, "{base}/users")
}

// Case 06: the reassignment target is a runtime value. The old "/api"
// constant must be invalidated, and the known suffix must survive — but no
// candidate may pretend to know the runtime value.
func TestAPIRestoreInvalidatedConstant(t *testing.T) {
	candidates := apiRestoreCandidates(t, "06-invalidate.js")
	requireExactCandidates(t, candidates, "{}/users")
	requireMissing(t, candidates, "/api/users", "/runtime/users")
}

func apiRestoreCandidates(t *testing.T, name string) []Candidate {
	t.Helper()
	source, _ := url.Parse("file:///" + name)
	return APIFromAST(source, apiRestoreFixture(t, name))
}

// TestAPIRestoreScopingUnit pins the scoping and reassignment rules with
// focused sources: block shadowing, function-body isolation, straight-line
// reassignment and alias cycles must all behave per lexical semantics.
func TestAPIRestoreScopingUnit(t *testing.T) {
	cases := []struct {
		name string
		code string
		want []string
	}{
		{
			name: "block scope shadows without leaking",
			code: "const base = \"/api\";\n{ const base = \"/admin\"; }\nfetch(base + \"/users\");",
			want: []string{"/api/users"},
		},
		{
			name: "block-scoped let stays inside its block",
			// The inner fetch legitimately yields /hidden/y; the outer read
			// of tmp yields nothing (unbound at file scope).
			code: "fetch(\"/api/x\");\n{ let tmp = \"/hidden\"; fetch(tmp + \"/y\"); }\nfetch(tmp);",
			want: []string{"/api/x", "/hidden/y"},
		},
		{
			name: "function body assignment cannot poison later outer reads",
			code: "const base = \"/api\";\nfunction setup() { base = \"/admin\"; }\nfetch(base + \"/users\");",
			want: []string{"/api/users"},
		},
		{
			name: "same-name const inside a function shadows the outer one",
			code: "const base = \"/api\";\nfunction other() { const base = \"/admin\"; fetch(base + \"/h\"); }\nfetch(base + \"/users\");",
			want: []string{"/admin/h", "/api/users"},
		},
		{
			name: "straight-line reassignment replaces the value",
			code: "let base = \"/api\";\nbase = \"/v2\";\nfetch(base + \"/users\");",
			want: []string{"/v2/users"},
		},
		{
			name: "self-referencing reassignment folds incrementally",
			code: "let p = \"/api\";\np = p + \"/v2\";\nfetch(p + \"/users\");",
			want: []string{"/api/v2/users"},
		},
		{
			name: "alias cycle degrades without recursion blowup",
			// a is bound to b before b exists, so a stays unknown; the
			// unknown-call chain contributes nothing and nothing recurses.
			code: "let a = b;\nlet b = a;\nfetch(a + \"/users\");\nfetch(cycle(cycle(cycle(\"/ok\"))));",
			want: []string{"{}/users"},
		},
		{
			name: "deeply nested expression degrades past the depth budget",
			// 12 nested concatenations resolve; 30 exceed maxEvalDepth and
			// degrade instead of overflowing the stack.
			code: "fetch(\"/x\" + \"/1\" + \"/2\" + \"/3\" + \"/4\" + \"/5\" + \"/6\" + \"/7\" + \"/8\" + \"/9\" + \"/10\" + \"/11\" + \"/12\");\n" +
				"fetch(\"/y\" + \"/1\" + \"/2\" + \"/3\" + \"/4\" + \"/5\" + \"/6\" + \"/7\" + \"/8\" + \"/9\" + \"/10\" + \"/11\" + \"/12\" + \"/13\" + \"/14\" + \"/15\" + \"/16\" + \"/17\" + \"/18\" + \"/19\" + \"/20\" + \"/21\" + \"/22\" + \"/23\" + \"/24\" + \"/25\" + \"/26\" + \"/27\" + \"/28\" + \"/29\" + \"/30\");",
			want: []string{"/x/1/2/3/4/5/6/7/8/9/10/11/12"},
		},
		{
			name: "unknown branch test still yields both branch URLs",
			code: "fetch(unknownFn() ? \"/api/yes\" : \"/api/no\");",
			want: []string{"/api/no", "/api/yes"},
		},
		{
			name: "ternary assignment merges both candidates",
			code: "let base = flag ? \"/api\" : \"/admin\";\nfetch(base + \"/users\");",
			want: []string{"/admin/users", "/api/users"},
		},
		{
			name: "branch assignment after a valid init merges candidates",
			code: "let base = \"/api\";\nif (flag) { base = \"/admin\"; }\nfetch(base + \"/users\");",
			want: []string{"/admin/users", "/api/users"},
		},
		{
			name: "branch reassignment with an unknown value keeps uncertainty",
			code: "let base = \"/api\";\nif (flag) { base = runtimeBase(); }\nfetch(base + \"/users\");",
			want: []string{"/api/users", "{}/users"},
		},
		{
			name: "read before the branch does not see the branch write",
			code: "let base = \"/api\";\nfetch(base + \"/early\");\nif (flag) { base = \"/admin\"; }\nfetch(base + \"/late\");",
			want: []string{"/admin/late", "/api/early", "/api/late"},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			requireExactCandidates(t, astCandidates(t, testCase.code), testCase.want...)
		})
	}
}

// TestAPIRestoreCandidateCap proves the branch-candidate budget: a merge
// that would exceed it collapses to uncertainty instead of reporting an
// arbitrary subset, and the analysis still terminates on pathological input.
func TestAPIRestoreCandidateCap(t *testing.T) {
	branches := make([]string, 0, 16)
	for i := 0; i < 16; i++ {
		branches = append(branches, "\"/p"+string(rune('a'+i))+"\"")
	}
	code := "fetch(c0 ? " + strings.Join(branches, " : c? ") + " : \"/pz\");"
	candidates := astCandidates(t, code)
	if len(candidates) > maxEvalOptions {
		t.Fatalf("branch candidates = %d, must be capped at %d", len(candidates), maxEvalOptions)
	}
	requireMissing(t, candidates, "/pz")
}

// TestAPIRestoreArithmetic pins JavaScript "+" semantics: numeric addition
// between numbers, string concatenation anywhere a string participates.
func TestAPIRestoreArithmetic(t *testing.T) {
	cases := []struct {
		code string
		want []string
	}{
		{`fetch("/api/" + (1 + 2));`, []string{"/api/3"}},
		{`fetch("/api/" + 1 + 2);`, []string{"/api/12"}},
		{`fetch(2 + 3);`, nil},
		{`fetch("/api/v" + 2 + 0);`, []string{"/api/v20"}},
		{`const n = 4; fetch("/api/" + n);`, []string{"/api/4"}},
		{`fetch("/api/" + true);`, []string{"/api/true"}},
	}
	for _, testCase := range cases {
		t.Run(testCase.code, func(t *testing.T) {
			candidates := astCandidates(t, testCase.code)
			if len(testCase.want) == 0 {
				requireExactCandidates(t, candidates)
				return
			}
			requireExactCandidates(t, candidates, testCase.want...)
		})
	}
}

// TestAPIRestoreURLReferenceSemantics pins new URL reference resolution:
// trailing-slash bases, root paths, ".." collapse, query and fragment
// references, and the absolute-URL override.
func TestAPIRestoreURLReferenceSemantics(t *testing.T) {
	cases := []struct {
		code string
		want []string
	}{
		{`fetch(new URL("users", "http://h:9/api").href);`, []string{"http://h:9/users"}},
		{`fetch(new URL("users", "http://h:9/api/").href);`, []string{"http://h:9/api/users"}},
		{`fetch(new URL("/root", "http://h:9/api").href);`, []string{"http://h:9/root"}},
		{`fetch(new URL("../up", "http://h:9/a/b/c").href);`, []string{"http://h:9/a/up"}},
		{`fetch(new URL("?page=2", "http://h:9/api").href);`, []string{"http://h:9/api?page=2"}},
		{`fetch(new URL("#frag", "http://h:9/api").href);`, []string{"http://h:9/api#frag"}},
		{`fetch(new URL("http://other/x", "http://h:9/api").href);`, []string{"http://other/x"}},
		{`fetch(new URL("users", "http://h:9/api").href + "/tail");`, []string{
			// The construction itself and its concatenated use are both
			// legitimate candidates.
			"http://h:9/users", "http://h:9/users/tail",
		}},
	}
	for _, testCase := range cases {
		t.Run(testCase.code, func(t *testing.T) {
			requireExactCandidates(t, astCandidates(t, testCase.code), testCase.want...)
		})
	}
}

// TestAPIRestoreReplaceSemantics pins first-hit replace vs replaceAll, and
// that unsupported patterns degrade instead of fabricating exact results.
func TestAPIRestoreReplaceSemantics(t *testing.T) {
	cases := []struct {
		name string
		code string
		want []string
	}{
		{"first occurrence only", `fetch("/x/x".replace("x", "users"));`, []string{"/users/x"}},
		{"all occurrences", `fetch("/x/x".replaceAll("x", "users"));`, []string{"/users/users"}},
		{"chained replace", `fetch("/api/v1/x".replace("v1", "v2"));`, []string{"/api/v2/x"}},
		{"regex pattern degrades", `fetch("/x/x".replace(/x/g, "users"));`, nil},
		{"dollar replacement degrades", `fetch("/x".replace("x", "$&y"));`, nil},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			candidates := astCandidates(t, testCase.code)
			if len(testCase.want) == 0 {
				requireExactCandidates(t, candidates)
				return
			}
			requireExactCandidates(t, candidates, testCase.want...)
		})
	}
}

// TestAPIRestoreWrapperParameterBoundaries pins the wrapper URL-propagation
// boundary: a reliably recognized direct call resolves the argument; an
// unresolvable argument keeps the dynamic template and never adopts the
// enclosing scope's constant.
func TestAPIRestoreWrapperParameterBoundaries(t *testing.T) {
	t.Run("unresolvable argument keeps dynamic path", func(t *testing.T) {
		candidates := astCandidates(t, `
			const base = "/api";
			function load(base) { fetch(base + "/users"); }
			load(pickTenant());
		`)
		requireCandidate(t, candidates, "{base}/users")
		requireMissing(t, candidates, "/api/users")
	})
	t.Run("concatenated literal argument resolves", func(t *testing.T) {
		candidates := astCandidates(t, `
			function load(base) { fetch(base + "/users"); }
			load("/tenant" + "/acme");
		`)
		requireCandidate(t, candidates, "/tenant/acme/users")
	})
	t.Run("body-forwarding wrapper is unaffected", func(t *testing.T) {
		candidates := astCandidates(t, `
			function P(t){return fetch("/save", {method: "POST", body: t})}
			P({orderId: 7});
		`)
		// The wrapper's own site keeps the keyless {t} placeholder; the
		// caller variant must carry the real field key.
		found := false
		for i := range candidates {
			if candidates[i].Raw != "/save" || candidates[i].Spec == nil {
				continue
			}
			if param := findParam(candidates[i].Spec.Body, "orderId"); param != nil &&
				param.Value == "7" && param.Evidence == model.EvidenceLiteral {
				found = true
			}
		}
		if !found {
			t.Fatalf("body forwarding broken: %+v", candidates)
		}
	})
}
