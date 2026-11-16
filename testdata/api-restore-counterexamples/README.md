# API restoration counterexamples

Each numbered JS file is analyzed independently so bindings cannot leak between cases.
The fixtures and the Node runtime baseline below predate the 2026-11 restoration
fix in `internal/discover/astapi.go`; the fix changed the analysis, and this
directory keeps both the pre-fix and post-fix AST outputs for comparison.

## Reproduce

Run from the repository root:

```powershell
node examples/api-restore-check/check-runtime.cjs
go run ./examples/api-restore-check
go test ./internal/discover -run TestAPIRestore
go run ./cmd/jsowl --location ./testdata/api-restore-counterexamples -o ./testdata/api-restore-counterexamples-output
```

The Node runner captures fetch arguments without network access. It supplies
`getRuntimeBase() = "/runtime"` and executes both values of `flag`.
These executions establish concrete results for the supplied environments,
not an exhaustive specification of all possible runtime inputs.
The Go runner invokes `discover.APIFromAST` (signature unchanged; internals
rebuilt on the scoped, bounded evaluator).
The CLI may probe the loopback URL in case 12; it never needs a public target.

## Observed results

The table records the pre-fix and post-fix comparison. Run the commands above
to reproduce current AST and runtime results. Generated reports and raw output
files are kept locally and excluded from version control.

| Case | Captured JavaScript fetch URL(s) | AST before fix | AST after fix |
|---|---|---|---|
| 01 template constant | `/api/v1/users` | `/api/{}/users` | `/api/v1/users` |
| 02 concatenation initializer | `/api/users` | none | `/api/users` |
| 03 variable alias | `/api/users` | none | `/api/users` |
| 04 inner scope contamination | `/api/users` | `/admin/users` | `/api/users` |
| 05 parameter shadowing | `/tenant/users` | `/api/users` | `/tenant/users` (+ dynamic `{base}/users` template) |
| 06 unknown reassignment | `/runtime/users` | `/api/users` | `{}/users` (runtime value unknowable; stale constant invalidated, suffix kept) |
| 07 conditional assignment | `/api/users`, `/admin/users` | `/admin/users` only | `/api/users`, `/admin/users` |
| 08 member inside concatenation | `/api/users` | none | `/api/users` |
| 09 conditional inside concatenation | `/api/users`, `/api/orders` | none | `/api/users`, `/api/orders` |
| 10 numeric concatenation | `/api/v1/users` | none | `/api/v1/users` |
| 11 replace first occurrence | `/users/x` | `/users/users` | `/users/x` |
| 12 URL base resolution | `http://127.0.0.1:9/users` | `http://127.0.0.1:9/api/users` | `http://127.0.0.1:9/users` |
| 13 positive control | `/api/users` | `/api/users` | `/api/users` |

The fixture set is now pinned as automated regression tests with exact
positive and negative assertions in `internal/discover/apirestore_test.go`;
they call the AST analysis directly, so the regex text scanner can never mask
a failure. The full CLI was also run once per fixture file (separate output
directories, no cross-file deduplication): every AST-restored URL above
appears as a complete endpoint in its own report, the wrong pre-fix forms
(`/admin/users`, `/users/users`, `http://127.0.0.1:9/api/users`, and the
stale `/api/users` in cases 05/06) do not, and the bare literal fragments the
regex layer reports (`/api`, `/x/x`, `http://127.0.0.1:9/api`) remain
distinguishable from correctly restored request URLs.

AST misses do not imply the full CLI finds no strings: its regex rules can
recover literal fragments. Those fragments must be distinguished from a
correctly restored complete request URL.
