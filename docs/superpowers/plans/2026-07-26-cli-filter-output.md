# JsOwl CLI Filter and Output Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add proxy/base URL CLI overrides, configurable suffix filtering, silent mode, and httpx-style result lines.

**Architecture:** Extend the public target and scope configuration, centralize suffix decisions in `internal/scope`, and keep terminal formatting in the CLI. The pipeline remains the single queue admission point, so direct and browser-derived candidates receive identical filtering.

**Tech Stack:** Go 1.25+, Cobra, Surf, Rod, strict YAML.

## Global Constraints

- `--base-url` changes only relative discovered URL resolution, never the entry request.
- Page-native browser request methods remain unchanged.
- Default suffixes exclude only clearly non-text assets.
- No new third-party dependencies.

---

### Task 1: Configuration and suffix filtering

**Files:**
- Modify: `internal/model/model.go`
- Modify: `internal/model/config.go`
- Modify: `internal/scope/scope.go`
- Modify: `scanner.go`
- Modify: `internal/pipeline/pipeline.go`
- Test: `config_test.go`
- Test: `internal/scope/scope_test.go`
- Test: `e2e_test.go`

**Interfaces:**
- Produces: `ScopeConfig.SuffixBlacklist []string`
- Produces: `(*scope.Scope).IsSuffixBlocked(*url.URL) bool`

- [ ] Write failing tests for default suffixes, case/query matching, and skipped image requests.
- [ ] Run the focused tests and confirm failures are caused by missing filtering.
- [ ] Add normalized suffix storage to `scope.Scope` and guard every seed/candidate queue admission.
- [ ] Run focused configuration, scope, and integration tests.

### Task 2: Base URL resolution

**Files:**
- Modify: `internal/model/model.go`
- Modify: `internal/pipeline/pipeline.go`
- Test: `e2e_test.go`

**Interfaces:**
- Produces: `Target.BaseURL string`

- [ ] Write a failing integration test with separate entry and base servers.
- [ ] Run the test and confirm the relative API resolves against the entry before implementation.
- [ ] Validate `BaseURL` and use it only when `Candidate.Raw` is relative.
- [ ] Run the focused integration tests.

### Task 3: CLI overrides and terminal output

**Files:**
- Modify: `cmd/jsowl/root.go`
- Modify: `cmd/jsowl/root_test.go`

**Interfaces:**
- Produces: `--proxy/-p`, `--base-url`, and `--silent/-s`
- Produces: `formatResultLine(*jsowl.Result) string`

- [ ] Write failing tests for proxy/base URL propagation, exact default output, and silent output.
- [ ] Run the CLI tests and confirm the new flags/format are absent.
- [ ] Add flag parsing, validation, target propagation, and document resource formatting.
- [ ] Run all CLI tests.

### Task 4: Examples, validation, and handoff

**Files:**
- Modify: `config.example.yml`
- Modify: `README.md`

- [ ] Document the new YAML key and CLI examples.
- [ ] Run `gofmt -l .`, `go test ./...`, `go vet ./...`, and `go build ./cmd/jsowl`.
- [ ] Confirm `bin/` and `report/` remain untouched.

