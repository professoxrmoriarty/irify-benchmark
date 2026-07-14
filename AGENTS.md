# irify-benchmark — Agent Constraints

> This document is the **AI Agent entrypoint** for the irify-benchmark subproject.
> Positioning: a lightweight framework for evaluating code-scanning engines, maintaining ground-truth annotations, running scans, matching results, and generating comparison reports.

## Where to Start

| Doc | Content |
|-----|---------|
| `README.md` | Project overview, data boundaries, baseline regression scripts |
| `AGENTS.md` | **This doc** — constraints, architecture, module boundaries, development standards |
| `docs/environment.md` | Build commands, dev workflow, frontend setup, SQLite path rules |
| `docs/common-pitfalls.md` | Recurring issues and their solutions |
| `docs/cli-usage.md` | Full CLI reference |
| `docs/openapi.yaml` | REST API contract (OpenAPI 3.0) |
| `docs/superpowers/specs/2026-05-21-irify-benchmark-v2-design.md` | v2 architecture design (Project-centric, dual-track storage, IDE frontend) |
| `web/README.md` | Frontend development (React + Vite + Monaco) |
| `Makefile` | Build targets (`all`, `build`, `build-web`, `dev`, `serve`, `test`, `e2e`) |

## Skills (invoke via the Skill tool)

Bundled skills live under `.agents/skills/`. Invoke them by name when the task matches — they encode the SyntaxFlow DSL knowledge, CLI commands, and the benchmark fix loop so you don't reinvent them from scratch.

| Skill | When to use |
|-------|-------------|
| `write-syntaxflow-rule` | **Authoring or fixing a `.sf` rule.** Use whenever you need to write a new SyntaxFlow rule, extend an existing rule's sink/source coverage, fix a rule that misses detections or over-reports, or generate a rule's metadata + test-cases skeleton. Covers the SyntaxFlow DSL (matching, taint propagation, `#{include}` trace filters, NativeCalls including the new control-flow `cfg*` family), the `yak` CLI commands (`create-sf`, `sf-format`, `sf-evaluate`, `static-check`, `ssa-query`), and a scaffold script (`scripts/scaffold_sf_rule.py`) that emits the `desc(...) → rule body → desc(...) test block` structure. |
| `benchmark-false-positive-fix` | **Diagnosing and fixing a benchmark FN/FP end-to-end.** Use when a benchmark scan reports a false negative or false positive and you need to triage (rule vs engine vs benchmark), fix the rule (delegates to `write-syntaxflow-rule`), test it (L2 go test + L1 `TestVerifiedRule`), and verify end-to-end. Covers the scan → diagnose → triage → fix → test → push → re-verify loop. |

> Rule-authoring factual knowledge (SyntaxFlow syntax, NativeCall reference, production-rule examples) is sourced from the sibling `../irify-sast-skill/skills/irify-sast/` repo — the skills read those files on demand. Do not assume SyntaxFlow details from memory; consult the skill.

## Project Positioning

irify-benchmark is the **evaluation sub-framework** for code-scanning engines. It lives in the **IRify_Client workspace** (this repository) as a sibling of `yaklang_engine/` (the shared scanning engine) and `multi_product_frontend/` (the multi-product frontend). It is decoupled from `IRify_SAST/` (the SaaS backend); SaaS-side consumption of benchmark results, if any, is out of scope here.

| Dimension | irify-benchmark | yaklang_engine | multi_product_frontend |
|-----------|-----------------|----------------|-------------------------|
| Responsibility | Ground-truth annotation, evaluation, reporting | SSA/SyntaxFlow scanning engine | Multi-product UI (yakit / irify / memfit) |
| Call direction | Invokes yaklang CLI | Invoked by benchmark | n/a (no direct dependency) |
| Storage | FS + SQLite dual-track | No persistent storage | n/a |

### yaklang Engine Repository Location

The yaklang scanning engine source code lives in the sibling directory **`../yaklang_engine`** (relative to this project root). Key paths:
- **Buildin SyntaxFlow rules**: `../yaklang_engine/common/syntaxflow/sfbuildin/buildin/` — organized by language and CWE category.
- **SSA API tests**: `../yaklang_engine/common/yak/ssaapi/test/`
- **SSA core tests**: `../yaklang_engine/common/yak/ssa/ssautil/testdata/`
- **Builtin rule regression tests**: `../yaklang_engine/common/syntaxflow/sfbuildin/buildin/buildin-rule-test/`

When investigating false positives or missing detections, always inspect the corresponding CWE directory under `sfbuildin/buildin/java/` (or `php/` / `javascript/` etc.) first.

### irify-sast-skill Reference Location

The canonical SyntaxFlow DSL / NativeCall reference lives in the sibling **`../irify-sast-skill`** repo (cloned at `~/goproject/irify-sast-skill`). See the skills below for how it is consumed. Do not assume SyntaxFlow details from memory; consult the skill.

## Directory Structure

```
irify-benchmark/
├── cmd/irify-benchmark/main.go    # CLI entrypoint + HTTP server (REST API + SPA fallback)
├── internal/
│   ├── store/                      # HybridStore: unified FS + SQLite interface
│   │   ├── hybrid.go               # Unified Store interface
│   │   ├── sqlite.go               # SQLite storage (findings / results / pending)
│   │   └── fs.go                   # File-system storage (annotation JSON, v1 compat)
│   ├── project/                    # Project management (CRUD + file ops)
│   ├── cases/                      # Case management (CRUD)
│   ├── matcher/                    # FlowMatcher: finding ↔ case matching engine
│   ├── pipeline/                   # Evaluation pipeline (scan → match → result)
│   ├── runner/                     # Engine runner (yaklang / mock)
│   ├── reporter/                   # Report generation (JSON / Markdown / HTML)
│   ├── reviewer/                   # Pending review logic
│   └── eval/                       # Evaluation metric computation
├── pkg/
│   ├── schema/                     # Core data models (Project, Case, Finding, Result, PendingItem)
│   └── engine/                     # Engine interface definition
├── web/                            # React frontend (Vite + Monaco)
│   ├── src/
│   │   ├── api/client.ts           # REST API client
│   │   ├── components/
│   │   │   └── CodeViewer.tsx      # Monaco wrapper (deltaDecorations highlight)
│   │   ├── pages/
│   │   │   ├── Dashboard.tsx       # Project list + Open Project
│   │   │   ├── ProjectExplorer.tsx # File tree + case list + Monaco
│   │   │   ├── CaseDetail.tsx      # Case detail + flow graph + code highlight
│   │   │   └── ReviewQueue.tsx     # Review queue (approve / reject + code preview)
│   │   └── config.ts               # API_BASE configuration
│   └── dist/                       # Build output (generated by make build-web)
├── cases/                          # Project directories (Git-tracked)
│   └── {project-id}/
│       ├── project.yaml            # Project metadata
│       ├── cases.yaml              # Ground-truth annotations
│       └── src/                    # Source code
├── data/
│   └── benchmark.db                # SQLite runtime database (not in Git)
├── bin/                            # Build artifacts (irify-benchmark binary)
├── annotations/                    # Legacy v1 ground-truth annotations (YAML)
├── schemas/                        # JSON Schema definitions
├── scripts/                        # Helper scripts (dev.sh, e2e-test.sh)
├── Makefile
├── go.mod / go.sum
├── pyproject.toml                  # Python legacy entrypoint (clean-feishu, sample-javaseclab, etc.)
└── README.md
```

## Module Boundaries

- `internal/store` is the **only** storage entrypoint. Direct file-system or SQLite manipulation in handlers / CLI / frontend is **forbidden**.
- `pkg/schema` defines data structures only; it **must not** contain business logic.
- `internal/runner` handles engine invocation only; it **must not** depend on matcher or pipeline.
- The `web/` frontend **must not** touch the backend file system directly; all data exchange goes through the REST API.
- `cmd/irify-benchmark/main.go` is the sole CLI + Server entrypoint; importing `cobra` in other packages is **forbidden**.

## Storage Architecture: Dual-Track (CRITICAL)

| Data | Storage | Git? | Notes |
|------|---------|------|-------|
| `cases/{id}/src/` | FS | **Yes** | Human-curated source, must be diffable |
| `cases/{id}/project.yaml` | FS | **Yes** | Project metadata |
| `cases/{id}/cases.yaml` | FS | **Yes** | Ground truth, subject to PR review |
| Findings | SQLite | No | Machine-generated, partitioned by (project, engine, version) |
| Results | SQLite | No | Evaluation output, reproducible |
| Pending review | SQLite | No | Runtime workflow state |

**Why not pure FS?** Findings grow linearly with (projects × engine versions × scan runs); JSON files are hard to query and filter.
**Why not pure SQLite?** Cases and source code must be diffable in PRs; SQLite binaries are not review-friendly.

## REST API

### API Contract (OpenAPI 3.0)

The frontend and backend are governed by **`docs/openapi.yaml`**. **When adding or modifying an API, update the YAML first, then the code**, to ensure both sides agree on request/response formats.

- No code-generation tools (zero build dependency)
- Hand-written YAML serves as the human reference
- Go backend and TypeScript frontend each implement against the YAML

Full spec: `docs/openapi.yaml`

### Endpoint Quick Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/projects` | GET | Project list |
| `/api/projects/{id}` | GET | Project details |
| `/api/projects/{id}/files` | GET | File tree (recursive directory structure) |
| `/api/projects/{id}/files/{path...}` | GET | File content (text/plain) |
| `/api/projects/{id}/cases` | GET | Case collection |
| `/api/projects/{id}/results` | GET | Evaluation result list |
| `/api/projects/{id}/findings` | GET | Engine findings (includes version list) |
| `/api/projects/{id}/raw-scan` | GET | Raw scan report download |
| `/api/cases` | GET | Global case search |
| `/api/pending` | GET | All pending items (cross-project aggregation) |
| `/api/pending/{itemId}/approve` | POST | Approve pending item |
| `/api/pending/{itemId}/reject` | POST | Reject pending item |

All endpoints return JSON (except file downloads). Static file serving supports SPA fallback (missing file → `index.html`).

## Git Integration

All file-system mutations (`project create/import/add-file/mkdir/cp-dir/case create/describe`) **automatically run `git add`** to ensure changes are staged.
**No automatic `git commit`** — commit timing is decided by the user or CI.

## Extension Points

| Extension | Approach |
|-----------|----------|
| New language | Declare in `project.yaml`; Monaco supports most languages natively |
| New engine | Implement `pkg/engine.Engine` interface; SQLite schema is engine-agnostic |
| New report format | Implement `pkg/reporter.Reporter` interface |
| New matching strategy | Implement `pkg/matcher.Matcher` interface |
| New frontend page | Add component in `web/src/pages/`, register route in `App.tsx` |
| New REST endpoint | Register handler in `cmd/irify-benchmark/main.go`, follow CORS middleware |

## Development Standards

- **English for code and docs, Chinese for UI copy**: Go/TypeScript code, README, design docs, and agent documents must be in English; user-visible UI text may be in Chinese.
- **Minimal change principle**: modify only the files necessary to achieve the goal; do not refactor unrelated code.
- **Error handling**: every `error` in Go must be handled or propagated upward; naked `panic` is forbidden.
- **Frontend state management**: use React `useState` + `useEffect`; Redux is not needed.
- **Testing**: Go unit tests cover core business logic; E2E uses bash + curl + diff.
- **CLI doc sync**: when changing CLI commands, flags, arguments, or output format, update `docs/cli-usage.md`.
- **API spec sync**: when adding or modifying REST endpoints, request/response structures, or query parameters, update `docs/openapi.yaml`.
- **Frontend linkage sync**: when adding or modifying pages, check the navbar, Dashboard entry, return links, and route registration to avoid blank-screen paths.
