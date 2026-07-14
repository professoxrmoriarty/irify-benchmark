---
name: benchmark-false-positive-fix
description: End-to-end workflow for diagnosing and fixing SAST rule misses (false negatives) and over-reports (false positives) found via the irify-benchmark evaluation framework. Use this skill when you have run a benchmark scan and need to figure out why a case is a false negative / false positive, decide whether the cause is the rule or the engine, fix the rule, test the fix, and verify it end-to-end. Trigger on phrases like "benchmark result shows FN", "rule misses detection", "false negative", "false positive", "why didn't the rule fire", "fix the scanning rule", or when reviewing a benchmark diagnose report.
---

# Benchmark False-Positive / False-Negative Fix Workflow

This skill orchestrates the full loop from "the benchmark says a case is FN/FP" to "the rule is fixed, tested, and verified end-to-end". It assumes you are working inside the `irify-benchmark` project (in the IRify_Client workspace), with the `yaklang_engine` source checked out as the sibling directory `../yaklang_engine`.

## Prerequisites

- `irify-benchmark` built (`make build` → `bin/irify-benchmark` or `build/irify-benchmark`).
- `yak` binary on PATH.
- `yaklang_engine` repo at `../yaklang_engine` (sibling, the shared scanning engine inside the IRify_Client workspace) for rule editing and rule tests.

## The workflow

### Step 0 — Verify the project is in v2 format

The `run` command requires the v2 layout (`cases/{id}/project.yaml` + `cases.yaml` + `src/`). Some older projects use the v1 layout (`cases/{id}/annotation.json` + source files loose in the project dir) and `run` will fail with `read project yaml: no such file or directory`.

If the project is v1, migrate it before scanning:
1. Create `cases/{id}/src/` and move the source files into it.
2. Write `project.yaml` (see an existing project like `securibench-micro-sqli/project.yaml` for fields: `project_id`, `name`, `language`, `source_root: src/`).
3. Write `cases.yaml` from `annotation.json` — map each v1 case to the v2 schema (`case_id`, `source_code` relative to `src/`, `expectation.flow.source/sink` with `symbol`/`line`/`file`).
4. **Re-check every annotated source/sink line against the actual source file.** v1 annotations were sometimes written without verifying line numbers (a recurring source of false negatives where the matcher's line tolerance can't bridge the gap). Use `cat -n src/<file>` to confirm.

### Step 1 — Run the benchmark scan and produce a diagnosis

```bash
cd irify-benchmark
./build/irify-benchmark run --engine yaklang --project <project-id> --output data
./build/irify-benchmark diagnose <project-id> --engine yaklang --format markdown
```

Read the diagnosis: it gives per-case `category` (`matched_tp`, `sink_method_mismatch`, `cross_cwe_or_noise_rule`, `matcher_endpoint_source_mismatch`, ...) and per-finding `category`, plus `rule_candidates` (which `.sf` files likely produced each finding).

### Step 2 — Triage: rule problem vs engine problem vs benchmark problem

For each FN/FP, decide which layer is at fault. Do not assume — verify against source.

**Triage order matters and saves hours.** The single most expensive mistake this skill has made is to assume an FN is a converter/matcher alignment problem and spend a long time editing `internal/runner/converter_irify.go` / `internal/matcher/` before discovering the real cause is **upstream: the engine never produced a risk for that case at all** (because the source library doesn't hook the source method, or SSA taint propagation breaks across an array swap / interprocedural alias). Rule of thumb: **if a FN case's `source_match=0 AND sink_match=0` and there is no finding in the SQLite `findings` table at the expected sink file+line, the engine didn't produce a risk — go to yaklang, do NOT touch the benchmark converter/matcher.** Use this SQL to bucket FN cases before doing anything:

```bash
sqlite3 data/benchmark.db <<'SQL'
SELECT source_match, sink_match, count(*)
FROM case_results
WHERE project_id='<project-id>' AND engine='yaklang'
  AND engine_version='<version>' AND status='fn'
GROUP BY source_match, sink_match;
-- Then, for the (0,0) bucket, check whether findings even exist at the expected sink:
SELECT sink_file, sink_line, sink_symbol
FROM findings
WHERE project_id='<project-id>' AND engine='yaklang' AND engine_version='<version>'
  AND sink_file LIKE '%<FileName>.java%';
SQL
```

| Symptom | How to tell rule vs engine vs benchmark |
|---|---|
| **FN: no risk produced at all (source/sink both match=0, no finding at expected sink file+line)** | The engine did not fire. Two upstream causes, both in yaklang (NOT in the benchmark repo): (a) the **source library doesn't hook the source method** — check `common/syntaxflow/sfbuildin/buildin/<lang>/lib/user-input-http-source/` and compare against the source code's actual API call; (b) **SSA taint propagation breaks** across an array-element swap (`a[i] = tainted; x = a[i]`), an interprocedural alias, a `StringBuffer.append` indirection, or an index read (`getParameterValues()[0]`). Confirm by isolating the case with `go run common/yak/cmd/yak.go code-scan` (see below). Fix the source library in the yaklang repo; for propagation gaps, write a `t.Skip`'d SSA test (see below) and leave the engine fix to a future SSA change. |
| **FN: rule never fired on a real sink (risk count 0 even with a direct source->sink flow)** | Check the rule's sink/source patterns against the source code. If the pattern doesn't cover the sink method (e.g. rule matches `executeQuery` but the code uses `executeUpdate`), it's a **rule coverage gap**. If the pattern covers it but no alert fires, it's a **rule taint-propagation bug** or an **engine SSA bug**. |
| **FN: rule fired but matched the wrong case** | Check the diagnosis `best_candidate_finding`. If it points at a cross-CWE noise rule (e.g. empty-catch on a SQLi case), it's a **benchmark matcher scope issue** (CWE filtering), not a rule issue. |
| **FN: rule fired with correct flow but case is `no_same_cwe_finding`** | The rule reported the right taint but its CWE doesn't match the case's CWE. yak derives a rule's CWE from its **directory name** (`cwe-NNN-<slug>`). If the rule is filed under a parent CWE (e.g. CWE-77 Command Injection) but the sink is a specific child (e.g. CWE-78 OS Command Injection for `Runtime.exec`), the scope filter drops it. Fix by **moving the rule to the precise child CWE directory** — do NOT add CWE parent-child hierarchy to the benchmark scope filter (it weakens noise isolation and is over-engineering for one imprecise rule). Confirm the CWE hierarchy at cwe.mitre.org before moving. |
| **FN: finding line/symbol doesn't align with case annotation** | Compare the finding's source/sink line against the source file (`cat -n`). If the finding is right and the annotation is wrong, it's a **benchmark annotation bug** — fix the annotation's line/symbol. If the finding is wrong (e.g. source anchored on the SSA entry/parameter-declaration line instead of the real API call), it's a **converter issue** (see `matcher_endpoint_source_mismatch`). This category is where the converter/matcher edits are actually justified — but verify first (via the SQL bucket above) that a risk was produced, otherwise you are editing the wrong layer. |
| **FP: rule fired on safe code** | Check the source: is the flagged value actually tainted/safe? If safe code is flagged, it's a **rule precision bug** (over-broad sink or missing sanitizer exclusion). If the code is genuinely vulnerable, it's a **benchmark annotation issue** (the case is mislabeled `must_not_alert`). |
| **Engine errors** (`record not found`, compile failures, wrong line numbers) | Not a rule issue. Report to the yaklang team. |

To confirm "rule covers the sink but doesn't fire", test the rule in isolation. **Prefer `go run` over the installed `yak` binary** so you always exercise the source tree you're editing:

```bash
cd ../yaklang_engine
go run common/yak/cmd/yak.go code-scan \
  -t <sample-source-or-dir> -l java --memory \
  --format irify --with-dataflow-path \
  --rule-keyword "<rule title keyword>" \
  -o /tmp/iso.json
python3 -c "import json;d=json.load(open('/tmp/iso.json'));print('risks:',len(d['Risks']))"
```

(`-t` accepts a directory; a single `.java` file fails with "input file type". `--rule-keyword` filters rules by title substring — without it every builtin rule runs and noise hides the signal.)

For propagation-gap triage, use **minimal controlled samples**: take the failing case, strip everything except source + the suspect propagation construct + sink, and scan. Compare against a direct-flow control (`getParameter` straight to `println`). If the control fires and the stripped sample doesn't, you have isolated the propagation gap to that construct. This is how the array-swap / interprocedural-alias / index-read gaps were pinned down.

If the isolated run also misses it, it's the rule/engine. If the isolated run catches it but the benchmark scan didn't, suspect rule loading or a scan-mode difference.

#### Documenting SSA propagation gaps as `t.Skip`'d tests

When you isolate an SSA propagation gap (the rule + source library are correct but taint doesn't cross an array swap / interprocedural alias / index read), **write it as a `t.Skip`'d test, do not just note it in a doc**. A skipped test is executable evidence that auto-regresses green and surfaces the moment a future SSA improvement closes the gap (just unskip + assert). Place it in `common/yak/ssaapi/test/syntaxflow/` (engine feature tests, NOT a builtin rule regression). Pattern:

```go
// Reproduces securibench-micro Aliasing3: array element write-then-read swap.
// Element-sensitive propagation does not track that the post-swap value
// carries the original taint. Real scan: Risk=0.
func TestServletXSS_ArrayElementSwapPropagation(t *testing.T) {
    t.Skipf("SSA taint-propagation gap (benchmark FN evidence): %s\n"+
        "Unskip after improving taint propagation in common/yak/ssa.",
        "array element write `a[i] = tainted` does not propagate to a later read of a[i]")
    const src = `...minimal Java sample with package decl...`
    runPropagationCase(t, src) // asserts $tainted non-empty; would fail today
}
```

Always pair a skipped gap with a non-skipped **control case** (direct `getParameter -> println`) that must pass — it proves the rule + source lib are correct, so the gap really is in propagation and not in your test rig.

### Step 3 — Fix the rule

**Delegate the rule authoring to the `write-syntaxflow-rule` skill.** It has the SyntaxFlow DSL knowledge, the CLI command reference, the scaffold script, and the pitfalls. Specifically:

1. Branch from `yaklang_engine` `origin/main`: `cd ../yaklang_engine && git checkout origin/main && git checkout -b fix/<short-description>`.
2. Read the rule file under `common/syntaxflow/sfbuildin/buildin/<lang>/cwe-NNN-<name>/`.
3. Follow `write-syntaxflow-rule` to extend sinks/sources, fix taint propagation, and **add a negative test sample** for every new coverage.
4. Keep comments plain — describe *what detection was missing and why*, no internal benchmark case IDs.

### Step 4 — Test the fix (two layers)

**Where to write tests — decide first, write once:**

| Test concern | Location | How to reference the rule |
|---|---|---|
| Builtin rule regression (alert on vuln / no-alert on safe) | `common/syntaxflow/sfbuildin/buildin/buildin-rule-test/` | `sfbuildin.GetEmbedRuleContent("java/cwe-NNN-.../rule.sf")` — by embed-FS path |
| Rule's inline self-test (min sample, run by `TestVerifiedRule`) | inside the `.sf` file's trailing `desc(...)` block | n/a — the rule self-contains it |
| SSA *engine* feature (not a rule) | `common/yak/ssaapi/test/<lang>/` | inline SF string or local `.sf`, NOT a builtin rule |

**Never** put builtin-rule regression tests under `ssaapi/test/<lang>/` — that directory is for SSA-engine feature tests, and embedding a rule copy there causes drift (the test runs a stale copy after the real rule changes). **Never** drop test sample `.java` files into `ssaapi/test/<lang>/sample/` either — that directory is the engine tests' shared sample pool; orphan files there are not referenced by name and just bloat the embed. Inline the sample Java inside the test row's `code` field instead (self-contained, no stray files).

**L2: go test in yaklang** — assert the rule now alerts on the missed sink and does NOT alert on safe code. Place builtin-rule regression tests under `common/syntaxflow/sfbuildin/buildin/buildin-rule-test/`. The `buildin-rule-test` package has a table-driven harness (`java_true_positive_regression_test.go` / `java_false_positive_regression_test.go`) that loads a builtin rule **by its embed-FS path** and runs it on a virtual Java file, tallying alerts by severity. Append a row instead of opening a new test file:

```go
// in TestJavaTruePositiveRegressionRules's cases slice:
{
    name:     "sqli_execute_update_sink_detected",
    rulePath: "java/cwe-89-sql-injection/java-execute-query-string-add-out-of-control.sf",
    fileName: "ExecUpdate.java",
    wantHigh: 1,   // true positive: expect >=1 high alert
    code: `package securibench.micro.basic;

import java.sql.*;
import javax.servlet.http.*;
public class ExecUpdate extends HttpServlet {
    protected void doGet(HttpServletRequest req) throws Exception {
        String name = req.getParameter("name");
        Connection con = DriverManager.getConnection("jdbc:test");
        Statement stmt = con.createStatement();
        stmt.executeUpdate("select * from Users where name=" + name); // BAD
    }
}`,
},
// always pair a positive row with a negative row for the new coverage:
{
    name:     "sqli_safe_prepared_statement_not_reported",
    rulePath: "java/cwe-89-sql-injection/java-execute-query-string-add-out-of-control.sf",
    fileName: "SafeQuery.java",
    negative: true, // expect zero alerts total
    code: `package securibench.micro.basic;
/* ...safe PreparedStatement + setString sample, WITH a package decl... */`,
},
```

Row fields: `wantHigh` (>=1 → true positive, asserts high-severity alert count), `negative: true` (safe sample, asserts zero alerts), `allowZeroHigh: true` (a known-uncovered gap you want to pin — must not be high today; flip to `wantHigh` once covered). Rules deduplicate tainted sink reaches per alert variable, so a program with several tainted sinks may still yield one high alert — assert `wantHigh: 1` (the sink is reached at all), not one alert per sink.

**Three traps when writing the `code` sample:**
- **Always include a `package` declaration.** Java allows an unnamed package (no `package` line) and yak will still parse it, so a missing package does NOT fail the test — but it is non-idiomatic and inconsistent with real project code. Start every sample with `package <something>;` (e.g. `package securibench.micro.basic;`).
- **Assert alert count, NOT `SyntaxFlowChain(rule).Len()`.** `SyntaxFlowChain(...).Len()` returns the *chain* length (all matched values, including non-alert intermediates), which can be far larger than the alert count (e.g. chain=11 but only 1 high alert). Asserting `Len() >= N` is a false-green trap. The `runJavaBuiltinRule` helper returns `alertCounts{Total,High,Mid,Low}` — assert against those, via `wantHigh` / `negative`.
- **Inline the sample in the `code` field.** Do not `//go:embed` a separate `.java` file. If you later delete the test row, an embedded sample file becomes an orphan nobody references. Self-contained rows keep the sample pinned to its assertion.

Run it:

```bash
cd ../yaklang_engine
go test -run "TestJavaTruePositiveRegressionRules" -v ./common/syntaxflow/sfbuildin/buildin/buildin-rule-test/
```

**L1: `TestVerifiedRule`** — the rule's trailing `desc` test block must still pass (no regression on existing cases):

```bash
cd ../yaklang_engine
go test -run "TestVerifiedRule/<lang>/CWE-<NNN>" ./common/syntaxflow/sfbuildin/buildin/buildin-rule-test/
```

Run `yak sf-evaluate -t <rule.sf> -v` to lint the rule quality after edits.

### Step 5 — Quick end-to-end check without rebuilding yak

You can test the fixed rule against the benchmark source without rebuilding the `yak` binary, using `code-scan --sf`:

```bash
cd ../yaklang_engine
yak code-scan -t <irify-benchmark>/cases/<project>/src \
  --format irify --with-dataflow-path --memory \
  --sf <rule.sf> -o /tmp/e2e.json
```

Inspect `/tmp/e2e.json` — confirm the previously-missed sinks now appear. Note: `--sf` mode may apply different risk deduplication than the embedded-rule scan path, so alert counts can differ from the L2 go test; what matters is that the previously-missed sink lines now produce risks.

### Step 6 — Commit and push (do NOT open the PR yourself)

```bash
cd ../yaklang_engine
git add <rule.sf> <buildin-rule-test test file>
git commit -F - <<'MSG'
fix(<cwe>): <plain description of what sink/source was missing>

<2-3 lines explaining the gap and the fix. No internal case IDs.>

Tests:
- L2 buildin-rule-test: <which case rows assert the new coverage + the paired negative>
- L1 TestVerifiedRule: passes (no regression)
MSG
git push -u origin fix/<short-description>
```

Give the user the compare link: `https://github.com/yaklang/yaklang/compare/main...<branch>`. **Let the user open the PR** — do not run `gh pr create` yourself.

### Step 7 — Final end-to-end verification (after the rule is merged and yak rebuilt)

Once the fix is merged and a new `yak` binary is built from `yaklang` main:

```bash
cd irify-benchmark
./build/irify-benchmark run --engine yaklang --project <project-id> --output data
./build/irify-benchmark diagnose <project-id> --engine yaklang --format markdown
```

Confirm: the previously-FN cases are now TP, recall improved, and no new FPs appeared.

## Common diagnosis categories → action

| Diagnosis category | Meaning | Action |
|---|---|---|
| `matched_tp` | Rule correctly detected the case. | Nothing. |
| `sink_method_mismatch` | Rule fired but on a different sink method than the case expects; or the rule doesn't cover the case's sink at all. | Usually a **rule coverage gap** → Step 3. |
| `cross_cwe_or_noise_rule` | A finding from a different CWE rule was matched to this case. | Benchmark matcher CWE scope issue (already handled by the matcher's scope filter). Verify the noise rule isn't a real FP; otherwise ignore for this case. |
| `matcher_endpoint_source_mismatch` | The finding's source doesn't align with the case's annotated source. | Check whether the converter picked the right source node (entry node vs real source API call). May be a benchmark converter issue. |
| `duplicate_finding_for_same_case` | Multiple findings map to one case (fan-in / multi-sink). | Check if findings are genuinely distinct flows; may be an annotation granularity question. |

## What this skill does NOT do

- It does not fix engine (SSA) bugs — those go to the yaklang team.
- It does not change benchmark annotations (case `must_alert`/`must_not_alert`) without the user's explicit decision — annotation changes are ground-truth changes and need review.
- It does not open PRs — it commits and pushes, then hands the compare link to the user.