---
name: write-syntaxflow-rule
description: Write, fix, and test SyntaxFlow (.sf) vulnerability rules for the yaklang engine. Use this skill whenever you need to author a new .sf rule, repair a rule that misses detections (false negatives) or over-reports (false positives), add sink/source coverage to an existing rule, or generate a rule's metadata and test-cases skeleton. Also use it when the user mentions SyntaxFlow rules, sf rules, taint rules, SAST rules, or wants to extend what a scanning rule detects.
---

# Write SyntaxFlow Rules

This skill helps you author and fix `.sf` (SyntaxFlow) vulnerability rules for the yaklang SAST engine. It solves three recurring pain points:

1. **Knowing how to write a rule** — the SyntaxFlow DSL, taint propagation idioms, and the pitfalls that cause rules to miss or over-report.
2. **Knowing how to debug and refine a rule** — the `yak` CLI commands for formatting, evaluating, completing, and testing a rule.
3. **Writing a rule without drowning in boilerplate** — a scaffold script generates the metadata block and test-cases block so you only write the rule body.

## Where factual SyntaxFlow knowledge lives

The canonical SyntaxFlow reference (matching primitives, NativeCalls, data-flow operators, production-rule examples by language) lives in the sibling **`irify-sast-skill`** repository. Read these on demand — do not assume them from memory:

| File (under `../irify-sast-skill/skills/irify-sast/`) | Read when you need |
|---|---|
| `SKILL.md` | The workflow, data-flow operators (`#>`, `#->`, `->`, `-->`), `?{}` filters, `#{include/exclude/until}` trace blocks, `check`/`alert`, a quick NativeCall table. |
| `nativecall-reference.md` | The full list of 40+ NativeCalls (`<getCallee>`, `<getFunc>`, `<getFormalParams>`, `<getMembers>`, `<getReturns>`, `<slice>`, `<dataflow>`, blueprint family, etc.) with per-call examples. |
| `syntaxflow-examples.md` | 20+ production rules by vulnerability type (SQLi, XSS, RCE, XXE, SSRF, path traversal, deserialization) and 6 generic source/sink/filter patterns. Use these as templates. |

> **Important**: that repo documents on-the-fly queries and the **prefix metadata `desc`** block, but NOT the **trailing test-cases `desc`** block. The trailing test block is documented in this skill's [Test-cases block](#test-cases-block) section below — read it before adding tests.

## Rule file structure

A persisted `.sf` rule has three parts, **separated by the comment markers shown below**. These markers are not optional — they are the convention this skill enforces so the rule body is easy to find and the metadata/test blocks stay visually distinct. When editing an existing rule that lacks them, add them as part of your edit.

```
desc(...)                                   # 1. metadata: title, type, rule_id, cwe, severity, solution, desc, ...

// ======================== Rule Body ========================

<source/sink matching + taint propagation + alert>   # 2. the actual detection logic

// ======================== Test Cases ========================

desc(...)                                   # 3. test cases: alert_min, file://bad, safefile://good
```

The exact marker lines are:
- `// ======================== Rule Body ========================`
- `// ======================== Test Cases ========================`

Use `scripts/scaffold_sf_rule.py` to generate this skeleton so you never hand-write the boilerplate and the markers are always present.

### alert blocks: do NOT repeat solution/desc (noise reduction)

The leading `desc(...)` block already carries the rule's `solution:` and `desc:` (the fix guidance and the vulnerability description). **Do not repeat them inside `alert $var for { ... }` blocks.** An alert block should only carry lightweight finding-specific fields:

```
alert $vuln for {
    level: "high",
    title: "Java SQL Injection Vulnerability Was Detected",
    title_zh: "检测到Java SQL注入漏洞",
    name: "vuln",
    message: "检测到Java SQL注入漏洞，并且从数据源（source）到污染汇聚点（sink）间，没有发现任何过滤函数信息。",
    risk: "SQL注入",
}
```

Repeating the full `solution: <<<SOLUTION ... SOLUTION` and `desc: <<<DESC ... DESC` inside every alert block bloats the rule file with duplicated text (some rules have 2-3 alerts, each re-pasting the same multi-page solution). This is noise: it makes the rule harder to read, harder to maintain, and inflates the alert payload. Keep the long-form `solution`/`desc` in the leading `desc(...)` once; alerts carry only `title`/`level`/`message`/`risk`/`name`.

When you encounter an existing rule that duplicates solution/desc in its alert blocks, **strip the duplicates** as part of your edit (leave the leading `desc(...)` copy intact).

### CWE is derived from the directory name

yak does **not** read a `cwe:` field from the rule file to classify the rule's CWE. It derives the CWE from the **parent directory name**: `common/syntaxflow/sfbuildin/buildin/<lang>/cwe-NNN-<slug>/rule.sf` → CWE `CWE-NNN` (parsed by `rules.go` from the `cwe-\d+` prefix). This means:

- **File the rule under the most specific (child) CWE that matches the sink**, not a broad parent. For example, `Runtime.getRuntime().exec` is OS Command Injection → use `cwe-78-os-command-injection/`, **not** `cwe-77-command-injection/` (CWE-77 is the generic parent). A rule filed under a parent CWE will be scope-filtered out of benchmark cases that declare the child CWE, producing false negatives even when the rule detects the vulnerability correctly.
- When in doubt about which CWE applies to a sink, check https://cwe.mitre.org/ for the hierarchy before choosing the directory.
- The `reference:` link inside the `desc` block should also point to the same CWE for consistency.

## Writing the rule body — the core pattern

Most taint rules follow this shape (see `syntaxflow-examples.md` for full versions):

```
// 1. Match the source(s) — where tainted user input enters.
*.getParameter(,*) as $source;

// 2. Match the sink(s) — where the tainted value is used dangerously.
//    Use glob (.method*) to collapse related sinks into one line when they
//    share a receiver and a prefix; pair it with a type-narrowing chain.
.createStatement().execute*(,* as $sink);
check $sink;

// 3. Propagate: does the source reach the sink?
$sink #-> as $flow;
check $flow;

// 4. (Optional) exclude sanitized paths.
// $flow - $sanitized as $vuln;

// 5. Alert.
alert $vuln for { level: "high", title: "SQL Injection" };
```

### Key facts (read the reference files for depth)

- **Matching**: `.method` matches a method call; `*method*` is a glob; `/(regex)/` is regex; `.method(,* as $params)` captures all call args. `check $var` asserts the var is non-empty (rule stops if empty).
- **Glob simplification**: `.method*` matches any method whose name starts with `method`. Use this to collapse multiple sink lines into one when they share a prefix. For example, instead of listing `.executeQuery(...)` + `.executeUpdate(...)` + `.execute(...)` on three lines, write `.createStatement().execute*(,* as $params)` — one line covers all three (plus future variants like `executeLargeUpdate`). The `(,* as $params)` argument requirement automatically excludes no-arg calls like `executeBatch()`. **The glob is safe when chained to a type-narrowing prefix** (e.g. `.createStatement()` locks the match to `java.sql.Statement`, so non-SQL `execute*` calls like `Runtime.exec` don't match). Without the chain, bare `.execute*` would over-match — always pair a glob with a receiver-narrowing prefix.
- **Data-flow operators**: `#->` walks *where a value comes from* (up, recursive); `->` walks *where it goes* (down). `#>` / `-->` are the one-step / recursive-down variants. Taint propagation almost always uses `#->` from the sink back to the source.
- **`#{include/exclude/until}` trace filters**: `$sink #{ include: \`* & $source\` }-> as $result` keeps only paths that touch the source. This is the most common taint idiom.
- **`?{}` filters**: `?{opcode: param}`, `?{opcode: call}`, `?{have: 'sql'}`, `?{!opcode: const}`, combined with `&&`.
- **NativeCalls** (`<...>`): `<getCallee>`, `<getFunc>`, `<getFormalParams>`, `<getMembers>`, `<getReturns>`, `<slice>`, `<dataflow>`, `<include('rule-name')>` (import a lib rule). Full table in `nativecall-reference.md`.

## Control-flow NativeCalls (recently added)

The `irify-sast-skill` reference may lag behind the engine. These newer CFG NativeCalls (in `sf_native_call.go` / `sf_cfg_native.go`) let rules reason about whether a sink is actually reachable, not just data-reachable:

| NativeCall | What it checks |
|---|---|
| `<getCfg>` | Anchor: the basic block containing the hit point. Start here for the cfg* family. |
| `<cfgGuards>` | Early-exit guards (return/panic/break/continue) on branches that dominate the sink. Use to suppress "sink unreachable because branch returns first". |
| `<cfgDominates target="$x">` | Does `target` dominate the current point (must-pass on the way from entry)? |
| `<cfgPostDominates target="$x">` | Does `target` post-dominate the current point (must-pass on the way to exit)? |
| `<cfgReachable target="$x">` | Is `target` CFG-reachable from the current point? |
| `<cfgReachPath target="$x">` | Shortest CFG path evidence (string). |
| `<cfgCondition>` | Condition summary of the current block. |
| `<cfgConditionValues>` | SSA values tied to the current block's condition. |
| `<reachabilityGuard target="$x">` | mustExecute: is `target` executed on every path from entry? |

Use these when a rule must distinguish "taint exists on some path" from "taint reaches the sink on a path that is actually taken". They are intra-procedural and conservative on merge blocks — see `control_flow_limitations.md` in `yaklang_engine` for caveats.

## CLI commands for authoring / debugging / testing

All commands are `yak` subcommands. Run them from the `yaklang_engine` repo (the sibling at `../yaklang_engine`) or a checkout that has `yak` on PATH.

| Command (alias) | Purpose | Example |
|---|---|---|
| `syntaxflow-create` (`create-sf`, `csf`) | Generate a `.sf` template. | `yak create-sf -l java -v --keyword "SQLi" -o rule.sf` |
| `syntaxflow-format` (`sf-format`, `sf-fmt`) | Beautify/normalize a `.sf` file in place (re-compiles to validate). | `yak sf-format rule.sf` |
| `syntaxflow-evaluate` (`sf-evaluate`) | Score/lint rule quality (catches missing tests, bad structure). | `yak sf-evaluate -t rule.sf -v` |
| `syntaxflowCompletion` (`sf-complete`) | AI-complete missing rule descriptions. | `yak sf-complete -t rule.sf` |
| `syntaxflow-test-cases-completion` (`sf-test-cases`, `sf-tc`) | AI-generate positive/negative test cases into the rule. | `yak sf-tc -t rule.sf` |
| `static-check` (`check`) | Compile a target and run rules; fails if any alert (local assertion test). | `yak check --input-file src.java --rules ./rule.sf` |
| `ssa-query` (`sf`, `syntaxFlow`) | Manual verification/debugging against a compiled program (shows query output, not batch report). | `yak sf --program MyProg --sf rule.sf --with-code` |
| `ssa-compile` (`ssa`) | Compile source to SSA (+ optional `--sf` to run a rule right after). | `yak ssa -t src.java -p MyProg --sf rule.sf` |
| `code-scan` (`codescan`, `sfscan`) | Full batch scan (the pipeline benchmark uses). Use `--sf <file/dir>` to test a custom rule without rebuilding the binary. | `yak code-scan -t src/ --format irify --sf rule.sf -o out.json` |

### Typical authoring loop

1. `python scripts/scaffold_sf_rule.py ... -o rule.sf` — generate skeleton.
2. Write the rule body between the separator comments.
3. `yak sf-format rule.sf` — normalize formatting.
4. `yak sf-evaluate -t rule.sf -v` — lint quality (missing tests? bad desc?).
5. `yak ssa -t sample.java -p TestProg --sf rule.sf --with-code` — debug against a positive sample; confirm it alerts.
6. Add test cases (`--append-tests` or by hand): `alert_min`, `file://` positive, `safefile://` negative.
7. `yak sf-evaluate -t rule.sf` — re-score; the trailing `desc` test block is exercised by `TestVerifiedRule` in yaklang's `buildin-rule-test`.
8. `yak check --input-file safe.java --rules rule.sf` — confirm the negative sample does NOT alert (expect exit 0 with no alerts).
9. **For a stronger L2 regression** (assert alert severity + a paired negative sample), append a row to `TestJavaTruePositiveRegressionRules` in `common/syntaxflow/sfbuildin/buildin/buildin-rule-test/java_true_positive_regression_test.go` — reference the rule by its embed path (`sfbuildin.GetEmbedRuleContent`), do NOT embed a rule copy under `ssaapi/test/` (see Pitfall 7). Inline the Java sample in the row's `code` field (WITH a `package` declaration), and assert against `alertCounts` (High/Mid/Low/Total), never `SyntaxFlowChain(...).Len()` (see Pitfalls 8–9).

## Scaffold script: `scripts/scaffold_sf_rule.py`

Generate a rule skeleton (metadata + body placeholder + test block) so you only write the body:

```bash
python scripts/scaffold_sf_rule.py \
  --title "Detect Java SQL Injection" \
  --type vuln --cwe CWE-89 --severity high --language java \
  --rule-id b8ede24d-8ff0-4d81-ab97-903495a6cb61 \
  -o path/to/java-sqli.sf
```

Add test cases to an existing rule (reads sample files for the test block):

```bash
python scripts/scaffold_sf_rule.py \
  --append-tests path/to/java-sqli.sf \
  --alert-min 4 --language java \
  --bad-file samples/bad_concat.java \
  --good-file samples/safe_prepared.java
```

Run `python scripts/scaffold_sf_rule.py --help` for all flags. The script is stdlib-only.

## Test-cases block

The trailing `desc(...)` block is how a rule self-tests. `yak sf-evaluate` and yaklang's `TestVerifiedRule` run it automatically.

```
desc(
    language: java
    alert_min: 4
    'file://bad.java': <<<FILE
    // positive sample — this MUST produce at least alert_min alerts
    ...vulnerable code...
    FILE
    'safefile://safe.java': <<<CODE
    // negative sample — this MUST produce 0 alerts
    ...safe code...
    CODE
)
```

- `alert_min: N` — the rule must produce at least N alerts on the `file://` samples, else the test fails.
- `file://` — positive sample (should alert). Multiple allowed.
- `safefile://` — negative sample (must NOT alert). Multiple allowed.
- **Always add a negative sample** when you add a new sink/source, so expanded coverage does not introduce false positives. This is the single most effective way to prevent the "broader sink match → safe code flagged" regression.

## Pitfalls to avoid

These are the recurring mistakes this skill exists to prevent:

1. **Multiple sink patterns clobbering shared variables.** Writing several `.executeQuery(,* as $params); .executeUpdate(,* as $params);` lines with downstream logic like `$params<getFunc><getFormalParams> as $limited` can leave `$limited`/`$appendParams` computed from only one sink's context, silently breaking the others. **Prefer a glob** (`.createStatement().execute*(,* as $params)`) to collapse related sinks into one pattern — this avoids the clobbering entirely and is more concise. If you must list sinks separately, **verify each sink in isolation** (one sink per test) — do not assume they all work because one does.
2. **Bare glob without a type-narrowing prefix.** `.execute*(,* as $p)` without a chain like `.createStatement()` will match non-SQL `execute*` calls (e.g. `Runtime.exec`, `SomeExecutor.executeTask`), causing false positives. Always pair a glob with a receiver-narrowing prefix (`.createStatement().execute*`, `con.prepareStatement(...)`) so the match is scoped to the right object type. The `(,* as $params)` argument requirement also helps by excluding no-arg calls like `executeBatch()`.
3. **Source = SSA entry node instead of the real source API call.** yak's `isEntryNode` marks the SSA parameter anchor, which may sit on the parameter *declaration* line, not the `getParameter` call line. When consuming findings downstream, prefer the node whose IR is a call (`contains "("`) with a known source method name.
4. **`$source` global match vs `$limited` formal-params match.** `#{include: * & $source}` is broad and can flag safe code where a tainted value merely co-occurs with the sink (e.g. a `prepareStatement` whose SQL arg is constant but the statement object is tainted via `setString`). `$params<getFunc><getFormalParams> as $limited` + `#{include: <self> & $limited}` restricts taint to the sink's own parameters and is more precise. Prefer the precise form; reach for the broad form only when the precise form misses real flows.
5. **Forgetting the negative test.** Every sink/source expansion needs a `safefile://` negative sample. Without it, `alert_min` can pass while a false positive silently ships.
6. **Comments with internal benchmark case IDs.** Do not put identifiers like `basic-basic19-001` or project-internal case names in rule comments or test samples. Comments should describe *what detection is missing and why you're adding it* in plain terms.
7. **Embedding a rule copy or sample file under `ssaapi/test/` causes drift and orphans.** Writing `//go:embed my_rule.sf` (or `//go:embed sample/X.java`) in a test under `common/yak/ssaapi/test/<lang>/` snapshots the rule / sample. After you fix the real rule under `sfbuildin/buildin/...`, the embedded rule copy is NOT updated — the test runs the stale copy and stays green while the shipped rule is broken. And if you later delete the test, the embedded `.java` sample becomes an orphan nobody references (it only bloats the `//go:embed sample` pool that the engine tests share). Builtin-rule regression tests must reference the rule by its embed-FS path (`sfbuildin.GetEmbedRuleContent("java/cwe-NNN-.../rule.sf")`) in the `buildin-rule-test` package, and inline the Java sample in the test row's `code` field. The `ssaapi/test/<lang>/` directory is for SSA-engine feature tests only, not builtin-rule regression tests.
8. **`SyntaxFlowChain(rule).Len()` is NOT the alert count.** `Len()` returns the *chain* length — all matched values including non-alert intermediates — which can be far larger than the number of alerts (observed: chain=11 but only 1 high alert on a 4-sink sample). Asserting `Len() >= N` is a false-green trap: it passes even when the rule reports far fewer alerts than expected. The `buildin-rule-test` `runJavaBuiltinRule` helper returns `alertCounts{Total,High,Mid,Low}` — assert against those fields (`wantHigh` / `negative`), never against chain length.
9. **Missing `package` declaration in a test sample.** Java allows an unnamed package (no `package` line) and yak will still parse it, so a missing package does NOT fail the test — that is exactly why it slips through. But it is non-idiomatic, inconsistent with real project code, and makes the sample look artificial. Start every test sample with a `package <something>;` line (e.g. `package securibench.micro.basic;`).

## When this skill is not enough

- For the **benchmark-driven workflow** (scan a project → diagnose FN/FP → decide rule vs engine → fix rule → test → re-scan), use the **`benchmark-false-positive-fix`** skill, which orchestrates this skill as one of its steps.
- For engine bugs (SSA compile errors, `record not found`, wrong line numbers), report to the yaklang team — this skill only covers rule logic, not engine internals.
