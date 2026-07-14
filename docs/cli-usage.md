# irify-benchmark CLI Usage

> CLI reference for the `irify-benchmark` command-line tool.
> For the latest command list, run `irify-benchmark --help`.

## Project Management

```bash
irify-benchmark project create --id demo --name "Demo" --language java --description "..."
irify-benchmark project import --id demo --name "Demo" --language java --from /path/to/src
irify-benchmark project describe --id demo --description "updated"
irify-benchmark project list
irify-benchmark project delete --id demo
```

## File Management (AI Friendly)

```bash
# Add file via stdin
echo 'public class Hello {}' | irify-benchmark project add-file --project demo --file src/Hello.java --stdin

# Add file from local disk
irify-benchmark project add-file --project demo --file src/Hello.java --from /path/to/Hello.java

# Create directory
irify-benchmark project mkdir --project demo --dir src/controllers/

# Copy directory
irify-benchmark project cp-dir --project demo --from /path/to/extra --to src/extra/

# List project files
irify-benchmark project files --project demo
```

## Case Management

### Create a Case

**Via CLI flags** (recommended for AI agents):
```bash
irify-benchmark case create --project demo --id demo-cmdi-001 --name "CMDi" \
  --description "Command injection test case" \
  --vuln-desc "User input flows into Runtime.exec without sanitization" \
  --language java \
  --source-code controllers/CmdiController.java \
  --source-file controllers/CmdiController.java --source-line 13 --source-symbol "request.getParameter" \
  --sink-file controllers/CmdiController.java --sink-line 14 --sink-symbol "Runtime.getRuntime().exec" \
  --cwe CWE-78 --tags command-injection,java
```

**Via stdin (JSON)**:
```bash
echo '{"case_id":"...",...}' | irify-benchmark case create --project demo --stdin
```

**From JSON file**:
```bash
irify-benchmark case create --project demo --file /path/to/case.json
```

> **Validation on create**: The CLI validates that referenced files exist, line numbers are in bounds, and symbols appear on the claimed lines. Hard errors block creation; warnings are printed but allowed.

### List Cases

```bash
irify-benchmark case list --project demo
```

### Show a Case

```bash
irify-benchmark case show --project demo --case demo-cmdi-001
```

> Shows the case YAML followed by source/sink code previews with line markers.

### Delete a Case

```bash
irify-benchmark case delete --project demo --case demo-cmdi-001
```

### Validate All Cases

```bash
irify-benchmark case validate --project demo
```

> Checks every case in the project for file existence, line bounds, symbol presence, and flow consistency. Returns non-zero exit code if any hard errors are found.

## Pipeline

```bash
# Full pipeline: scan → match → result → SQLite
irify-benchmark run --project demo --engine yaklang

# Scan only (save findings to SQLite)
irify-benchmark scan --project demo --engine yaklang

# Match only (use existing findings in SQLite)
irify-benchmark match --project demo --engine yaklang --version 1.4.5
```

## Review

```bash
irify-benchmark review list --project demo
irify-benchmark review approve --project demo --item pending-001 --reviewer user --notes "..."
irify-benchmark review reject --project demo --item pending-001 --reviewer user --reason "fp"
```

## Query Findings

### `findings list`

List all findings for a project with match summary:

```bash
irify-benchmark findings list <project-id> [--engine=<engine>] [--version=<version>]
```

Output: JSON array of findings with `match_status` (`tp`/`fp`/`fn`/`tn`).

### `findings show`

Show a single finding with full details and case match diagnosis:

```bash
irify-benchmark findings show <project-id> <finding-index> [--engine=<engine>] [--version=<version>]
```

Output: JSON with `finding`, `match`, and `diagnosis` fields.

### `raw-scan`

Output the raw engine scan report (unmodified JSON):

```bash
irify-benchmark raw-scan <project-id> [--engine=<engine>] [--version=<version>]
```

## Diagnosis

Generate AI-friendly diagnosis for benchmark scan results:

```bash
irify-benchmark diagnose <project-id> --engine yaklang --format prompt --max-priorities 12 --max-rule-reviews 8
irify-benchmark diagnose <project-id> --engine yaklang --format manifest --max-priorities 12 --max-rule-reviews 8
irify-benchmark diagnose <project-id> --engine yaklang --version latest --format bundle
irify-benchmark diagnose <project-id> --engine yaklang --format bundle --max-priorities 6 --max-rule-reviews 3
irify-benchmark diagnose <project-id> --engine yaklang --version latest --format json
irify-benchmark diagnose <project-id> --engine yaklang --format markdown
irify-benchmark diagnose validate-response --file ai-response.md
```

Use `--format bundle` when an AI agent needs bounded context for diagnosis and
rule review. The bundle contains priority items, deduplicated SyntaxFlow review
suggestions, rule snippets, and validation commands. Tune
`--max-priorities` and `--max-rule-reviews` to keep the context small for quick
triage or larger for deeper rule review. Use `--format json` for the complete
report consumed by the Web workbench. The command does not modify `.sf` rules.

Use `--format prompt` when you want a ready-to-paste AI task. It wraps the
bundle with guardrails and a JSON response contract for `root_causes`,
`rule_suggestions`, `benchmark_fixes`, `validation_plan`, and `uncertainties`.
The prompt explicitly requires review-only SyntaxFlow suggestions instead of
editing rule files directly.

Use `--format manifest` when an AI agent or automation runner needs a
machine-readable handoff plan. It lists workflow steps, commands, API endpoints,
expected artifacts, guardrails, rule review queue entries, and validation gates.
The manifest explicitly forbids automatic edits to `yaklang/common/syntaxflow/sfbuildin`.

Use `diagnose validate-response` to check whether an AI response satisfies the
prompt response contract. The command accepts raw JSON or Markdown containing a
fenced `json` block. It prints validation JSON and returns a non-zero exit code
when required fields are missing.

## Web Frontend

```bash
# Start the development web server (Vite + React)
irify-benchmark web

# With custom port and API endpoint
irify-benchmark web --port 3000 --api http://localhost:8081
```

> **Flags**:
> - `--port, -p`: Vite dev server port (default: 5173)
> - `--api, -a`: Backend API base URL (default: http://localhost:8081)
>
> The command auto-detects the `web/` directory relative to the binary and runs `npm install` if `node_modules` is missing.

## Server

```bash
# Start REST API + static file serving
irify-benchmark server --port 8081 --static web/dist
```
