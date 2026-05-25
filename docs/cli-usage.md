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

## Server

```bash
# Start REST API + static file serving
irify-benchmark server --port 8081 --static web/dist
```
