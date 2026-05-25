# CLI Findings Query Design

> Date: 2026-05-25
> Scope: irify-benchmark CLI extension for AI-driven rule optimization

## Background

The irify-benchmark framework currently supports two automation pipelines:
1. AI analyzes a target range → CLI adds cases → human confirms cases
2. Yak scans a target range → results are parsed into benchmark → matched against vulnerabilities

Pipeline #2 lacks a CLI interface for AI agents to query scan results in a structured way. The AI needs to inspect findings, compare them against ground-truth cases, and use this data to optimize scanning rules.

## Requirements

1. **CLI raw scan access**: AI must be able to view the raw engine scan output via CLI
2. **CLI findings query**: AI must be able to query findings with match information (TP/FP/FN, match scores, case expectations)
3. **No frontend JSON rendering**: JSON viewing is CLI-only; frontend keeps the existing "Download Raw Scan" button but does not render JSON inline

## Decision: Hierarchical Query Approach

Selected over single-command export because:
- AI agents can execute multiple commands sequentially
- Data volume stays controllable per command
- Separates raw engine output from benchmark-processed findings
- Enables "overview → deep dive" analysis pattern

## CLI Command Structure

```bash
# View raw engine scan report (unprocessed JSON)
irify-benchmark raw-scan <project-id> [--engine=<engine>] [--version=<version>]

# Query parsed findings (overview)
irify-benchmark findings list <project-id> [--engine=<engine>] [--version=<version>]

# Query single finding with match details (deep dive)
irify-benchmark findings show <project-id> <finding-index> [--engine=<engine>] [--version=<version>]
```

### Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `project-id` | Yes | — | Project identifier |
| `finding-index` | Yes (show) | — | Zero-based index into the findings array |
| `--engine` | No | Latest scan | Engine name (e.g. `yaklang`) |
| `--version` | No | Latest scan | Engine version string |

When `--engine` and `--version` are both omitted, the CLI uses the most recent scan data available for the project.

## Output JSON Schemas

### `raw-scan` Output

Direct pass-through of the engine's original JSON report. No transformation is applied.

### `findings list` Output

```json
{
  "project_id": "java-cmdi-001",
  "project_name": "Java CMDi Demo",
  "engine": "yaklang",
  "engine_version": "1.2.3",
  "scan_time": "2026-05-20T10:00:00Z",
  "total_findings": 15,
  "findings": [
    {
      "index": 0,
      "rule_id": "java-cmdi-001",
      "rule_name": "Command Injection",
      "severity": "high",
      "confidence": "high",
      "source": {
        "file": "src/main/java/com/example/Vuln.java",
        "line": 42,
        "column": 10
      },
      "sink": {
        "file": "src/main/java/com/example/Vuln.java",
        "line": 45,
        "column": 20
      },
      "matched_case": "case-001",
      "match_status": "tp",
      "match_score": 0.95
    }
  ]
}
```

Field semantics:
- `match_status`: `tp` | `fp` | `fn` | `tn` | `null` (no case matched)
- `matched_case`: Matched case ID, or `null`
- `source` / `sink`: Extracted from `finding.flow.source/sink`

### `findings show` Output

```json
{
  "project_id": "java-cmdi-001",
  "project_name": "Java CMDi Demo",
  "engine": "yaklang",
  "finding": {
    "index": 0,
    "rule_id": "java-cmdi-001",
    "rule_name": "Command Injection",
    "severity": "high",
    "confidence": "high",
    "description": "存在命令注入漏洞...",
    "solution": "使用 ProcessBuilder 并校验输入...",
    "flow": {
      "source": {
        "file": "src/main/java/com/example/Vuln.java",
        "line": 42,
        "column": 10,
        "code": "String cmd = request.getParameter(\"cmd\");"
      },
      "sink": {
        "file": "src/main/java/com/example/Vuln.java",
        "line": 45,
        "column": 20,
        "code": "Runtime.getRuntime().exec(cmd);"
      },
      "sanitizers": []
    },
    "extra": {}
  },
  "match": {
    "matched_case": "case-001",
    "match_status": "tp",
    "match_score": 0.95,
    "match_details": {
      "source_match": 1.0,
      "sink_match": 1.0,
      "sanitizer_match": 0,
      "trace_complete": 1.0,
      "line_distance": 0
    },
    "case_expectation": {
      "case_id": "case-001",
      "expectation_type": "must_alert",
      "flow": {
        "source": { "file": "...", "line": 42 },
        "sink": { "file": "...", "line": 45 }
      }
    },
    "diagnosis": {
      "is_misaligned": false,
      "text": "位置与 Case 接近，请人工确认"
    }
  }
}
```

The `diagnosis` field reuses the same deviation logic as the frontend (`diagnoseFinding`): file mismatch detection and line offset threshold of 3 lines.

## Integration Points

### Command Registration

In `cmd/irify-benchmark/main.go`:

```go
findingsCmd := &cobra.Command{Use: "findings", Short: "Query findings"}
findingsListCmd := &cobra.Command{Use: "list <project-id>", ...}
findingsShowCmd := &cobra.Command{Use: "show <project-id> <finding-index>", ...}
rawScanCmd := &cobra.Command{Use: "raw-scan <project-id>", ...}

findingsCmd.AddCommand(findingsListCmd, findingsShowCmd)
rootCmd.AddCommand(findingsCmd, rawScanCmd)
```

### Data Access (Read-Only)

| Command | Store Method | Additional Reads |
|---------|-------------|------------------|
| `raw-scan` | `store.GetRawReport(projectID, engine, version)` | None |
| `findings list` | `store.GetFindings(...)` + `store.GetResults(...)` | None |
| `findings show` | `store.GetFindings(...)` + `store.GetResults(...)` | `cases/{id}/cases.yaml` for case expectation |

### Diagnosis Logic

The `diagnosis` block in `findings show` is computed inline in the CLI handler:
- File path comparison between `finding.flow.source/sink.file` and `case.expectation.flow.source/sink.file`
- Line distance calculation with a threshold of 3 lines
- Returns `is_misaligned: true` if file mismatch or line distance > 3

This logic mirrors the frontend `diagnoseFinding()` function in `FindingsPage.tsx`. Keeping it in the CLI handler avoids cross-module refactoring.

## Error Handling

| Scenario | Exit Code | stdout |
|----------|-----------|--------|
| Success | 0 | JSON payload |
| Project not found | 1 | `{"error":"project not found: xxx"}` |
| No scan data | 1 | `{"error":"no findings found for project xxx"}` |
| Finding index out of range | 1 | `{"error":"finding index 99 out of range (total: 15)"}` |
| Store read failure | 1 | `{"error":"..."}` |

## Frontend Impact

No changes to the frontend. The "Download Raw Scan" button on `FindingsPage` continues to work as a file download. JSON viewing is CLI-only.

## Scope Boundaries

- **No pipeline changes**: These are pure query commands; they do not trigger scans, matching, or result writes
- **No store schema changes**: Uses existing `HybridStore` read methods
- **No frontend code changes**: CLI-only feature
- **No matcher changes**: Reuses stored match results; does not re-run `FlowMatcher.Match()`

## Testing Strategy

- Unit tests for JSON schema validation against sample finding/match data
- E2E test: run `findings list` and `findings show` against a project with known data, verify JSON structure
- E2E test: run `raw-scan` and verify output matches the stored raw report byte-for-byte
