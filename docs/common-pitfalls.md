# Common Pitfalls

This document collects recurring issues and their solutions when developing or operating irify-benchmark.

## 1. SQLite NULL Scan Error

`pending_review.original_finding_json` can be NULL. Scanning into a plain `string` fails:
```
sql: Scan error on column index 4: converting NULL to string is unsupported
```
**Fix**: use `sql.NullString`.

## 2. Database Path Mismatch

The server and CLI may connect to different `data/benchmark.db` files depending on CWD.

**Diagnosis**:
```bash
# Check the server's CWD
readlink /proc/<PID>/cwd
# Or query directly via SQLite
sqlite3 data/benchmark.db "SELECT * FROM pending_review"
```

## 3. Frontend Data Parsing Resilience

API response structures may vary across versions (e.g., top-level fields in `cases.yaml`). The frontend should defensively parse:
```typescript
setFiles(fileTree.entries || fileTree || [])
setCases(caseData.cases || caseData || [])
```

## 4. SPA Fallback Path Traversal

The static file server's SPA fallback must prevent path traversal. Current implementation:
```go
absPath, _ := filepath.Abs(fullPath)
absBase, _ := filepath.Abs(filepath.Join("cases", projectID, "src"))
if !strings.HasPrefix(absPath, absBase+string(filepath.Separator)) && absPath != absBase {
    http.Error(w, "Invalid path", http.StatusForbidden)
    return
}
```

## 5. CGO and Cross-Compilation

The SQLite driver `github.com/mattn/go-sqlite3` requires CGO. For cross-compilation:
```bash
# Linux AMD64
CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build ...
# Or disable SQLite-related code for a pure-Go build
```
