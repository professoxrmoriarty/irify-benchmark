# Development Environment

This document covers build commands, development workflow, and environment setup for the irify-benchmark project.

## Tech Stack

| Layer | Technology |
|-------|------------|
| CLI / Backend | Go 1.22, cobra, sqlite3 (CGO), yaml.v3 |
| Frontend | React 19, TypeScript, Vite, Monaco Editor (`@monaco-editor/react`) |
| Build | make, npm |
| Testing | go test, bash e2e |

## Build Commands

```bash
# Default: build backend + frontend
make all

# Build Go backend only (outputs bin/irify-benchmark)
make build

# Build frontend only (outputs web/dist/)
make build-web

# Development mode: start frontend dev server (5173) + backend (8080)
make dev

# Production mode: start backend and serve static files
make serve          # default port 8080

# Run tests
go test ./...
make e2e

# Clean build artifacts
make clean
```

## Frontend Development

```bash
cd web
npm install
npm run dev        # Vite dev server (default 5173)
npm run build      # Production build → dist/
npm run preview    # Preview production build
```

> **SPA Fallback**: The app uses `BrowserRouter`. If you get 404 on direct access to deep routes (e.g. `/project/:id/results`), ensure `historyApiFallback: true` is set in `vite.config.ts` under `server`.

### Frontend API Configuration

`web/src/config.ts`:
```typescript
export const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:8081'
```

### Monaco Language Mapping

`CodeViewer.tsx` includes a built-in language map for common languages. To add a new language:
1. Add the mapping in `languageMap`
2. Monaco supports most languages natively—no extra configuration needed

### Routing

| Route | Page |
|-------|------|
| `/` | Dashboard (project list) |
| `/project/:id` | Project Explorer (file tree + case list + code) |
| `/project/:id/results` | Results / Evaluation |
| `/project/:id/results/scan` | Scan Results (raw engine findings) |
| `/project/:projectId/case/:caseId` | Case Detail (flow graph + code highlight) |
| `/review` | Review Queue |
| `/cases` | Case List (legacy v1) |

The app uses `BrowserRouter`; the backend is configured with SPA fallback.

### Adding New Pages (CRITICAL)

When adding a new page or route, always update the following to avoid orphaned pages or blank screens:
1. **`App.tsx` route registration** — add `<Route>`, check if the navbar `<NavLink>` needs updating
2. **`App.tsx` navbar** — ensure every nav link has a matching route
3. **Dashboard project cards** — if adding a project-level page, add an entry button on `Dashboard.tsx`
4. **Page return links** — breadcrumb / back links must point to valid routes
5. **Parameter fallback** — pages using `useParams` must handle missing params (show a selector or hint), never `if (!id) return` causing infinite loading
6. **Terminology consistency** — use the same name for the same concept everywhere (e.g., do not mix "Findings" and "Results")

## SQLite Path Rules

- Relative path: `data/benchmark.db`
- In production, the path is relative to the server's CWD; for CLI commands, relative to the execution directory
- **Common pitfall**: the server and CLI may connect to different database files (the server may start from a subdirectory of `irify-benchmark/`). When debugging, use `lsof` or `readlink /proc/<PID>/cwd` to verify the server's CWD.
