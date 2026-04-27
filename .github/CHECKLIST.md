# ComplyKit — Agent Checklist

This file is read by agents automatically. Every task involving checks, frameworks, or the
catalog must verify each applicable item before marking work complete.

---

## ✅ Adding or modifying a check

- [ ] Check ID is globally unique (`grep -r "check_id_here" internal/`)
- [ ] Check ID follows `<integration>_<resource>_<what>` format
- [ ] `CheckID`, `Title`, `Integration`, and `Severity` are identical in the checker file,
      `ControlMap` (controls.go), and `Registry` (registry.go)
- [ ] `ControlMap` entry added/updated in `internal/engine/controls.go`
- [ ] `Registry` entry added/updated in `internal/engine/registry.go`
- [ ] Checker wired into `cmd/scan.go` (if new checker struct)
- [ ] `go build ./...` passes with zero errors
- [ ] Check appears in `comply scan --framework <fw>` output
- [ ] Pass finding has no Severity set (only Fail findings carry severity)

## ✅ Adding a new integration (cloud/service)

- [ ] All items from "Adding or modifying a check" above
- [ ] New `internal/checks/<integration>/` directory created
- [ ] Checker implements `engine.Checker` interface (`Run()` + `Integration()`)
- [ ] `want("<integration>")` block added in `cmd/scan.go`
- [ ] `--only` flag description updated in `cmd/scan.go`
- [ ] Integration string matches across checker, ControlMap, Registry, and scan.go

## ✅ Adding a new framework

- [ ] `Framework<Name> Framework = "<name>"` constant added in `internal/engine/types.go`
- [ ] Helper `func MyNew(id string) ControlRef` added in `internal/engine/controls.go`
- [ ] Existing check `ControlMap` entries updated where the framework applies
- [ ] Existing `Registry` entries updated — `Frameworks` slice includes `"<name>"`
- [ ] `--framework` flag description updated in `cmd/scan.go`
- [ ] `FRAMEWORKS` array updated in `complykit-ui/src/views/ChecksCatalog.tsx`
- [ ] `FRAMEWORKS` array updated in `complykit-ui/src/views/Checks.tsx`
- [ ] Frontend rebuilt: `cd complykit-ui && npm run build`
- [ ] Docker images rebuilt and restarted: `docker-compose build && docker-compose up -d`

## ✅ Adding or modifying a DB migration

- [ ] New file `internal/db/migrate/NNN_description.sql` (sequential number)
- [ ] Embedded in `internal/db/db.go`: `//go:embed migrate/NNN_description.sql`
- [ ] Added to `migrate()` slice in `db.go`
- [ ] Migration is idempotent (`CREATE TABLE IF NOT EXISTS`, `ON CONFLICT DO UPDATE`)
- [ ] `go build ./...` passes

## ✅ Adding an API endpoint

- [ ] Handler added to `cmd/serve.go` on the correct mux (`mux` for public, `protected` for auth-required)
- [ ] Role check added if the endpoint is admin/super_admin only
- [ ] Corresponding function added to `complykit-ui/src/api.ts`
- [ ] Response type added to `complykit-ui/src/types.ts` if new shape
- [ ] Frontend rebuilt and Docker image updated

## ✅ Modifying the Admin or Checks Catalog UI

- [ ] `complykit-ui/src/views/Admin.tsx` — org/user management
- [ ] `complykit-ui/src/views/ChecksCatalog.tsx` — checks browser (super_admin, has error boundary)
- [ ] `complykit-ui/src/views/Checks.tsx` — standalone checks tab
- [ ] Role guard correct: `isSuperAdmin` for catalog, `isAdmin` for user management
- [ ] `npm run build` passes with zero TypeScript errors
- [ ] Docker UI image rebuilt: `docker-compose build ui && docker-compose up -d ui`
- [ ] Hard refresh browser after deploy (or open incognito) to bypass JS cache

## ✅ Before every PR

- [ ] `go build ./...` — zero errors
- [ ] `go vet ./...` — zero warnings
- [ ] `cd complykit-ui && npm run build` — zero TypeScript errors
- [ ] No hardcoded secrets, credentials, or passwords
- [ ] No direct string comparisons with framework names in Go (use constants)
- [ ] CLAUDE.md and this checklist updated if architecture changed

---

## Key file locations (quick reference)

| Purpose | File |
|---------|------|
| Check logic | `internal/checks/<integration>/<file>.go` |
| Control mappings | `internal/engine/controls.go` |
| Checks catalog | `internal/engine/registry.go` |
| Scan wiring | `cmd/scan.go` |
| API server | `cmd/serve.go` |
| Embedded dashboard | `cmd/dashboard.html` |
| DB migrations | `internal/db/migrate/NNN_*.sql` |
| DB methods | `internal/db/checks.go`, `internal/db/user.go`, etc. |
| Frontend API calls | `complykit-ui/src/api.ts` |
| Frontend types | `complykit-ui/src/types.ts` |
| Checks catalog UI | `complykit-ui/src/views/ChecksCatalog.tsx` |
| Admin UI | `complykit-ui/src/views/Admin.tsx` |
| App routing/tabs | `complykit-ui/src/App.tsx` |
