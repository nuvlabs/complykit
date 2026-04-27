# ComplyKit — Agent Context

ComplyKit is a CLI + SaaS compliance scanner. It scans cloud infrastructure (AWS, GCP, Azure),
Kubernetes, GitHub, and Terraform against frameworks like SOC 2, HIPAA, CIS, ISO 27001, and PCI DSS.

## Repository Layout

```
cmd/
  scan.go          # CLI scan command — wires checkers, calls addFiltered()
  serve.go         # HTTP server — dashboard, API routes, DB seeding
  dashboard.html   # Embedded Go dashboard (port 8080, no build step)

internal/
  engine/
    types.go       # Finding, ScanResult, Checker interface, Framework/Status/Severity enums
    controls.go    # ControlMap: check ID → []ControlRef for ISO 27001 + PCI DSS enrichment
    registry.go    # Registry []CheckInfo: canonical catalog synced to DB on startup

  checks/
    aws/           # One file per integration (iam.go, s3.go, cloudtrail.go …)
                   # iso27001.go  — ISO 27001-specific AWS checks
                   # pcidss.go    — PCI DSS-specific AWS checks
    gcp/           # GCP checks
    azure/         # Azure checks
    kubernetes/    # Kubernetes checks
    github/        # GitHub org checks
    terraform/     # IaC static-analysis checks
    custom/        # User-defined checks from complykit.yaml
    policy/        # Cross-cutting policy checks

  db/
    db.go          # Postgres connect + migrate (runs all migrate/*.sql in order)
    checks.go      # UpsertChecks, ListChecks, UpdateCheck (compliance_checks table)
    migrate/
      001_init.sql … 005_checks_catalog.sql

complykit-ui/      # React + Vite frontend (served on port 3000 via nginx in Docker)
  src/
    views/
      Admin.tsx         # Orgs + Users management (admin/super_admin)
      ChecksCatalog.tsx # Checks browser with enable/disable toggles (super_admin only)
      Checks.tsx        # Standalone checks tab (super_admin only)
    api.ts              # All API calls — add new endpoints here
    types.ts            # TypeScript types — add new API response shapes here
```

## How the Check Pipeline Works

```
Checker.Run() → []Finding  →  addFiltered()  →  ScanResult
                                   │
                                   └─ engine.EnrichWithFrameworks(&f)  ← ControlMap
```

1. Each checker returns `[]engine.Finding` with `Controls []ControlRef` already set.
2. `addFiltered` in `cmd/scan.go` calls `EnrichWithFrameworks` to bolt on extra ISO 27001 /
   PCI DSS controls from `ControlMap`, then keeps only findings relevant to `--framework`.
3. `engine.Registry` (registry.go) is the catalog of all checks — synced to `compliance_checks`
   DB table on every `comply serve` startup via `UpsertChecks`.

## Key Rules for Agents

See `.github/ADDING_CHECKS.md` for the full step-by-step guide.

**Never** modify only one of these — they must all stay in sync:
- The checker file (`internal/checks/<integration>/<file>.go`)
- `internal/engine/controls.go` — ControlMap entry
- `internal/engine/registry.go` — Registry entry
- `cmd/scan.go` — wire the checker into `awsCheckers` (or equivalent) slice

**Framework constants** live in `internal/engine/types.go`:
`FrameworkSOC2`, `FrameworkHIPAA`, `FrameworkCIS`, `FrameworkISO27001`, `FrameworkPCIDSS`

**Never hardcode** framework strings — always use the constants.

## Adding a New Framework

See `.github/ADDING_CHECKS.md` → "Adding a new framework".
