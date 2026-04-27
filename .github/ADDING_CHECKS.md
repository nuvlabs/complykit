# Adding Checks and Frameworks to ComplyKit

This is the single source of truth for agents and contributors adding compliance checks.
**Read this completely before touching any file.**

---

## Anatomy of a Check

Every check has **four touch-points** that must all be updated together:

| # | File | What to add |
|---|------|-------------|
| 1 | `internal/checks/<integration>/<file>.go` | The check function that calls the cloud API |
| 2 | `internal/engine/controls.go` | `ControlMap` entry: check ID → ISO 27001 + PCI DSS control refs |
| 3 | `internal/engine/registry.go` | `Registry` entry: human-readable catalog row for the admin UI |
| 4 | `cmd/scan.go` | Wire the checker into the correct source slice |

Missing any one of these means the check either doesn't run, doesn't appear in the catalog,
or doesn't map to framework controls correctly.

---

## Step-by-Step: Adding a Check to an Existing Integration

### 1. Write the check function

Place it in the appropriate checker file, e.g. `internal/checks/aws/s3.go`.

```go
// Req <control> — <short description>
func (c *S3Checker) checkMyNewThing(add func(engine.Finding)) {
    // call AWS SDK …
    if bad {
        add(engine.Finding{
            CheckID:     "aws_s3_my_new_thing",        // snake_case, globally unique
            Title:       "S3 buckets have X enabled",  // plain English, no "check" suffix
            Status:      engine.StatusFail,
            Severity:    engine.SeverityHigh,           // critical | high | medium | low
            Integration: c.Integration(),               // reuse the checker's Integration()
            Resource:    strings.Join(failing, ", "),
            Remediation: "Run: aws s3 …",
            Controls: []engine.ControlRef{
                {engine.FrameworkSOC2, "CC6.1"},
                {engine.FrameworkCIS,  "2.1.5"},
            },
        })
        return
    }
    add(engine.Finding{
        CheckID: "aws_s3_my_new_thing", Title: "S3 buckets have X enabled",
        Status: engine.StatusPass, Integration: c.Integration(),
        Controls: []engine.ControlRef{{engine.FrameworkSOC2, "CC6.1"}},
    })
}
```

Call it from `Run()`:
```go
func (c *S3Checker) Run() ([]engine.Finding, error) {
    // …existing calls…
    c.checkMyNewThing(add)
    return findings, nil
}
```

**Check ID rules:**
- Format: `<integration>_<resource>_<what>` e.g. `aws_s3_versioning`, `gcp_sql_no_public_ip`
- Must be globally unique across all checkers
- Use only lowercase letters, digits, underscores

### 2. Add to ControlMap (`internal/engine/controls.go`)

```go
var ControlMap = map[string][]ControlRef{
    // … existing entries …
    "aws_s3_my_new_thing": {ISO27001("A.10.1.1"), PCIDSS("3.5.1")},
}
```

`EnrichWithFrameworks` automatically merges these into every finding that matches the check ID,
so you don't need to duplicate them in the checker itself.

### 3. Add to Registry (`internal/engine/registry.go`)

```go
var Registry = []CheckInfo{
    // … existing entries …
    {
        ID: "aws_s3_my_new_thing",
        Title: "S3 buckets have X enabled",
        Severity: "high",                        // must match what the checker sets
        Integration: "AWS/S3",                   // must match checker.Integration()
        Frameworks: []string{"soc2", "iso27001", "pcidss"},  // lowercase, all that apply
        Controls: []ControlRef{
            {FrameworkSOC2, "CC6.1"},
            ISO27001("A.10.1.1"),
            PCIDSS("3.5.1"),
        },
    },
}
```

The Registry is synced to the `compliance_checks` Postgres table on every `comply serve` startup
via `UpsertChecks`. New checks appear in the Admin → Checks Catalog automatically.

### 4. Wire the checker (`cmd/scan.go`)

For AWS checks, add to the `awsCheckers` slice:
```go
awsCheckers := []engine.Checker{
    // …existing checkers…
    awschecks.NewMyNewChecker(cfg),   // if it's a new checker struct
}
```

If you added the check to an existing checker struct (e.g. `S3Checker`), no change needed here —
the checker already runs.

### 5. Verify

```bash
go build ./...                          # must compile with zero errors
comply scan --framework soc2 --only aws # must include the new check in output
```

---

## Step-by-Step: Adding a New Integration (new cloud/service)

1. Create `internal/checks/<integration>/` directory.
2. Create `<integration>.go` with a `Checker` struct implementing `engine.Checker`:
   ```go
   type MyChecker struct { … }
   func (c *MyChecker) Integration() string { return "MyService" }
   func (c *MyChecker) Run() ([]engine.Finding, error) { … }
   ```
3. Add all check functions following the rules above.
4. Add all check IDs to `ControlMap` (controls.go).
5. Add all check IDs to `Registry` (registry.go).
6. In `cmd/scan.go`, add a new `if !want("<integration>") { … } else { … }` block, modelled
   on the existing AWS/GCP/GitHub blocks.
7. Add `--only <integration>` to the scan command's flag description string.

---

## Step-by-Step: Adding a New Framework

### Backend

1. **Add the constant** in `internal/engine/types.go`:
   ```go
   FrameworkMyNew Framework = "mynew"
   ```

2. **Add a helper** in `internal/engine/controls.go`:
   ```go
   func MyNew(id string) ControlRef {
       return ControlRef{Framework: FrameworkMyNew, ID: id}
   }
   ```

3. **Enrich existing checks** — for each check relevant to the new framework, add a
   `ControlMap` entry or add to an existing entry:
   ```go
   "aws_iam_root_mfa": {ISO27001("A.9.4.2"), PCIDSS("8.4.2"), MyNew("CTL-1.1")},
   ```

4. **Update Registry entries** — add `"mynew"` to the `Frameworks` slice for each applicable
   `CheckInfo` in `registry.go`.

5. **Update `cmd/scan.go` flag description**:
   ```go
   scanCmd.Flags().StringVarP(&flagFramework, "framework", "f", "soc2",
       "Compliance framework: soc2, hipaa, cis, iso27001, pcidss, mynew")
   ```

### Frontend

6. **Add to filter dropdown** in `complykit-ui/src/views/ChecksCatalog.tsx`:
   ```typescript
   const FRAMEWORKS = ['soc2', 'hipaa', 'cis', 'iso27001', 'pcidss', 'mynew']
   ```

7. **Add to filter dropdown** in `complykit-ui/src/views/Checks.tsx` (same `FRAMEWORKS` array).

---

## File Ownership Map

| What you're changing | Files to touch |
|----------------------|---------------|
| New check in existing integration | checker file, controls.go, registry.go |
| New checker struct | checker file, controls.go, registry.go, scan.go |
| New integration | new dir + files, controls.go, registry.go, scan.go |
| New framework | types.go, controls.go, registry.go, scan.go, ChecksCatalog.tsx, Checks.tsx |
| Admin UI only | complykit-ui/src/views/Admin.tsx |
| Checks catalog UI | complykit-ui/src/views/ChecksCatalog.tsx |
| API endpoint | cmd/serve.go + complykit-ui/src/api.ts + complykit-ui/src/types.ts |
| DB schema | internal/db/migrate/NNN_name.sql + internal/db/db.go (embed + migrate slice) |

---

## Naming Conventions

| Thing | Convention | Example |
|-------|-----------|---------|
| Check ID | `<integration>_<resource>_<what>` | `aws_s3_versioning` |
| Checker struct | `<Integration>Checker` | `ISO27001Checker` |
| Constructor | `New<Integration>Checker` | `NewISO27001Checker` |
| Integration() return | `<Provider>/<Service>` | `AWS/S3`, `GCP/IAM` |
| Framework constant | `Framework<Name>` | `FrameworkISO27001` |
| Migration file | `NNN_description.sql` (sequential) | `006_feature_flags.sql` |

---

## Common Mistakes to Avoid

- **Skipping the Registry entry** — the check runs but never appears in the Admin Checks Catalog.
- **Skipping the ControlMap entry** — the check has no ISO 27001 / PCI DSS controls in reports.
- **Mismatched CheckID** — if the ID in the checker differs from ControlMap/Registry, enrichment silently does nothing.
- **Hardcoding framework strings** — always use `engine.FrameworkSOC2` etc., never `"soc2"` directly in Go code.
- **Using StatusSkip for errors** — use `StatusSkip` only when the resource doesn't exist (e.g. no RDS instances). Use `StatusFail` for actual findings.
- **Forgetting to rebuild** — after editing `cmd/dashboard.html` or adding a DB migration, run `go build .` to re-embed.
