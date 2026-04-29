# UI + Score + PDF Plan

Four tracks to fix before Phase 3. Ordered by dependency.

---

## Current State

| Area | What exists | Gap |
|---|---|---|
| Checks Catalog | Registry synced to DB on `comply serve` | Phase 1+2 IDs not verified end-to-end |
| PDF export | `/api/export/:id?format=pdf` + Download button in Overview | No button in History; framework not prominent in PDF |
| Score Over Time | Single line — overall score | Goes down when new integrations added; no per-integration breakdown |
| DB schema | `scans` table: `score, passed, failed, skipped` | No `integration_scores` column |

---

## Track 1 — Checks Catalog Audit
**~2 hours · Go only · no DB change**

**Problem:** Phase 1+2 added 24 new check IDs. If any ID fires but has no Registry entry, it runs silently — never appears in the Admin Checks Catalog.

**Fix:**
- Add a startup validation in `cmd/serve.go` that compares Registry IDs against the DB catalog and logs a warning for any missing entry. This catches future drift automatically.
- Manually verify all Phase 1+2 IDs appear in `internal/engine/registry.go`.

**Files:**
- `cmd/serve.go` — add `validateRegistry()` call after `db.UpsertChecks()`
- `internal/engine/registry.go` — verify completeness

**Validation list (Phase 1+2):**
```
aws_rds_not_public          aws_rds_ssl_enforcement     aws_rds_deletion_protection
aws_rds_backup              aws_rds_iam_auth             aws_rds_multi_az
aws_rds_minor_upgrade       aws_rds_no_master_user_exposed
aws_ec2_db_ebs_encrypted    aws_ec2_db_no_public_ip      aws_ec2_db_sg_exposure
k8s_db_pvc_encrypted        k8s_db_no_public_service     k8s_db_not_root
k8s_db_secret_not_configmap tf_rds_ssl_mode              tf_db_hardcoded_password
aws_rds_overprivileged_iam  aws_secrets_manager_rotation github_db_credentials
```

---

## Track 2 — Per-Integration Score History
**~2 days · Go backend + React frontend**

### Root cause of score drop

When a new integration is added (e.g. Kubernetes), its failing checks are included in the overall score. The score drops even though no existing check regressed — you just added more coverage.

### Fix: store + display per-integration scores

**Step 1 — DB migration**

New column on `scans` table:
```sql
ALTER TABLE scans ADD COLUMN IF NOT EXISTS
  integration_scores JSONB NOT NULL DEFAULT '{}';
```

Shape: `{ "AWS/RDS": { "score": 85, "passed": 11, "failed": 2 }, "Kubernetes": { ... } }`

**Step 2 — Compute on save**

In `cmd/serve.go` `/api/push` handler and in `internal/db/store.go` local save:
```go
func computeIntegrationScores(findings []engine.Finding) map[string]IntegrationScore {
    // group findings by Integration field
    // for each group: passed/(passed+failed)*100
    // skip findings are excluded (same as overall score)
}
```

The `Finding.Integration` field already holds `"AWS/RDS"`, `"Kubernetes"`, `"GitHub"`, etc.

**Step 3 — Return in `/api/history`**

Add `integration_scores` to the `ScanRecord` and `HistoryRecord` response.

**Step 4 — Frontend chart rewrite** (`History.tsx`)

Replace single `<Line>` with one `<Line>` per integration, each with its own color.
Only draw a line for integrations that appeared in that scan (no phantom zeros for unscanned integrations — use `null` to create gaps in Recharts).

Integration color palette:
```
AWS/RDS          → #f97316  (orange)
AWS/EC2-Database → #fb923c  (light orange)
AWS/DB-Access    → #f59e0b  (amber)
Kubernetes       → #3b82f6  (blue)
GitHub           → #8b5cf6  (purple)
GCP              → #22c55e  (green)
Azure            → #06b6d4  (cyan)
Terraform        → #a78bfa  (violet)
Overall          → #6366f1  (indigo, dashed)
```

Chart features:
- All integration lines + dashed overall line
- Legend below chart: click to show/hide individual integrations
- Tooltip: shows all integration scores for that date
- Gap (broken line) when integration was not in a scan — never draws 0

**Step 5 — Types** (`types.ts`)

```ts
export interface IntegrationScore {
  score: number
  passed: number
  failed: number
}

export interface HistoryRecord {
  // existing fields ...
  integration_scores: Record<string, IntegrationScore>
}
```

---

## Track 3 — PDF Download in History View
**~0.5 day · React only**

**Problem:** PDF download button only exists in the Overview (latest scan). History view shows past scans but no way to export them.

**Fix:** Add a download icon button to each row in `History.tsx`.

```tsx
// Each history row gets:
<button
  onClick={(e) => { e.stopPropagation(); downloadPDF(r.id, r.framework, orgId) }}
  title="Download PDF"
>
  <Download size={14} />
</button>
```

`downloadPDF()` already exists in `api.ts` and calls `/api/export/:id?format=pdf` — no backend change needed.

---

## Track 4 — PDF Framework Context
**~0.5 day · Go `internal/report/` only**

**Problem:** PDF doesn't prominently show which framework was scanned or which integrations were covered.

**Fix:** Enhance `report.WritePDF()`:

1. **Header** — add framework badge + scan date + integration list
   ```
   ComplyKit Compliance Report
   Framework: PCI DSS v4.0          Scanned: 2026-04-28
   Integrations: AWS/RDS · AWS/EC2-Database · Kubernetes · GitHub
   ```

2. **Coverage summary** — before findings table, add a small breakdown:
   ```
   AWS/RDS         11 passed  2 failed   Score: 85
   Kubernetes       8 passed  4 failed   Score: 67
   GitHub           6 passed  0 failed   Score: 100
   ```

3. **Controls index** — at the end: list all framework controls referenced in the scan, grouped by control family (e.g. PCI Req 3, Req 4, Req 7...)

**Files:** `internal/report/pdf.go` (or wherever WritePDF lives)

---

## Implementation Order

```
Track 1  (2h)   → Verify checks appear in catalog — quick, unblocks confidence
Track 3  (4h)   → PDF button in History — quick UI win, no backend change
Track 4  (4h)   → Better PDF content — Go only
Track 2  (2d)   → Per-integration score history — biggest change, do last
```

---

## Track 2 Detail: Integration Score Data Flow

```
comply scan --push
     │
     ▼
cmd/serve.go /api/push
     │  receive findings[]
     │  computeIntegrationScores(findings) → map[string]IntegrationScore
     │
     ▼
db.SaveScan(score, passed, failed, skipped, findings, integration_scores)
     │
     ▼
scans table: { ..., integration_scores: {"AWS/RDS": {score:85,...}, ...} }
     │
     ▼
GET /api/history → []HistoryRecord{ ..., integration_scores: {...} }
     │
     ▼
History.tsx: render one <Line> per integration key in integration_scores
```

For local scans (no server push), `integration_scores` are computed from evidence JSON when loading history — no DB needed for CLI-only mode.

---

## Non-goals

- Changing the overall score formula — per-integration lines solve the confusion without touching it
- Retroactively computing `integration_scores` for old scans — old records just won't have per-integration lines (gaps shown)
