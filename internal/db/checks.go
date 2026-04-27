package db

import (
	"context"
	"encoding/json"
	"time"

	"github.com/complykit/complykit/internal/engine"
)

type CheckRow struct {
	ID          string           `json:"id"`
	Title       string           `json:"title"`
	Severity    string           `json:"severity"`
	Integration string           `json:"integration"`
	Frameworks  []string         `json:"frameworks"`
	Controls    []engine.ControlRef `json:"controls"`
	Enabled     bool             `json:"enabled"`
	CreatedAt   time.Time        `json:"created_at"`
	UpdatedAt   time.Time        `json:"updated_at"`
}

// UpsertChecks syncs the in-code registry into the DB.
// It inserts new checks and updates title/severity/integration/frameworks/controls
// for existing ones, but never changes the enabled flag (admins may have toggled it).
func (d *DB) UpsertChecks(ctx context.Context, checks []engine.CheckInfo) error {
	for _, c := range checks {
		fwJSON, _ := json.Marshal(c.Frameworks)
		ctrlJSON, _ := json.Marshal(c.Controls)
		_, err := d.Pool.Exec(ctx, `
			INSERT INTO compliance_checks (id, title, severity, integration, frameworks, controls)
			VALUES ($1, $2, $3, $4, $5, $6)
			ON CONFLICT (id) DO UPDATE SET
				title       = EXCLUDED.title,
				severity    = EXCLUDED.severity,
				integration = EXCLUDED.integration,
				frameworks  = EXCLUDED.frameworks,
				controls    = EXCLUDED.controls,
				updated_at  = now()
		`, c.ID, c.Title, c.Severity, c.Integration, fwJSON, ctrlJSON)
		if err != nil {
			return err
		}
	}
	return nil
}

// ListChecks returns all checks, optionally filtered by framework and/or integration.
// When includeDisabled is false, only enabled=true rows are returned.
func (d *DB) ListChecks(ctx context.Context, framework, integration string, includeDisabled bool) ([]CheckRow, error) {
	rows, err := d.Pool.Query(ctx, `
		SELECT id, title, severity, integration, frameworks, controls, enabled, created_at, updated_at
		FROM compliance_checks
		WHERE ($1 = '' OR frameworks @> $2::jsonb)
		  AND ($3 = '' OR lower(integration) = lower($3))
		  AND ($4 OR enabled = true)
		ORDER BY integration, id
	`, framework, jsonStrArray(framework), integration, includeDisabled)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []CheckRow
	for rows.Next() {
		var r CheckRow
		var fwRaw, ctrlRaw []byte
		if err := rows.Scan(&r.ID, &r.Title, &r.Severity, &r.Integration,
			&fwRaw, &ctrlRaw, &r.Enabled, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		json.Unmarshal(fwRaw, &r.Frameworks)
		json.Unmarshal(ctrlRaw, &r.Controls)
		out = append(out, r)
	}
	return out, rows.Err()
}

// UpdateCheck lets a super_admin toggle enabled or edit title/severity.
func (d *DB) UpdateCheck(ctx context.Context, id string, enabled *bool, title, severity string) error {
	_, err := d.Pool.Exec(ctx, `
		UPDATE compliance_checks SET
			enabled    = COALESCE($2, enabled),
			title      = CASE WHEN $3 <> '' THEN $3 ELSE title END,
			severity   = CASE WHEN $4 <> '' THEN $4 ELSE severity END,
			updated_at = now()
		WHERE id = $1
	`, id, enabled, title, severity)
	return err
}

// jsonStrArray encodes a single string as a JSON array element for @> containment queries.
func jsonStrArray(s string) string {
	if s == "" {
		return "[]"
	}
	b, _ := json.Marshal([]string{s})
	return string(b)
}
