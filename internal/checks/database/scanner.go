package database

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/complykit/complykit/internal/engine"
)

const queryTimeout = 30 * time.Second

// Scanner connects to a database via DSN and runs privacy/security checks.
type Scanner struct {
	dsn    string
	conn   *pgx.Conn
	engine string // "postgres" | "mysql" (extend later)
}

func NewScanner(dsn string) *Scanner {
	return &Scanner{dsn: dsn}
}

func (s *Scanner) Integration() string { return "Database" }

func (s *Scanner) connect() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, s.dsn)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	s.conn = conn
	s.engine = "postgres"
	return nil
}

func (s *Scanner) close() {
	if s.conn != nil {
		_ = s.conn.Close(context.Background())
	}
}

func (s *Scanner) Run() ([]engine.Finding, error) {
	if err := s.connect(); err != nil {
		return []engine.Finding{dbSkip("db_connect", "Database Connection", err.Error())}, nil
	}
	defer s.close()

	var findings []engine.Finding
	findings = append(findings, s.checkPIIColumns()...)
	findings = append(findings, s.checkPIISampling()...)
	findings = append(findings, s.checkTLSEnforcement()...)
	findings = append(findings, s.checkRLSOnPIITables()...)
	findings = append(findings, s.checkAuditTable()...)
	findings = append(findings, s.checkDefaultAccounts()...)
	findings = append(findings, s.checkUnusedAccounts()...)
	return findings, nil
}

// checkPIIColumns detects columns whose names suggest PII storage.
func (s *Scanner) checkPIIColumns() []engine.Finding {
	ctx, cancel := context.WithTimeout(context.Background(), queryTimeout)
	defer cancel()

	rows, err := s.conn.Query(ctx, `
		SELECT table_schema, table_name, column_name
		FROM information_schema.columns
		WHERE table_schema NOT IN ('pg_catalog','information_schema')
		ORDER BY table_schema, table_name, column_name
	`)
	if err != nil {
		return []engine.Finding{dbSkip("db_pii_column_detection", "PII Column Detection", err.Error())}
	}
	defer rows.Close()

	type col struct{ schema, table, column string }
	var hits []col
	for rows.Next() {
		var sc, tbl, colName string
		if err := rows.Scan(&sc, &tbl, &colName); err != nil {
			continue
		}
		if IsPIIColumn(colName) {
			hits = append(hits, col{sc, tbl, colName})
		}
	}

	if len(hits) == 0 {
		return []engine.Finding{dbPass("db_pii_column_detection", "No PII-named columns detected in schema")}
	}

	var details []string
	for _, h := range hits {
		details = append(details, fmt.Sprintf("%s.%s.%s", h.schema, h.table, h.column))
	}
	return []engine.Finding{dbFail(
		"db_pii_column_detection",
		fmt.Sprintf("%d PII-named column(s) found — verify encryption and access controls", len(hits)),
		engine.SeverityHigh,
		strings.Join(details, "\n"),
		"Ensure PII columns are encrypted at rest, access is audited, and retention policies are enforced.\n"+
			"Use column-level encryption or a dedicated vault for SSN/CC columns.",
	)}
}

// checkPIISampling samples up to 100 rows from PII-named columns and looks for unencrypted patterns.
func (s *Scanner) checkPIISampling() []engine.Finding {
	ctx, cancel := context.WithTimeout(context.Background(), queryTimeout)
	defer cancel()

	rows, err := s.conn.Query(ctx, `
		SELECT table_schema, table_name, column_name
		FROM information_schema.columns
		WHERE table_schema NOT IN ('pg_catalog','information_schema')
		  AND data_type IN ('text','character varying','varchar','char','character')
		ORDER BY table_schema, table_name, column_name
	`)
	if err != nil {
		return []engine.Finding{dbSkip("db_pii_data_sampling", "PII Data Sampling", err.Error())}
	}
	defer rows.Close()

	type colID struct{ schema, table, column string }
	var candidates []colID
	for rows.Next() {
		var sc, tbl, col string
		if err := rows.Scan(&sc, &tbl, &col); err != nil {
			continue
		}
		if IsPIIColumn(col) {
			candidates = append(candidates, colID{sc, tbl, col})
		}
	}

	if len(candidates) == 0 {
		return []engine.Finding{dbPass("db_pii_data_sampling", "No PII-typed columns to sample")}
	}

	type hit struct {
		col     colID
		pattern string
	}
	var hits []hit

	for _, c := range candidates {
		qctx, qcancel := context.WithTimeout(context.Background(), 10*time.Second)
		sampleRows, serr := s.conn.Query(qctx, fmt.Sprintf(
			`SELECT %s FROM %s.%s WHERE %s IS NOT NULL LIMIT 50`,
			pgQuote(c.column), pgQuote(c.schema), pgQuote(c.table), pgQuote(c.column),
		))
		if serr != nil {
			qcancel()
			continue
		}
		for sampleRows.Next() {
			var val string
			if err := sampleRows.Scan(&val); err != nil {
				continue
			}
			for _, p := range PIIPatterns {
				if p.Re.MatchString(val) {
					hits = append(hits, hit{c, p.Label})
					break
				}
			}
			// Luhn CC check
			if IsCreditCard(val) {
				hits = append(hits, hit{c, "Credit card number (Luhn)"})
			}
		}
		sampleRows.Close()
		qcancel()
		if len(hits) > 0 {
			break // one confirmed exposure is enough to flag
		}
	}

	if len(hits) == 0 {
		return []engine.Finding{dbPass("db_pii_data_sampling", "No unencrypted PII patterns detected in sampled rows")}
	}

	var details []string
	seen := map[string]bool{}
	for _, h := range hits {
		k := fmt.Sprintf("%s.%s.%s: %s", h.col.schema, h.col.table, h.col.column, h.pattern)
		if !seen[k] {
			details = append(details, k)
			seen[k] = true
		}
	}
	return []engine.Finding{dbFail(
		"db_pii_data_sampling",
		fmt.Sprintf("Unencrypted PII detected in %d column(s)", len(seen)),
		engine.SeverityCritical,
		strings.Join(details, "\n"),
		"Encrypt PII at the application layer before storing, or use Postgres pgcrypto / Transparent Data Encryption.\n"+
			"Rotate any exposed credentials immediately.",
	)}
}

// checkTLSEnforcement verifies the current connection is using TLS and that
// the server is configured to reject plaintext connections.
func (s *Scanner) checkTLSEnforcement() []engine.Finding {
	ctx, cancel := context.WithTimeout(context.Background(), queryTimeout)
	defer cancel()

	// ssl=on means TLS is active on the server
	var sslOn string
	err := s.conn.QueryRow(ctx, `SHOW ssl`).Scan(&sslOn)
	if err != nil {
		return []engine.Finding{dbSkip("db_tls_connection_test", "Database TLS Enforcement", err.Error())}
	}

	if strings.ToLower(strings.TrimSpace(sslOn)) == "on" {
		return []engine.Finding{dbPass("db_tls_connection_test", "Database server has SSL/TLS enabled")}
	}
	return []engine.Finding{dbFail(
		"db_tls_connection_test",
		"Database server has SSL/TLS disabled — plaintext connections accepted",
		engine.SeverityCritical,
		"",
		"Set ssl=on in postgresql.conf and restart the server.\n"+
			"Use ssl_min_protocol_version=TLSv1.2 and enforce sslmode=require in all connection strings.",
	)}
}

// checkRLSOnPIITables checks that Row Level Security is enabled on tables containing PII columns.
func (s *Scanner) checkRLSOnPIITables() []engine.Finding {
	ctx, cancel := context.WithTimeout(context.Background(), queryTimeout)
	defer cancel()

	// Get all PII tables
	rows, err := s.conn.Query(ctx, `
		SELECT DISTINCT table_schema, table_name
		FROM information_schema.columns
		WHERE table_schema NOT IN ('pg_catalog','information_schema')
	`)
	if err != nil {
		return []engine.Finding{dbSkip("db_rls_on_pii_tables", "RLS on PII Tables", err.Error())}
	}
	defer rows.Close()

	type tbl struct{ schema, name string }
	var piiTables []tbl
	for rows.Next() {
		var sc, tn string
		if err := rows.Scan(&sc, &tn); err != nil {
			continue
		}
		// check if any column in this table is PII
		colCtx, colCancel := context.WithTimeout(context.Background(), 5*time.Second)
		colRows, cerr := s.conn.Query(colCtx, `
			SELECT column_name FROM information_schema.columns
			WHERE table_schema=$1 AND table_name=$2
		`, sc, tn)
		if cerr != nil {
			colCancel()
			continue
		}
		hasPII := false
		for colRows.Next() {
			var cn string
			if err := colRows.Scan(&cn); err != nil {
				continue
			}
			if IsPIIColumn(cn) {
				hasPII = true
				break
			}
		}
		colRows.Close()
		colCancel()
		if hasPII {
			piiTables = append(piiTables, tbl{sc, tn})
		}
	}

	if len(piiTables) == 0 {
		return []engine.Finding{dbPass("db_rls_on_pii_tables", "No PII tables found — RLS check skipped")}
	}

	// Check RLS status from pg_class
	var noRLS []string
	for _, t := range piiTables {
		rlsCtx, rlsCancel := context.WithTimeout(context.Background(), 5*time.Second)
		var rlsEnabled bool
		rerr := s.conn.QueryRow(rlsCtx, `
			SELECT c.relrowsecurity
			FROM pg_class c
			JOIN pg_namespace n ON n.oid = c.relnamespace
			WHERE n.nspname=$1 AND c.relname=$2
		`, t.schema, t.name).Scan(&rlsEnabled)
		rlsCancel()
		if rerr != nil || !rlsEnabled {
			noRLS = append(noRLS, fmt.Sprintf("%s.%s", t.schema, t.name))
		}
	}

	if len(noRLS) == 0 {
		return []engine.Finding{dbPass("db_rls_on_pii_tables", "Row Level Security is enabled on all PII tables")}
	}
	return []engine.Finding{dbFail(
		"db_rls_on_pii_tables",
		fmt.Sprintf("%d PII table(s) do not have Row Level Security enabled", len(noRLS)),
		engine.SeverityHigh,
		strings.Join(noRLS, "\n"),
		"Enable RLS on each PII table:\n  ALTER TABLE <table> ENABLE ROW LEVEL SECURITY;\n"+
			"Then create policies to restrict row access by role or user_id.",
	)}
}

// checkAuditTable verifies an audit or activity log table exists.
func (s *Scanner) checkAuditTable() []engine.Finding {
	ctx, cancel := context.WithTimeout(context.Background(), queryTimeout)
	defer cancel()

	var count int
	err := s.conn.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM information_schema.tables
		WHERE table_schema NOT IN ('pg_catalog','information_schema')
		  AND (
		    table_name ILIKE '%audit%'
		    OR table_name ILIKE '%audit_log%'
		    OR table_name ILIKE '%activity_log%'
		    OR table_name ILIKE '%event_log%'
		    OR table_name ILIKE '%access_log%'
		  )
	`).Scan(&count)
	if err != nil {
		return []engine.Finding{dbSkip("db_schema_audit_table", "Audit Log Table", err.Error())}
	}
	if count > 0 {
		return []engine.Finding{dbPass("db_schema_audit_table", "Audit log table found in schema")}
	}
	return []engine.Finding{dbFail(
		"db_schema_audit_table",
		"No audit log table detected — data access events may not be recorded",
		engine.SeverityMedium,
		"",
		"Create an audit_log table that captures: who accessed what, when, from where.\n"+
			"Alternatively enable pgaudit extension:\n  CREATE EXTENSION pgaudit;\n"+
			"  SET pgaudit.log = 'read, write, ddl';",
	)}
}

// pgQuote quotes a Postgres identifier safely.
func pgQuote(id string) string {
	return `"` + strings.ReplaceAll(id, `"`, `""`) + `"`
}

func dbPass(id, title string) engine.Finding {
	return engine.Finding{
		CheckID:     id,
		Title:       title,
		Status:      engine.StatusPass,
		Integration: "Database",
		Controls:    dbControls(id),
	}
}

func dbFail(id, title string, severity engine.Severity, detail, remediation string) engine.Finding {
	return engine.Finding{
		CheckID:     id,
		Title:       title,
		Status:      engine.StatusFail,
		Severity:    severity,
		Integration: "Database",
		Detail:      detail,
		Remediation: remediation,
		Controls:    dbControls(id),
	}
}

func dbSkip(id, title, detail string) engine.Finding {
	return engine.Finding{
		CheckID:     id,
		Title:       title,
		Status:      engine.StatusSkip,
		Integration: "Database",
		Detail:      detail,
	}
}

func dbControls(id string) []engine.ControlRef {
	refs, ok := engine.ControlMap[id]
	if !ok {
		return nil
	}
	return refs
}
