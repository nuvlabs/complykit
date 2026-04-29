package database

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/complykit/complykit/internal/engine"
)

// knownDefaultAccounts are usernames that should not exist in production
// databases — they are created by default installers and are a common attack vector.
var knownDefaultAccounts = []string{
	"postgres", "root", "sa", "mysql", "admin", "administrator",
	"oracle", "system", "sysdba", "mariadb", "test", "guest",
}

// checkDefaultAccounts looks for default database usernames that are still active.
// These accounts often have well-known default passwords or broad privileges.
func (s *Scanner) checkDefaultAccounts() []engine.Finding {
	ctx, cancel := context.WithTimeout(context.Background(), queryTimeout)
	defer cancel()

	rows, err := s.conn.Query(ctx, `
		SELECT usename
		FROM pg_catalog.pg_user
		WHERE usename != current_user
	`)
	if err != nil {
		return []engine.Finding{dbSkip("db_default_accounts", "Default DB Accounts", err.Error())}
	}
	defer rows.Close()

	var found []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			continue
		}
		lower := strings.ToLower(name)
		for _, def := range knownDefaultAccounts {
			if lower == def {
				found = append(found, name)
				break
			}
		}
	}

	if len(found) == 0 {
		return []engine.Finding{dbPass("db_default_accounts", "No default database accounts found")}
	}
	return []engine.Finding{dbFail(
		"db_default_accounts",
		fmt.Sprintf("%d default account(s) still active: %s", len(found), strings.Join(found, ", ")),
		engine.SeverityCritical,
		strings.Join(found, "\n"),
		"Rename or drop default accounts and create named accounts for each service:\n"+
			"  -- Rename: ALTER USER postgres RENAME TO myapp_db;\n"+
			"  -- Or drop: DROP USER IF EXISTS <name>;\n"+
			"Ensure no application connection string references a default username.",
	)}
}

// checkUnusedAccounts finds database users who have not logged in for 90+ days.
// Stale accounts are a persistent access risk if credentials are ever exposed.
func (s *Scanner) checkUnusedAccounts() []engine.Finding {
	ctx, cancel := context.WithTimeout(context.Background(), queryTimeout)
	defer cancel()

	// pg_stat_activity captures last activity; pg_user gives us all users.
	// We join with the last seen activity per user.
	rows, err := s.conn.Query(ctx, `
		SELECT u.usename,
		       MAX(a.backend_start) AS last_seen
		FROM pg_catalog.pg_user u
		LEFT JOIN pg_stat_activity a ON a.usename = u.usename
		WHERE u.usename != current_user
		  AND u.usename NOT IN ('pg_monitor','pg_read_all_settings','pg_read_all_stats',
		                        'pg_stat_scan_tables','pg_signal_backend','pg_read_server_files',
		                        'pg_write_server_files','pg_execute_server_program',
		                        'replication','replicator')
		GROUP BY u.usename
	`)
	if err != nil {
		return []engine.Finding{dbSkip("db_unused_accounts", "Unused DB Accounts", err.Error())}
	}
	defer rows.Close()

	cutoff := time.Now().UTC().Add(-90 * 24 * time.Hour)
	var stale []string
	for rows.Next() {
		var name string
		var lastSeen *time.Time
		if err := rows.Scan(&name, &lastSeen); err != nil {
			continue
		}
		if lastSeen == nil || lastSeen.Before(cutoff) {
			label := name + " (never logged in)"
			if lastSeen != nil {
				daysAgo := int(time.Since(*lastSeen).Hours() / 24)
				label = fmt.Sprintf("%s (last seen %d days ago)", name, daysAgo)
			}
			stale = append(stale, label)
		}
	}

	if len(stale) == 0 {
		return []engine.Finding{dbPass("db_unused_accounts", "All database accounts show recent activity (within 90 days)")}
	}
	return []engine.Finding{dbFail(
		"db_unused_accounts",
		fmt.Sprintf("%d database account(s) inactive for 90+ days", len(stale)),
		engine.SeverityMedium,
		strings.Join(stale, "\n"),
		"Disable or drop accounts that are no longer needed:\n"+
			"  -- Disable login: ALTER USER <name> NOLOGIN;\n"+
			"  -- Or drop: DROP USER IF EXISTS <name>;\n"+
			"Review quarterly and remove any account not tied to an active service or user.",
	)}
}
