package db

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

type ShareLink struct {
	ID             string
	OrgID          string
	ScanID         string
	CreatedBy      string
	CreatedByEmail string
	Token          string
	Label          string
	ExpiresAt      time.Time
	CreatedAt      time.Time
}

func (d *DB) CreateShareLink(ctx context.Context, orgID, userID, scanID, label string, ttl time.Duration) (*ShareLink, error) {
	// verify scan belongs to this org
	var count int
	if err := d.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM scans WHERE id=$1 AND org_id=$2`, scanID, orgID,
	).Scan(&count); err != nil || count == 0 {
		return nil, fmt.Errorf("scan not found in your organization")
	}

	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	token := "sh_" + hex.EncodeToString(b)
	expiresAt := time.Now().Add(ttl)

	var sl ShareLink
	err := d.Pool.QueryRow(ctx, `
		INSERT INTO share_links (org_id, created_by, scan_id, token, label, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6)
		RETURNING id, org_id, created_by, scan_id, token, label, expires_at, created_at`,
		orgID, userID, scanID, token, label, expiresAt,
	).Scan(&sl.ID, &sl.OrgID, &sl.CreatedBy, &sl.ScanID, &sl.Token, &sl.Label, &sl.ExpiresAt, &sl.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("create share link: %w", err)
	}
	return &sl, nil
}

// ResolveShareToken validates the token and returns the scan_id + org it belongs to.
func (d *DB) ResolveShareToken(ctx context.Context, token string) (scanID string, org *Org, err error) {
	var o Org
	err = d.Pool.QueryRow(ctx, `
		SELECT sl.scan_id, o.id, o.slug, o.name, o.plan, o.created_at
		FROM share_links sl
		JOIN orgs o ON o.id = sl.org_id
		WHERE sl.token = $1 AND sl.expires_at > now()`,
		token,
	).Scan(&scanID, &o.ID, &o.Slug, &o.Name, &o.Plan, &o.CreatedAt)
	if err != nil {
		return "", nil, fmt.Errorf("invalid or expired share link")
	}
	return scanID, &o, nil
}

// ListShareLinks returns share links. Members see only their own; admins see all for the org.
func (d *DB) ListShareLinks(ctx context.Context, orgID, userID, role string) ([]ShareLink, error) {
	var query string
	var args []any

	if role == "admin" || role == "super_admin" {
		query = `
			SELECT sl.id, sl.org_id, sl.scan_id, sl.created_by, u.email,
			       sl.token, sl.label, sl.expires_at, sl.created_at
			FROM share_links sl
			JOIN users u ON u.id = sl.created_by
			WHERE sl.org_id = $1
			ORDER BY sl.created_at DESC`
		args = []any{orgID}
	} else {
		query = `
			SELECT sl.id, sl.org_id, sl.scan_id, sl.created_by, u.email,
			       sl.token, sl.label, sl.expires_at, sl.created_at
			FROM share_links sl
			JOIN users u ON u.id = sl.created_by
			WHERE sl.org_id = $1 AND sl.created_by = $2
			ORDER BY sl.created_at DESC`
		args = []any{orgID, userID}
	}

	rows, err := d.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var links []ShareLink
	for rows.Next() {
		var sl ShareLink
		if err := rows.Scan(&sl.ID, &sl.OrgID, &sl.ScanID, &sl.CreatedBy, &sl.CreatedByEmail,
			&sl.Token, &sl.Label, &sl.ExpiresAt, &sl.CreatedAt); err != nil {
			return nil, err
		}
		links = append(links, sl)
	}
	return links, rows.Err()
}

// RevokeShareLink deletes a share link. Admins can revoke any; members only their own.
func (d *DB) RevokeShareLink(ctx context.Context, id, orgID, userID, role string) error {
	var result interface{ RowsAffected() int64 }
	var err error

	if role == "admin" || role == "super_admin" {
		result, err = d.Pool.Exec(ctx,
			`DELETE FROM share_links WHERE id=$1 AND org_id=$2`, id, orgID)
	} else {
		result, err = d.Pool.Exec(ctx,
			`DELETE FROM share_links WHERE id=$1 AND org_id=$2 AND created_by=$3`, id, orgID, userID)
	}
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("share link not found or permission denied")
	}
	return nil
}
