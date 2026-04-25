package db

import (
	"context"
	"fmt"
	"time"
)

type Org struct {
	ID        string
	Slug      string
	Name      string
	Plan      string
	CreatedAt time.Time
}

func (d *DB) GetOrgBySlug(ctx context.Context, slug string) (*Org, error) {
	row := d.Pool.QueryRow(ctx,
		`SELECT id, slug, name, plan, created_at FROM orgs WHERE slug = $1`, slug)
	var o Org
	if err := row.Scan(&o.ID, &o.Slug, &o.Name, &o.Plan, &o.CreatedAt); err != nil {
		return nil, fmt.Errorf("org not found: %w", err)
	}
	return &o, nil
}

func (d *DB) GetOrCreateOrg(ctx context.Context, slug, name string) (*Org, error) {
	_, err := d.Pool.Exec(ctx,
		`INSERT INTO orgs (slug, name) VALUES ($1, $2) ON CONFLICT (slug) DO NOTHING`,
		slug, name)
	if err != nil {
		return nil, fmt.Errorf("upsert org: %w", err)
	}
	return d.GetOrgBySlug(ctx, slug)
}

func (d *DB) CreateOrg(ctx context.Context, slug, name string) (*Org, error) {
	var o Org
	err := d.Pool.QueryRow(ctx,
		`INSERT INTO orgs (slug, name) VALUES ($1, $2)
		 RETURNING id, slug, name, plan, created_at`,
		slug, name,
	).Scan(&o.ID, &o.Slug, &o.Name, &o.Plan, &o.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("create org: %w", err)
	}
	return &o, nil
}

func (d *DB) ListOrgs(ctx context.Context) ([]Org, error) {
	rows, err := d.Pool.Query(ctx,
		`SELECT id, slug, name, plan, created_at FROM orgs
		 WHERE id != $1 ORDER BY created_at DESC`, SystemOrgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var orgs []Org
	for rows.Next() {
		var o Org
		if err := rows.Scan(&o.ID, &o.Slug, &o.Name, &o.Plan, &o.CreatedAt); err != nil {
			return nil, err
		}
		orgs = append(orgs, o)
	}
	return orgs, rows.Err()
}
