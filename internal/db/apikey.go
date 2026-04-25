package db

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type APIKey struct {
	ID        string
	OrgID     string
	Name      string
	KeyPrefix string
	CreatedAt time.Time
}

// CreateAPIKey generates a new key, stores its bcrypt hash, returns the raw key once.
func (d *DB) CreateAPIKey(ctx context.Context, orgID, name string) (rawKey string, meta *APIKey, err error) {
	b := make([]byte, 24)
	if _, err = rand.Read(b); err != nil {
		return "", nil, fmt.Errorf("rand: %w", err)
	}
	rawKey = "ck_" + hex.EncodeToString(b)
	prefix := rawKey[:10] + "..."

	hash, err := bcrypt.GenerateFromPassword([]byte(rawKey), bcrypt.DefaultCost)
	if err != nil {
		return "", nil, fmt.Errorf("hash key: %w", err)
	}

	meta = &APIKey{}
	err = d.Pool.QueryRow(ctx, `
		INSERT INTO api_keys (org_id, name, key_hash, key_prefix)
		VALUES ($1, $2, $3, $4)
		RETURNING id, org_id, name, key_prefix, created_at`,
		orgID, name, string(hash), prefix,
	).Scan(&meta.ID, &meta.OrgID, &meta.Name, &meta.KeyPrefix, &meta.CreatedAt)
	if err != nil {
		return "", nil, fmt.Errorf("insert api key: %w", err)
	}
	return rawKey, meta, nil
}

// ResolveAPIKey finds the org for a raw key by checking bcrypt hashes.
func (d *DB) ResolveAPIKey(ctx context.Context, rawKey string) (*Org, error) {
	rows, err := d.Pool.Query(ctx, `
		SELECT ak.key_hash, o.id, o.slug, o.name, o.plan, o.created_at
		FROM api_keys ak
		JOIN orgs o ON o.id = ak.org_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var hash string
		var o Org
		if err := rows.Scan(&hash, &o.ID, &o.Slug, &o.Name, &o.Plan, &o.CreatedAt); err != nil {
			continue
		}
		if bcrypt.CompareHashAndPassword([]byte(hash), []byte(rawKey)) == nil {
			return &o, nil
		}
	}
	return nil, fmt.Errorf("invalid api key")
}

func (d *DB) ListAPIKeys(ctx context.Context, orgID string) ([]APIKey, error) {
	rows, err := d.Pool.Query(ctx, `
		SELECT id, org_id, name, key_prefix, created_at
		FROM api_keys WHERE org_id = $1 ORDER BY created_at DESC`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var keys []APIKey
	for rows.Next() {
		var k APIKey
		if err := rows.Scan(&k.ID, &k.OrgID, &k.Name, &k.KeyPrefix, &k.CreatedAt); err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}
