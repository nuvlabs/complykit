package db

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const SystemOrgID = "00000000-0000-0000-0000-000000000000"

type User struct {
	ID        string
	OrgID     string
	Email     string
	Role      string
	CreatedAt time.Time
}

func (d *DB) CreateUser(ctx context.Context, orgID, email, password, role string) (*User, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}
	var u User
	err = d.Pool.QueryRow(ctx, `
		INSERT INTO users (org_id, email, password_hash, role)
		VALUES ($1, $2, $3, $4)
		RETURNING id, org_id, email, role, created_at`,
		orgID, email, string(hash), role,
	).Scan(&u.ID, &u.OrgID, &u.Email, &u.Role, &u.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("create user: %w", err)
	}
	return &u, nil
}

// SeedSuperAdmin creates or updates the super admin user from env vars.
func (d *DB) SeedSuperAdmin(ctx context.Context, email, password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = d.Pool.Exec(ctx, `
		INSERT INTO users (org_id, email, password_hash, role)
		VALUES ($1, $2, $3, 'super_admin')
		ON CONFLICT (email) DO UPDATE
		  SET password_hash = EXCLUDED.password_hash,
		      role = 'super_admin'`,
		SystemOrgID, email, string(hash),
	)
	return err
}

// AuthenticateUser verifies email+password and returns the user on success.
func (d *DB) AuthenticateUser(ctx context.Context, email, password string) (*User, error) {
	var u User
	var hash string
	err := d.Pool.QueryRow(ctx, `
		SELECT id, org_id, email, role, created_at, password_hash
		FROM users WHERE email = $1`, email,
	).Scan(&u.ID, &u.OrgID, &u.Email, &u.Role, &u.CreatedAt, &hash)
	if err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}
	return &u, nil
}

// ResetPassword sets a new password.
// orgID="" means super admin calling — no org restriction applied.
func (d *DB) ResetPassword(ctx context.Context, callerOrgID, targetEmail, newPassword string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	var tag string
	var queryErr error
	if callerOrgID == SystemOrgID || callerOrgID == "" {
		// super admin — can reset anyone
		var result interface{ RowsAffected() int64 }
		result, queryErr = d.Pool.Exec(ctx,
			`UPDATE users SET password_hash = $1 WHERE email = $2`,
			string(hash), targetEmail)
		if queryErr == nil && result.RowsAffected() == 0 {
			tag = "not_found"
		}
	} else {
		// org admin — can only reset users in their own org
		var result interface{ RowsAffected() int64 }
		result, queryErr = d.Pool.Exec(ctx,
			`UPDATE users SET password_hash = $1 WHERE email = $2 AND org_id = $3`,
			string(hash), targetEmail, callerOrgID)
		if queryErr == nil && result.RowsAffected() == 0 {
			tag = "not_found"
		}
	}
	if queryErr != nil {
		return queryErr
	}
	if tag == "not_found" {
		return fmt.Errorf("user %q not found in your organization", targetEmail)
	}
	return nil
}

// ListUsers returns all users for the given org. Super admin (SystemOrgID) gets all users.
func (d *DB) ListUsers(ctx context.Context, orgID string) ([]User, error) {
	var rows interface {
		Next() bool
		Scan(...any) error
		Close()
		Err() error
	}
	var err error

	if orgID == SystemOrgID {
		rows, err = d.Pool.Query(ctx,
			`SELECT id, org_id, email, role, created_at FROM users ORDER BY created_at DESC`)
	} else {
		rows, err = d.Pool.Query(ctx,
			`SELECT id, org_id, email, role, created_at FROM users WHERE org_id = $1 ORDER BY created_at DESC`, orgID)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.OrgID, &u.Email, &u.Role, &u.CreatedAt); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}
