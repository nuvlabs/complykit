package db

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID           string
	OrgID        string
	Email        string
	Role         string
	CreatedAt    time.Time
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

// AuthenticateUser verifies email+password and returns the user on success.
func (d *DB) AuthenticateUser(ctx context.Context, email, password string) (*User, error) {
	var u User
	var hash string
	err := d.Pool.QueryRow(ctx, `
		SELECT id, org_id, email, role, created_at, password_hash
		FROM users WHERE email = $1`, email,
	).Scan(&u.ID, &u.OrgID, &u.Email, &u.Role, &u.CreatedAt, &hash)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}
	return &u, nil
}
