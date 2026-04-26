package db

import (
	"context"
	_ "embed"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrate/001_init.sql
var migration001 string

//go:embed migrate/002_auth.sql
var migration002 string

//go:embed migrate/003_superadmin.sql
var migration003 string

//go:embed migrate/004_shares.sql
var migration004 string

type DB struct {
	Pool *pgxpool.Pool
}

func Connect(ctx context.Context, dsn string) (*DB, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("pgxpool.New: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("db ping: %w", err)
	}
	d := &DB{Pool: pool}
	if err := d.migrate(ctx); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return d, nil
}

func (d *DB) migrate(ctx context.Context) error {
	for _, sql := range []string{migration001, migration002, migration003, migration004} {
		if _, err := d.Pool.Exec(ctx, sql); err != nil {
			return err
		}
	}
	return nil
}

func (d *DB) Close() {
	d.Pool.Close()
}
