package db

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/complykit/complykit/internal/engine"
	"github.com/complykit/complykit/internal/evidence"
)

// OrgStore is a PostgreSQL-backed evidence store scoped to one org.
type OrgStore struct {
	db    *DB
	orgID string
}

func NewOrgStore(db *DB, orgID string) *OrgStore {
	return &OrgStore{db: db, orgID: orgID}
}

// SaveRecord imports a full evidence.Record preserving its original collected_at timestamp.
func (s *OrgStore) SaveRecord(ctx context.Context, rec *evidence.Record) (string, error) {
	findings, err := json.Marshal(rec.Findings)
	if err != nil {
		return "", fmt.Errorf("marshal findings: %w", err)
	}
	intgScores := evidence.ComputeIntegrationScores(rec.Findings)
	intgJSON, err := json.Marshal(intgScores)
	if err != nil {
		return "", fmt.Errorf("marshal integration_scores: %w", err)
	}
	var id string
	err = s.db.Pool.QueryRow(ctx, `
		INSERT INTO scans (org_id, framework, score, passed, failed, skipped, findings, integration_scores, collected_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id`,
		s.orgID, rec.Framework, rec.Score, rec.Passed, rec.Failed, rec.Skipped, findings, intgJSON, rec.CollectedAt,
	).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("insert scan: %w", err)
	}
	return id, nil
}

func (s *OrgStore) Save(ctx context.Context, result *engine.ScanResult, framework string) (string, error) {
	findings, err := json.Marshal(result.Findings)
	if err != nil {
		return "", fmt.Errorf("marshal findings: %w", err)
	}
	intgScores := evidence.ComputeIntegrationScores(result.Findings)
	intgJSON, err := json.Marshal(intgScores)
	if err != nil {
		return "", fmt.Errorf("marshal integration_scores: %w", err)
	}
	var id string
	err = s.db.Pool.QueryRow(ctx, `
		INSERT INTO scans (org_id, framework, score, passed, failed, skipped, findings, integration_scores)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id`,
		s.orgID, framework, result.Score, result.Passed, result.Failed, result.Skipped, findings, intgJSON,
	).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("insert scan: %w", err)
	}
	return id, nil
}

func (s *OrgStore) Latest(ctx context.Context) (*evidence.Record, error) {
	row := s.db.Pool.QueryRow(ctx, `
		SELECT id, org_id, framework, score, passed, failed, skipped, findings, integration_scores, collected_at
		FROM scans
		WHERE org_id = $1
		ORDER BY collected_at DESC
		LIMIT 1`,
		s.orgID,
	)
	return scanRecord(row)
}

func (s *OrgStore) List(ctx context.Context) ([]evidence.Record, error) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, org_id, framework, score, passed, failed, skipped, findings, integration_scores, collected_at
		FROM scans
		WHERE org_id = $1
		ORDER BY collected_at DESC`,
		s.orgID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []evidence.Record
	for rows.Next() {
		r, err := scanRecord(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, *r)
	}
	return records, rows.Err()
}

func (s *OrgStore) GetByID(ctx context.Context, id string) (*evidence.Record, error) {
	row := s.db.Pool.QueryRow(ctx, `
		SELECT id, org_id, framework, score, passed, failed, skipped, findings, integration_scores, collected_at
		FROM scans
		WHERE org_id = $1 AND id = $2`,
		s.orgID, id,
	)
	return scanRecord(row)
}

type scanner interface {
	Scan(dest ...any) error
}

func scanRecord(row scanner) (*evidence.Record, error) {
	var (
		r             evidence.Record
		orgID         string
		findingsJSON  []byte
		intgJSON      []byte
		collectedAt   time.Time
	)
	err := row.Scan(&r.ID, &orgID, &r.Framework, &r.Score, &r.Passed, &r.Failed, &r.Skipped,
		&findingsJSON, &intgJSON, &collectedAt)
	if err != nil {
		return nil, err
	}
	r.CollectedAt = collectedAt
	if err := json.Unmarshal(findingsJSON, &r.Findings); err != nil {
		return nil, fmt.Errorf("unmarshal findings: %w", err)
	}
	if len(intgJSON) > 0 && string(intgJSON) != "{}" {
		if err := json.Unmarshal(intgJSON, &r.IntegrationScores); err != nil {
			return nil, fmt.Errorf("unmarshal integration_scores: %w", err)
		}
	}
	return &r, nil
}
