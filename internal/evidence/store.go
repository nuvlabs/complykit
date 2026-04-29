package evidence

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/complykit/complykit/internal/engine"
)

// DefaultDir returns the default evidence directory: ~/.complykit/evidence
func DefaultDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		// Fallback to current directory if home is not available
		return ".complykit/evidence"
	}
	return filepath.Join(home, ".complykit", "evidence")
}

// IntegrationScore holds per-integration pass/fail counts and score.
type IntegrationScore struct {
	Score  int `json:"score"`
	Passed int `json:"passed"`
	Failed int `json:"failed"`
}

type Record struct {
	ID                string                      `json:"id"`
	CollectedAt       time.Time                   `json:"collected_at"`
	Framework         string                      `json:"framework"`
	Score             int                         `json:"score"`
	Passed            int                         `json:"passed"`
	Failed            int                         `json:"failed"`
	Skipped           int                         `json:"skipped"`
	Findings          []engine.Finding            `json:"findings"`
	IntegrationScores map[string]IntegrationScore `json:"integration_scores,omitempty"`
}

// ComputeIntegrationScores groups findings by Integration and returns per-integration scores.
// Skip findings are excluded (same as overall score).
func ComputeIntegrationScores(findings []engine.Finding) map[string]IntegrationScore {
	type counts struct{ passed, failed int }
	byIntg := map[string]*counts{}
	for _, f := range findings {
		if f.Integration == "" {
			continue
		}
		c := byIntg[f.Integration]
		if c == nil {
			c = &counts{}
			byIntg[f.Integration] = c
		}
		switch f.Status {
		case engine.StatusPass:
			c.passed++
		case engine.StatusFail:
			c.failed++
		}
	}
	out := make(map[string]IntegrationScore, len(byIntg))
	for intg, c := range byIntg {
		total := c.passed + c.failed
		score := 0
		if total > 0 {
			score = c.passed * 100 / total
		}
		out[intg] = IntegrationScore{Score: score, Passed: c.passed, Failed: c.failed}
	}
	return out
}

type Store struct {
	dir string
}

func NewStore(dir string) *Store {
	if dir == "" {
		dir = DefaultDir()
	}
	return &Store{dir: dir}
}

func (s *Store) Save(result *engine.ScanResult, framework string) (string, error) {
	if err := os.MkdirAll(s.dir, 0700); err != nil {
		return "", fmt.Errorf("cannot create evidence dir: %w", err)
	}

	now := time.Now().UTC()
	id := fmt.Sprintf("%s-%04d", now.Format("20060102-150405"), rand.Intn(10000))

	record := Record{
		ID:          id,
		CollectedAt: now,
		Framework:   framework,
		Score:       result.Score,
		Passed:      result.Passed,
		Failed:      result.Failed,
		Skipped:     result.Skipped,
		Findings:    result.Findings,
	}

	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return "", err
	}

	filename := filepath.Join(s.dir, fmt.Sprintf("scan-%s.json", id))
	if err := os.WriteFile(filename, data, 0600); err != nil {
		return "", err
	}
	return filename, nil
}

func (s *Store) List() ([]Record, error) {
	entries, err := filepath.Glob(filepath.Join(s.dir, "scan-*.json"))
	if err != nil {
		return nil, err
	}
	sort.Sort(sort.Reverse(sort.StringSlice(entries)))

	var records []Record
	for _, path := range entries {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var r Record
		if err := json.Unmarshal(data, &r); err != nil {
			continue
		}
		records = append(records, r)
	}
	return records, nil
}

func (s *Store) Latest() (*Record, error) {
	records, err := s.List()
	if err != nil || len(records) == 0 {
		return nil, err
	}
	return &records[0], nil
}

func (s *Store) Dir() string { return s.dir }
