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

const defaultDir = ".complykit-evidence"

type Record struct {
	ID          string         `json:"id"`
	CollectedAt time.Time      `json:"collected_at"`
	Framework   string         `json:"framework"`
	Score       int            `json:"score"`
	Passed      int            `json:"passed"`
	Failed      int            `json:"failed"`
	Skipped     int            `json:"skipped"`
	Findings    []engine.Finding `json:"findings"`
}

type Store struct {
	dir string
}

func NewStore(dir string) *Store {
	if dir == "" {
		dir = defaultDir
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
