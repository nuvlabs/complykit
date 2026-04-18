package evidence

import (
	"os"
	"testing"

	"github.com/complykit/complykit/internal/engine"
)

func TestStore_SaveAndList(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)

	result := &engine.ScanResult{}
	result.Add(engine.Finding{Status: engine.StatusPass, CheckID: "test_pass", Title: "Test Pass"})
	result.Add(engine.Finding{Status: engine.StatusFail, CheckID: "test_fail", Title: "Test Fail", Severity: engine.SeverityCritical})

	path, err := store.Save(result, "soc2")
	if err != nil {
		t.Fatalf("Save failed: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("evidence file not created: %v", err)
	}

	records, err := store.List()
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}

	r := records[0]
	if r.Score != 50 {
		t.Errorf("expected score=50, got %d", r.Score)
	}
	if r.Passed != 1 || r.Failed != 1 {
		t.Errorf("expected passed=1 failed=1, got %+v", r)
	}
	if r.Framework != "soc2" {
		t.Errorf("expected framework=soc2, got %s", r.Framework)
	}
	if len(r.Findings) != 2 {
		t.Errorf("expected 2 findings, got %d", len(r.Findings))
	}
}

func TestStore_Latest_Empty(t *testing.T) {
	store := NewStore(t.TempDir())
	rec, err := store.Latest()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec != nil {
		t.Errorf("expected nil for empty store, got %v", rec)
	}
}

func TestStore_Latest_ReturnsNewest(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)

	r1 := &engine.ScanResult{}
	r1.Add(engine.Finding{Status: engine.StatusPass})
	store.Save(r1, "soc2")

	r2 := &engine.ScanResult{}
	r2.Add(engine.Finding{Status: engine.StatusFail})
	store.Save(r2, "hipaa")

	latest, err := store.Latest()
	if err != nil {
		t.Fatalf("Latest failed: %v", err)
	}
	// list is sorted descending by filename (timestamp), last saved = newest
	if latest == nil {
		t.Fatal("expected a record")
	}
}

func TestStore_List_MultipleRecords(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)

	for i := 0; i < 3; i++ {
		r := &engine.ScanResult{}
		r.Add(engine.Finding{Status: engine.StatusPass})
		if _, err := store.Save(r, "soc2"); err != nil {
			t.Fatalf("Save %d failed: %v", i, err)
		}
	}

	records, err := store.List()
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(records) != 3 {
		t.Errorf("expected 3 records, got %d", len(records))
	}
}
