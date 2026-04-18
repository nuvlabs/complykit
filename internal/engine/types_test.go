package engine

import "testing"

func TestScanResult_Add_PassIncrements(t *testing.T) {
	r := &ScanResult{}
	r.Add(Finding{Status: StatusPass})
	if r.Passed != 1 || r.Failed != 0 || r.Score != 100 {
		t.Errorf("expected passed=1 failed=0 score=100, got %+v", r)
	}
}

func TestScanResult_Add_FailIncrements(t *testing.T) {
	r := &ScanResult{}
	r.Add(Finding{Status: StatusFail})
	if r.Failed != 1 || r.Score != 0 {
		t.Errorf("expected failed=1 score=0, got %+v", r)
	}
}

func TestScanResult_Add_MixedScore(t *testing.T) {
	r := &ScanResult{}
	r.Add(Finding{Status: StatusPass})
	r.Add(Finding{Status: StatusPass})
	r.Add(Finding{Status: StatusPass})
	r.Add(Finding{Status: StatusFail})
	// 3 passed / 4 total = 75
	if r.Score != 75 {
		t.Errorf("expected score=75, got %d", r.Score)
	}
}

func TestScanResult_Add_SkipNotCounted(t *testing.T) {
	r := &ScanResult{}
	r.Add(Finding{Status: StatusPass})
	r.Add(Finding{Status: StatusSkip})
	// 1 pass / 1 total (skip excluded from score denominator)
	if r.Score != 100 {
		t.Errorf("skip should not affect score, got %d", r.Score)
	}
	if r.Skipped != 1 {
		t.Errorf("expected skipped=1, got %d", r.Skipped)
	}
}

func TestScanResult_Add_Empty(t *testing.T) {
	r := &ScanResult{}
	if r.Score != 0 {
		t.Errorf("empty result score should be 0")
	}
}
