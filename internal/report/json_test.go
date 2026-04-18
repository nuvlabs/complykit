package report

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/complykit/complykit/internal/engine"
)

func TestWriteJSON_CreatesFile(t *testing.T) {
	result := &engine.ScanResult{}
	result.Add(engine.Finding{
		CheckID: "test_check", Title: "Test Check",
		Status: engine.StatusFail, Severity: engine.SeverityCritical,
		Integration: "AWS/IAM", Remediation: "Fix it.",
		Controls: []engine.ControlRef{{Framework: engine.FrameworkSOC2, ID: "CC6.1"}},
	})
	result.Add(engine.Finding{CheckID: "test_pass", Title: "Pass", Status: engine.StatusPass})

	f, err := os.CreateTemp("", "report-*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.Close()

	if err := WriteJSON(result, "soc2", f.Name()); err != nil {
		t.Fatalf("WriteJSON failed: %v", err)
	}

	data, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}

	var report JSONReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}

	if report.Framework != "soc2" {
		t.Errorf("expected framework=soc2, got %s", report.Framework)
	}
	if report.Score != 50 {
		t.Errorf("expected score=50, got %d", report.Score)
	}
	if report.Summary.Failed != 1 || report.Summary.Passed != 1 {
		t.Errorf("unexpected summary: %+v", report.Summary)
	}
	if len(report.Findings) != 2 {
		t.Errorf("expected 2 findings, got %d", len(report.Findings))
	}
	if report.GeneratedAt == "" {
		t.Error("generated_at should not be empty")
	}
}

func TestWriteJSON_ControlsFormatted(t *testing.T) {
	result := &engine.ScanResult{}
	result.Add(engine.Finding{
		CheckID: "multi_control", Status: engine.StatusFail,
		Controls: []engine.ControlRef{
			{Framework: engine.FrameworkSOC2, ID: "CC6.1"},
			{Framework: engine.FrameworkHIPAA, ID: "164.312(d)"},
		},
	})

	f, err := os.CreateTemp("", "*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.Close()

	WriteJSON(result, "soc2", f.Name())

	data, _ := os.ReadFile(f.Name())
	var report JSONReport
	json.Unmarshal(data, &report)

	if len(report.Findings[0].Controls) != 2 {
		t.Errorf("expected 2 controls, got %d", len(report.Findings[0].Controls))
	}
}
