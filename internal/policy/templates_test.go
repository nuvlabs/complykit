package policy

import (
	"os"
	"strings"
	"testing"
)

func TestGenerate_CreatesAllFiles(t *testing.T) {
	dir := t.TempDir()
	written, err := Generate(dir, "Acme Inc", "Jane Smith", "CTO", "soc2")
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	templates := All()
	if len(written) != len(templates) {
		t.Errorf("expected %d files, got %d", len(templates), len(written))
	}

	for _, path := range written {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("file not created: %s", path)
		}
	}
}

func TestGenerate_InterpolatesCompanyName(t *testing.T) {
	dir := t.TempDir()
	written, err := Generate(dir, "TestCorp", "Alice", "CISO", "soc2")
	if err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(written[0])
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(string(data), "TestCorp") {
		t.Error("expected company name to appear in policy document")
	}
}

func TestGenerate_InterpolatesOwner(t *testing.T) {
	dir := t.TempDir()
	written, _ := Generate(dir, "Corp", "Bob Jones", "VP Engineering", "soc2")
	data, _ := os.ReadFile(written[0])
	content := string(data)

	if !strings.Contains(content, "Bob Jones") {
		t.Error("expected owner name in policy document")
	}
	if !strings.Contains(content, "VP Engineering") {
		t.Error("expected owner title in policy document")
	}
}

func TestAll_ReturnsExpectedPolicies(t *testing.T) {
	expected := []string{
		"access_control",
		"incident_response",
		"change_management",
		"data_classification",
		"vendor_management",
	}

	templates := All()
	if len(templates) != len(expected) {
		t.Fatalf("expected %d templates, got %d", len(expected), len(templates))
	}

	ids := make(map[string]bool)
	for _, tmpl := range templates {
		ids[tmpl.ID] = true
	}
	for _, id := range expected {
		if !ids[id] {
			t.Errorf("missing template: %s", id)
		}
	}
}
