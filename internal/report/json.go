package report

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/complykit/complykit/internal/engine"
)

// JSONReport is exported so cmd/fix can deserialize saved scan reports.
type JSONReport struct {
	GeneratedAt string            `json:"generated_at"`
	Framework   string            `json:"framework"`
	Score       int               `json:"score"`
	Summary     JSONSummary       `json:"summary"`
	Findings    []JSONFinding     `json:"findings"`
}

type JSONSummary struct {
	Total   int `json:"total"`
	Passed  int `json:"passed"`
	Failed  int `json:"failed"`
	Skipped int `json:"skipped"`
}

type JSONFinding struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Status      string   `json:"status"`
	Severity    string   `json:"severity,omitempty"`
	Integration string   `json:"integration"`
	Resource    string   `json:"resource,omitempty"`
	Controls    []string `json:"controls,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
}

func WriteJSON(result *engine.ScanResult, framework, path string) error {
	report := JSONReport{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Framework:   framework,
		Score:       result.Score,
		Summary: JSONSummary{
			Total:   result.Passed + result.Failed + result.Skipped,
			Passed:  result.Passed,
			Failed:  result.Failed,
			Skipped: result.Skipped,
		},
	}

	for _, f := range result.Findings {
		jf := JSONFinding{
			ID:          f.CheckID,
			Title:       f.Title,
			Status:      string(f.Status),
			Severity:    string(f.Severity),
			Integration: f.Integration,
			Resource:    f.Resource,
			Remediation: f.Remediation,
		}
		for _, c := range f.Controls {
			jf.Controls = append(jf.Controls, fmt.Sprintf("%s/%s", c.Framework, c.ID))
		}
		report.Findings = append(report.Findings, jf)
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}

	if path == "-" {
		fmt.Println(string(data))
		return nil
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return err
	}
	fmt.Printf("  Report written to %s\n", path)
	return nil
}
