package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	dbchecks "github.com/complykit/complykit/internal/checks/database"
	"github.com/complykit/complykit/internal/engine"
)

var dbCmd = &cobra.Command{
	Use:   "db",
	Short: "Database privacy and security scanning",
	Example: `  comply db scan --dsn "postgres://readonly:pass@host:5432/mydb"
  comply db scan --dsn "postgres://..." --framework pci --output json`,
}

var dbScanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan a database for PII exposure and security misconfigurations",
	Long: `Connects to the target database using the provided DSN and runs:

  • PII column detection     — column names suggesting personal data
  • PII data sampling        — sample rows checked for SSN, email, CC numbers
  • TLS enforcement          — confirms server rejects plaintext connections
  • Row Level Security       — RLS enabled on PII tables (PostgreSQL)
  • Audit log table          — confirms an audit/activity log exists

Supported: PostgreSQL (pgx/v5). MySQL support coming in a future release.`,
	Example: `  comply db scan --dsn "postgres://readonly:pass@db.example.com:5432/prod"
  comply db scan --dsn "$DATABASE_URL" --framework hipaa --output json`,
	RunE: runDBScan,
}

func runDBScan(cmd *cobra.Command, _ []string) error {
	dsn, _ := cmd.Flags().GetString("dsn")
	if dsn == "" {
		dsn = os.Getenv("DATABASE_URL")
	}
	if dsn == "" {
		return fmt.Errorf("--dsn is required (or set DATABASE_URL)")
	}

	framework, _ := cmd.Flags().GetString("framework")
	outputFmt, _ := cmd.Flags().GetString("output")

	color.New(color.FgCyan, color.Bold).Println("\nComplyKit — Database Privacy Scan")
	color.New(color.Faint).Println(strings.Repeat("─", 60))

	scanner := dbchecks.NewScanner(dsn)
	findings, err := scanner.Run()
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	// Filter by framework if specified
	if framework != "" && framework != "all" {
		findings = filterByFramework(findings, framework)
	}

	switch outputFmt {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(findings)
	default:
		printDBResults(findings)
	}
	return nil
}

func printDBResults(findings []engine.Finding) {
	pass := color.New(color.FgGreen, color.Bold)
	fail := color.New(color.FgRed, color.Bold)
	skip := color.New(color.FgYellow)
	faint := color.New(color.Faint)

	var passed, failed, skipped int
	for _, f := range findings {
		switch f.Status {
		case engine.StatusPass:
			passed++
			pass.Printf("  ✓ ")
			fmt.Printf("[%s] %s\n", f.CheckID, f.Title)
		case engine.StatusFail:
			failed++
			fail.Printf("  ✗ ")
			fmt.Printf("[%s] %s", f.CheckID, f.Title)
			if f.Severity != "" {
				faint.Printf(" (%s)", f.Severity)
			}
			fmt.Println()
			if f.Detail != "" {
				lines := strings.Split(f.Detail, "\n")
				for _, l := range lines {
					faint.Printf("      %s\n", l)
				}
			}
			if f.Remediation != "" {
				color.New(color.FgYellow).Printf("    Remediation:\n")
				for _, l := range strings.Split(f.Remediation, "\n") {
					faint.Printf("      %s\n", l)
				}
			}
		case engine.StatusSkip:
			skipped++
			skip.Printf("  - ")
			fmt.Printf("[%s] %s", f.CheckID, f.Title)
			if f.Detail != "" {
				faint.Printf(" (%s)", f.Detail)
			}
			fmt.Println()
		}
	}

	color.New(color.Faint).Println(strings.Repeat("─", 60))
	score := 0
	total := passed + failed
	if total > 0 {
		score = passed * 100 / total
	}
	fmt.Printf("\n  Score: %d%%  |  Pass: %d  Fail: %d  Skip: %d\n\n",
		score, passed, failed, skipped)

	if failed > 0 {
		os.Exit(1)
	}
}

func filterByFramework(findings []engine.Finding, fw string) []engine.Finding {
	var out []engine.Finding
	for _, f := range findings {
		for _, c := range f.Controls {
			if strings.EqualFold(string(c.Framework), fw) {
				out = append(out, f)
				break
			}
		}
	}
	return out
}

func init() {
	dbScanCmd.Flags().String("dsn", "", "Database connection string (or set DATABASE_URL env var)")
	dbScanCmd.Flags().String("framework", "all", "Filter by framework: soc2, hipaa, pci, iso27001")
	dbScanCmd.Flags().StringP("output", "o", "text", "Output format: text, json")
	dbCmd.AddCommand(dbScanCmd)
	rootCmd.AddCommand(dbCmd)
}
