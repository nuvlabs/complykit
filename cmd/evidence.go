package cmd

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/complykit/complykit/internal/evidence"
)

var evidenceCmd = &cobra.Command{
	Use:   "evidence",
	Short: "Manage the compliance evidence vault",
}

var evidenceListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all collected evidence records",
	RunE:  runEvidenceList,
}

var evidenceShowCmd = &cobra.Command{
	Use:   "show [scan-id]",
	Short: "Show findings for a specific evidence record (defaults to latest)",
	RunE:  runEvidenceShow,
}

func init() {
	evidenceCmd.AddCommand(evidenceListCmd)
	evidenceCmd.AddCommand(evidenceShowCmd)
	rootCmd.AddCommand(evidenceCmd)
}

func runEvidenceList(cmd *cobra.Command, args []string) error {
	bold := color.New(color.Bold)
	dim := color.New(color.Faint)
	green := color.New(color.FgGreen)
	red := color.New(color.FgRed)
	cyan := color.New(color.FgCyan)

	store := evidence.NewStore("")
	records, err := store.List()
	if err != nil {
		return fmt.Errorf("cannot read evidence store: %w", err)
	}

	if len(records) == 0 {
		fmt.Println("\n  No evidence collected yet. Run `comply scan` to collect evidence.")
		return nil
	}

	fmt.Println()
	bold.Printf("  Evidence Vault — %d record(s) in %s\n\n", len(records), store.Dir())
	cyan.Printf("  %-20s  %-10s  %-6s  %-8s  %-8s\n", "SCAN ID", "FRAMEWORK", "SCORE", "PASSED", "FAILED")
	dim.Println("  " + strings.Repeat("─", 60))

	for _, r := range records {
		scoreColor := green
		if r.Score < 50 {
			scoreColor = red
		} else if r.Score < 80 {
			scoreColor = color.New(color.FgYellow)
		}

		fmt.Printf("  %-20s  %-10s  ", r.ID, r.Framework)
		scoreColor.Printf("%-6d", r.Score)
		fmt.Printf("  ")
		green.Printf("%-8d", r.Passed)
		red.Printf("%-8d\n", r.Failed)
	}

	fmt.Println()
	dim.Println("  Run `comply evidence show [scan-id]` to see full findings for a record.")
	fmt.Println()
	return nil
}

func runEvidenceShow(cmd *cobra.Command, args []string) error {
	bold := color.New(color.Bold)
	dim := color.New(color.Faint)
	green := color.New(color.FgGreen)
	red := color.New(color.FgRed)
	cyan := color.New(color.FgCyan)

	store := evidence.NewStore("")

	var record *evidence.Record
	if len(args) > 0 {
		records, err := store.List()
		if err != nil {
			return err
		}
		for _, r := range records {
			r := r
			if r.ID == args[0] {
				record = &r
				break
			}
		}
		if record == nil {
			return fmt.Errorf("no evidence record with id: %s", args[0])
		}
	} else {
		var err error
		record, err = store.Latest()
		if err != nil || record == nil {
			fmt.Println("\n  No evidence collected yet. Run `comply scan` first.")
			return nil
		}
	}

	fmt.Println()
	bold.Printf("  Evidence Record: %s\n", record.ID)
	dim.Printf("  Collected: %s | Framework: %s | Score: %d/100\n\n",
		record.CollectedAt.Format("2006-01-02 15:04:05 UTC"), record.Framework, record.Score)

	currentIntegration := ""
	for _, f := range record.Findings {
		if f.Integration != currentIntegration {
			currentIntegration = f.Integration
			fmt.Println()
			cyan.Printf("  [%s]\n", currentIntegration)
		}
		switch f.Status {
		case "pass":
			green.Print("  ✓ ")
		case "fail":
			red.Print("  ✗ ")
		default:
			dim.Print("  ~ ")
		}
		fmt.Println(f.Title)
	}
	fmt.Println()
	return nil
}
