package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/fatih/color"
	"github.com/spf13/cobra"

	awschecks "github.com/complykit/complykit/internal/checks/aws"
	"github.com/complykit/complykit/internal/engine"
	"github.com/complykit/complykit/internal/report"
)

var (
	flagFixFrom string
)

var fixCmd = &cobra.Command{
	Use:   "fix [check-id]",
	Short: "Show remediation steps for a specific check or all failures",
	Example: `  comply fix                           # show all failures with remediation
  comply fix aws_iam_root_mfa           # show fix for specific check
  comply fix --from report.json         # load from previous scan output`,
	RunE: runFix,
}

func init() {
	fixCmd.Flags().StringVar(&flagFixFrom, "from", "", "Load findings from a JSON report file")
	rootCmd.AddCommand(fixCmd)
}

func runFix(cmd *cobra.Command, args []string) error {
	bold := color.New(color.Bold)
	red := color.New(color.FgRed)
	dim := color.New(color.Faint)
	cyan := color.New(color.FgCyan, color.Bold)

	var findings []engine.Finding

	if flagFixFrom != "" {
		// load from JSON report
		data, err := os.ReadFile(flagFixFrom)
		if err != nil {
			return fmt.Errorf("cannot read report file: %w", err)
		}
		var jr report.JSONReport
		if err := json.Unmarshal(data, &jr); err != nil {
			return fmt.Errorf("invalid report file: %w", err)
		}
		for _, jf := range jr.Findings {
			if jf.Status == "fail" {
				findings = append(findings, engine.Finding{
					CheckID:     jf.ID,
					Title:       jf.Title,
					Status:      engine.StatusFail,
					Severity:    engine.Severity(jf.Severity),
					Integration: jf.Integration,
					Remediation: jf.Remediation,
				})
			}
		}
	} else {
		// run a fresh scan
		bold.Println("\n  Running scan to find failures...")
		opts := []func(*config.LoadOptions) error{}
		cfg, err := config.LoadDefaultConfig(context.Background(), opts...)
		if err != nil {
			return fmt.Errorf("AWS credentials not found: %w", err)
		}
		checkers := []engine.Checker{
			awschecks.NewIAMChecker(cfg),
			awschecks.NewS3Checker(cfg),
			awschecks.NewCloudTrailChecker(cfg),
			awschecks.NewSecurityGroupChecker(cfg),
		}
		for _, checker := range checkers {
			fs, _ := checker.Run()
			for _, f := range fs {
				if f.Status == engine.StatusFail {
					findings = append(findings, f)
				}
			}
		}
	}

	// filter by check ID if provided
	if len(args) > 0 {
		targetID := args[0]
		var filtered []engine.Finding
		for _, f := range findings {
			if f.CheckID == targetID {
				filtered = append(filtered, f)
			}
		}
		if len(filtered) == 0 {
			fmt.Printf("  No failure found with id: %s\n", targetID)
			return nil
		}
		findings = filtered
	}

	if len(findings) == 0 {
		color.New(color.FgGreen, color.Bold).Println("\n  No failures found — you're clean!")
		return nil
	}

	fmt.Println()
	bold.Printf("  %d failing check(s) with remediation steps:\n", len(findings))

	for i, f := range findings {
		fmt.Println()
		fmt.Printf("  %d. ", i+1)
		red.Printf("[%s] ", strings.ToUpper(string(f.Severity)))
		bold.Println(f.Title)
		dim.Printf("     Check ID: %s\n", f.CheckID)
		if f.Integration != "" {
			dim.Printf("     Integration: %s\n", f.Integration)
		}

		if f.Remediation != "" {
			fmt.Println()
			cyan.Println("     How to fix:")
			for _, line := range strings.Split(f.Remediation, "\n") {
				fmt.Printf("       %s\n", line)
			}
		}
	}
	fmt.Println()
	return nil
}
