package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/fatih/color"
	"github.com/spf13/cobra"

	awschecks "github.com/complykit/complykit/internal/checks/aws"
	gcpchecks "github.com/complykit/complykit/internal/checks/gcp"
	ghchecks "github.com/complykit/complykit/internal/checks/github"
	"github.com/complykit/complykit/internal/engine"
	"github.com/complykit/complykit/internal/evidence"
	"github.com/complykit/complykit/internal/report"
)

var (
	flagFramework string
	flagProfile   string
	flagRegion    string
	flagOutput    string
	flagPDF       string
	flagGHToken   string
	flagGHOwner   string
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan your infrastructure for compliance issues",
	Example: `  comply scan --framework soc2
  comply scan --framework hipaa --profile prod
  comply scan --framework soc2 --github-owner myorg --output report.json`,
	RunE: runScan,
}

func init() {
	scanCmd.Flags().StringVarP(&flagFramework, "framework", "f", "soc2", "Compliance framework: soc2, hipaa, cis")
	scanCmd.Flags().StringVar(&flagProfile, "profile", "", "AWS profile (default: AWS_PROFILE or default)")
	scanCmd.Flags().StringVar(&flagRegion, "region", "", "AWS region (default: AWS_DEFAULT_REGION or us-east-1)")
	scanCmd.Flags().StringVarP(&flagOutput, "output", "o", "", "Write JSON report to file path (use - for stdout)")
	scanCmd.Flags().StringVar(&flagPDF, "pdf", "", "Write PDF report to file path (e.g. report.pdf)")
	scanCmd.Flags().StringVar(&flagGHToken, "github-token", "", "GitHub token (default: GITHUB_TOKEN env)")
	scanCmd.Flags().StringVar(&flagGHOwner, "github-owner", "", "GitHub org or user to scan (default: GITHUB_OWNER env)")
	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	bold := color.New(color.Bold)
	dim := color.New(color.Faint)

	bold.Printf("\n  ComplyKit — %s Scan\n\n", flagFramework)

	result := &engine.ScanResult{}

	// AWS checks
	dim.Println("  Loading AWS credentials...")
	opts := []func(*config.LoadOptions) error{}
	if flagProfile != "" {
		opts = append(opts, config.WithSharedConfigProfile(flagProfile))
	}
	if flagRegion != "" {
		opts = append(opts, config.WithRegion(flagRegion))
	}
	cfg, err := config.LoadDefaultConfig(context.Background(), opts...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  warning: AWS credentials not found (%v) — skipping AWS checks\n", err)
	} else {
		awsCheckers := []engine.Checker{
			awschecks.NewIAMChecker(cfg),
			awschecks.NewS3Checker(cfg),
			awschecks.NewCloudTrailChecker(cfg),
			awschecks.NewSecurityGroupChecker(cfg),
		}
		for _, checker := range awsCheckers {
			dim.Printf("  Scanning %s...\n", checker.Integration())
			findings, err := checker.Run()
			if err != nil {
				fmt.Fprintf(os.Stderr, "  warning: %s: %v\n", checker.Integration(), err)
				continue
			}
			for _, f := range findings {
				result.Add(f)
			}
		}
	}

	// GCP checks
	if checker := gcpchecks.NewCheckerFromEnv(); checker != nil {
		dim.Printf("  Scanning %s...\n", checker.Integration())
		findings, err := checker.Run()
		if err != nil {
			fmt.Fprintf(os.Stderr, "  warning: GCP: %v\n", err)
		} else {
			for _, f := range findings {
				result.Add(f)
			}
		}
	} else {
		dim.Println("  Skipping GCP (set GCP_PROJECT_ID env to enable)")
	}

	// GitHub checks
	token := flagGHToken
	if token == "" {
		token = os.Getenv("GITHUB_TOKEN")
	}
	owner := flagGHOwner
	if owner == "" {
		owner = os.Getenv("GITHUB_OWNER")
	}
	if token != "" && owner != "" {
		checker := ghchecks.NewChecker(token, owner)
		dim.Printf("  Scanning %s...\n", checker.Integration())
		findings, err := checker.Run()
		if err != nil {
			fmt.Fprintf(os.Stderr, "  warning: GitHub: %v\n", err)
		} else {
			for _, f := range findings {
				result.Add(f)
			}
		}
	} else {
		dim.Println("  Skipping GitHub (set GITHUB_TOKEN + GITHUB_OWNER or use --github-token/--github-owner)")
	}

	// print terminal report
	report.PrintResult(result, flagFramework)

	// write JSON if requested
	if flagOutput != "" {
		if err := report.WriteJSON(result, flagFramework, flagOutput); err != nil {
			return fmt.Errorf("failed to write JSON report: %w", err)
		}
	}

	// auto-save to evidence vault
	store := evidence.NewStore("")
	if path, err := store.Save(result, flagFramework); err != nil {
		dim.Printf("  warning: could not save evidence: %v\n", err)
	} else {
		dim.Printf("  Evidence saved → %s\n", path)
	}

	// write PDF if requested
	if flagPDF != "" {
		dim.Printf("  Generating PDF report...")
		if err := report.WritePDF(result, flagFramework, flagPDF); err != nil {
			return fmt.Errorf("failed to write PDF report: %w", err)
		}
		fmt.Printf("\r  PDF report written to %s\n", flagPDF)
	}

	return nil
}
