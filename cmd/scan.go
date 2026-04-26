package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/fatih/color"
	"github.com/spf13/cobra"

	awschecks "github.com/complykit/complykit/internal/checks/aws"
	azchecks "github.com/complykit/complykit/internal/checks/azure"
	gcpchecks "github.com/complykit/complykit/internal/checks/gcp"
	ghchecks "github.com/complykit/complykit/internal/checks/github"
	k8schecks "github.com/complykit/complykit/internal/checks/kubernetes"
	policychecks "github.com/complykit/complykit/internal/checks/policy"
	"github.com/complykit/complykit/internal/credentials"
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
	flagPush      bool
	flagGHToken   string
	flagGHOwner   string
	flagOnly      string
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
	scanCmd.Flags().StringVar(&flagOnly, "only", "", "Comma-separated sources to scan: aws,gcp,azure,kubernetes,github (default: all)")
	scanCmd.Flags().BoolVar(&flagPush, "push", false, "Push results to ComplyKit server (uses credentials from `comply login`)")
	rootCmd.AddCommand(scanCmd)
}

func want(source string) bool {
	if flagOnly == "" {
		return true
	}
	for _, s := range strings.Split(flagOnly, ",") {
		if strings.EqualFold(strings.TrimSpace(s), source) {
			return true
		}
	}
	return false
}

// addFiltered adds findings that are relevant to the selected framework.
// Skipped findings (no controls) always pass through so coverage gaps are visible.
func addFiltered(result *engine.ScanResult, findings []engine.Finding, framework string) {
	fw := engine.Framework(strings.ToLower(framework))
	for _, f := range findings {
		if f.Status == engine.StatusSkip {
			result.Add(f)
			continue
		}
		for _, c := range f.Controls {
			if c.Framework == fw {
				result.Add(f)
				break
			}
		}
	}
}

func runScan(cmd *cobra.Command, args []string) error {
	bold := color.New(color.Bold)
	dim := color.New(color.Faint)

	// Apply saved config as env var fallbacks (env vars still take precedence)
	if cfg, err := credentials.LoadConfig(); err == nil && cfg != nil {
		cfg.ApplyToEnv()
	}

	bold.Printf("\n  ComplyKit — %s Scan\n\n", flagFramework)

	result := &engine.ScanResult{}

	// AWS checks
	if !want("aws") {
		dim.Println("  Skipping AWS (not in --only)")
	} else {
		dim.Println("  Loading AWS credentials...")
		opts := []func(*awsconfig.LoadOptions) error{}
		if flagProfile != "" {
			opts = append(opts, awsconfig.WithSharedConfigProfile(flagProfile))
		}
		if flagRegion != "" {
			opts = append(opts, awsconfig.WithRegion(flagRegion))
		}
		cfg, err := awsconfig.LoadDefaultConfig(context.Background(), opts...)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  warning: AWS credentials not found (%v) — skipping AWS checks\n", err)
		} else {
			awsCheckers := []engine.Checker{
				awschecks.NewIAMChecker(cfg),
				awschecks.NewAccessAnalyzerChecker(cfg),
				awschecks.NewS3Checker(cfg),
				awschecks.NewCloudTrailChecker(cfg),
				awschecks.NewCloudWatchChecker(cfg),
				awschecks.NewSecurityGroupChecker(cfg),
				awschecks.NewKMSChecker(cfg),
				awschecks.NewGuardDutyChecker(cfg),
				awschecks.NewRDSChecker(cfg),
				awschecks.NewAWSConfigChecker(cfg),
				awschecks.NewMonitoringChecker(cfg),
				awschecks.NewEKSChecker(cfg),
				awschecks.NewECRChecker(cfg),
				awschecks.NewWAFChecker(cfg),
				awschecks.NewP2Checker(cfg),
				awschecks.NewP3Checker(cfg),
			}
			for _, checker := range awsCheckers {
				dim.Printf("  Scanning %s...\n", checker.Integration())
				findings, err := checker.Run()
				if err != nil {
					fmt.Fprintf(os.Stderr, "  warning: %s: %v\n", checker.Integration(), err)
					continue
				}
				addFiltered(result, findings, flagFramework)
			}
		}
	}

	// GCP checks
	if !want("gcp") {
		dim.Println("  Skipping GCP (not in --only)")
	} else if gcpChecker := gcpchecks.NewCheckerFromEnv(); gcpChecker != nil {
		pid := gcpChecker.ProjectID()
		for _, checker := range []engine.Checker{
			gcpChecker,
			gcpchecks.NewGKEChecker(pid),
			gcpchecks.NewIAMExtraChecker(pid),
			gcpchecks.NewLoggingChecker(pid),
			gcpchecks.NewComputeExtraChecker(pid),
			gcpchecks.NewStorageExtraChecker(pid),
			gcpchecks.NewGKEExtraChecker(pid),
			gcpchecks.NewNetworkExtraChecker(pid),
			gcpchecks.NewBigQueryChecker(pid),
			gcpchecks.NewGCPP2Checker(pid),
			gcpchecks.NewGCPP3Checker(pid),
		} {
			dim.Printf("  Scanning %s...\n", checker.Integration())
			findings, err := checker.Run()
			if err != nil {
				fmt.Fprintf(os.Stderr, "  warning: %s: %v\n", checker.Integration(), err)
				continue
			}
			addFiltered(result, findings, flagFramework)
		}
	} else {
		dim.Println("  Skipping GCP (set GCP_PROJECT_ID env to enable)")
	}

	// Azure checks
	if !want("azure") {
		dim.Println("  Skipping Azure (not in --only)")
	} else if checker := azchecks.NewCheckerFromEnv(); checker != nil {
		dim.Printf("  Scanning %s...\n", checker.Integration())
		findings, err := checker.Run()
		if err != nil {
			fmt.Fprintf(os.Stderr, "  warning: Azure: %v\n", err)
		} else {
			addFiltered(result, findings, flagFramework)
		}
	} else {
		dim.Println("  Skipping Azure (set AZURE_SUBSCRIPTION_ID env to enable)")
	}

	// Kubernetes workload checks
	if !want("kubernetes") {
		dim.Println("  Skipping Kubernetes (not in --only)")
	} else if checker := k8schecks.NewCheckerFromEnv(); checker != nil {
		dim.Printf("  Scanning %s...\n", checker.Integration())
		findings, err := checker.Run()
		if err != nil {
			fmt.Fprintf(os.Stderr, "  warning: Kubernetes: %v\n", err)
		} else {
			addFiltered(result, findings, flagFramework)
		}
	} else {
		dim.Println("  Skipping Kubernetes (no kubeconfig found — set KUBECONFIG or place at ~/.kube/config)")
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
	if !want("github") {
		dim.Println("  Skipping GitHub (not in --only)")
	} else if token != "" && owner != "" {
		checker := ghchecks.NewChecker(token, owner)
		dim.Printf("  Scanning %s...\n", checker.Integration())
		findings, err := checker.Run()
		if err != nil {
			fmt.Fprintf(os.Stderr, "  warning: GitHub: %v\n", err)
		} else {
			addFiltered(result, findings, flagFramework)
		}
	} else {
		dim.Println("  Skipping GitHub (set GITHUB_TOKEN + GITHUB_OWNER or use --github-token/--github-owner)")
	}

	// Policy / cross-cutting checks
	if !want("policy") {
		dim.Println("  Skipping Policy (not in --only)")
	} else {
		var awsCfgPtr *awssdk.Config
		if awsCfg, err := awsconfig.LoadDefaultConfig(context.Background()); err == nil {
			awsCfgPtr = &awsCfg
		}
		checker := policychecks.New("", awsCfgPtr)
		dim.Printf("  Scanning %s...\n", checker.Integration())
		findings, err := checker.Run()
		if err != nil {
			fmt.Fprintf(os.Stderr, "  warning: Policy: %v\n", err)
		} else {
			addFiltered(result, findings, flagFramework)
		}
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

	// push to server if --push or credentials exist
	creds, _ := credentials.Load()
	if flagPush || creds != nil {
		validCreds, err := requireValidCreds()
		if err != nil {
			if err.Error() != "" {
				color.New(color.FgRed).Printf("  Push failed: %v\n", err)
			}
		} else {
			if err := pushResult(result, flagFramework, validCreds); err != nil {
				color.New(color.FgRed).Printf("  Push failed: %v\n", err)
			}
		}
	}

	return nil
}

func pushResult(result *engine.ScanResult, framework string, creds *credentials.Credentials) error {
	cyan  := color.New(color.FgCyan)
	green := color.New(color.FgGreen)

	cyan.Printf("  Pushing results to %s...\n", creds.URI)

	payload, err := json.Marshal(map[string]interface{}{
		"framework": framework,
		"score":     result.Score,
		"passed":    result.Passed,
		"failed":    result.Failed,
		"skipped":   result.Skipped,
		"findings":  result.Findings,
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, creds.URI+"/api/push", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+creds.Token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("could not reach server: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("token expired — run: comply login --uri %s", creds.URI)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned %d", resp.StatusCode)
	}

	var out struct{ ID string `json:"id"` }
	json.NewDecoder(resp.Body).Decode(&out)
	green.Printf("  Pushed → scan ID: %s\n", out.ID)
	return nil
}
