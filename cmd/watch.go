package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/fatih/color"
	"github.com/spf13/cobra"

	awschecks "github.com/complykit/complykit/internal/checks/aws"
	gcpchecks "github.com/complykit/complykit/internal/checks/gcp"
	ghchecks "github.com/complykit/complykit/internal/checks/github"
	"github.com/complykit/complykit/internal/alert"
	ckconfig "github.com/complykit/complykit/internal/config"
	"github.com/complykit/complykit/internal/engine"
	"github.com/complykit/complykit/internal/report"
)

var (
	flagWatchInterval int
	flagWatchOutput   string
)

var watchCmd = &cobra.Command{
	Use:   "watch",
	Short: "Continuously scan and alert on compliance regressions",
	Example: `  comply watch                      # scan every 60 minutes
  comply watch --interval 30        # scan every 30 minutes
  comply watch --output reports/    # write timestamped JSON reports`,
	RunE: runWatch,
}

func init() {
	watchCmd.Flags().IntVar(&flagWatchInterval, "interval", 60, "Scan interval in minutes")
	watchCmd.Flags().StringVar(&flagWatchOutput, "output", "", "Directory to write timestamped JSON reports")
	rootCmd.AddCommand(watchCmd)
}

type snapshot struct {
	score   int
	failed  int
	byCheck map[string]engine.Status
}

func runWatch(cmd *cobra.Command, args []string) error {
	bold := color.New(color.Bold)
	dim := color.New(color.Faint)
	warn := color.New(color.FgYellow, color.Bold)
	good := color.New(color.FgGreen, color.Bold)
	bad := color.New(color.FgRed, color.Bold)

	bold.Printf("\n  ComplyKit — Watch Mode (every %d min)\n", flagWatchInterval)
	dim.Println("  Press Ctrl+C to stop\n")

	if flagWatchOutput != "" {
		if err := os.MkdirAll(flagWatchOutput, 0755); err != nil {
			return fmt.Errorf("cannot create output dir: %w", err)
		}
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	var prev *snapshot
	iteration := 0

	runOnce := func() {
		iteration++
		now := time.Now()
		dim.Printf("  [%s] Scan #%d running...\n", now.Format("15:04:05"), iteration)

		result := collectFindings()

		curr := &snapshot{
			score:   result.Score,
			failed:  result.Failed,
			byCheck: make(map[string]engine.Status),
		}
		for _, f := range result.Findings {
			curr.byCheck[f.CheckID] = f.Status
		}

		// diff against previous
		if prev != nil {
			regressions := []string{}
			improvements := []string{}

			for id, status := range curr.byCheck {
				old, existed := prev.byCheck[id]
				if existed && old == engine.StatusPass && status == engine.StatusFail {
					regressions = append(regressions, id)
				}
				if existed && old == engine.StatusFail && status == engine.StatusPass {
					improvements = append(improvements, id)
				}
			}

			scoreDelta := curr.score - prev.score
			if scoreDelta > 0 {
				good.Printf("  ↑ Score: %d → %d (+%d)\n", prev.score, curr.score, scoreDelta)
			} else if scoreDelta < 0 {
				bad.Printf("  ↓ Score: %d → %d (%d)\n", prev.score, curr.score, scoreDelta)
			} else {
				dim.Printf("  = Score unchanged: %d/100\n", curr.score)
			}

				var regressedFindings []alert.Regression
			for _, id := range regressions {
				bad.Printf("  ✗ REGRESSION: %s (was passing, now failing)\n", id)
				for _, f := range result.Findings {
					if f.CheckID == id {
						regressedFindings = append(regressedFindings, alert.Regression{
							CheckID: f.CheckID, Title: f.Title,
							Severity: f.Severity, Integration: f.Integration,
						})
					}
				}
			}
			for _, id := range improvements {
				good.Printf("  ✓ FIXED: %s\n", id)
			}

			if len(regressions) > 0 {
				warn.Printf("  ⚠  %d regression(s) detected — run `comply fix` for remediation steps\n", len(regressions))
				if alertCfg := loadAlertConfig(); alertCfg != nil {
					if err := alert.Notify(*alertCfg, regressedFindings, curr.score, prev.score); err != nil {
						dim.Printf("  warning: alert failed: %v\n", err)
					} else {
						dim.Println("  Alert sent.")
					}
				}
			}
		} else {
			fmt.Printf("  Score: %d/100  |  %d passed  |  %d failed\n", result.Score, result.Passed, result.Failed)
		}

		// write report if output dir set
		if flagWatchOutput != "" {
			filename := fmt.Sprintf("%s/scan-%s.json", flagWatchOutput, now.Format("20060102-150405"))
			if err := report.WriteJSON(result, "soc2", filename); err != nil {
				dim.Printf("  warning: could not write report: %v\n", err)
			}
		}

		prev = curr
		dim.Printf("  Next scan in %d min (Ctrl+C to stop)\n\n", flagWatchInterval)
	}

	// run immediately on start
	runOnce()

	ticker := time.NewTicker(time.Duration(flagWatchInterval) * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			runOnce()
		case <-sigCh:
			fmt.Println("\n  Watch stopped.")
			return nil
		}
	}
}

func loadAlertConfig() *alert.Config {
	cfg, err := ckconfig.Load()
	if err != nil || (cfg.Alerts.SlackWebhook == "" && cfg.Alerts.EmailTo == "") {
		return nil
	}
	return &alert.Config{
		SlackWebhook: cfg.Alerts.SlackWebhook,
		EmailTo:      cfg.Alerts.EmailTo,
		EmailFrom:    cfg.Alerts.EmailFrom,
		SMTPHost:     cfg.Alerts.SMTPHost,
		SMTPPort:     cfg.Alerts.SMTPPort,
		SMTPUser:     cfg.Alerts.SMTPUser,
		SMTPPass:     cfg.Alerts.SMTPPass,
	}
}

func collectFindings() *engine.ScanResult {
	result := &engine.ScanResult{}

	opts := []func(*awsconfig.LoadOptions) error{}
	cfg, err := awsconfig.LoadDefaultConfig(context.Background(), opts...)
	if err == nil {
		checkers := []engine.Checker{
			awschecks.NewIAMChecker(cfg),
			awschecks.NewS3Checker(cfg),
			awschecks.NewCloudTrailChecker(cfg),
			awschecks.NewSecurityGroupChecker(cfg),
		}
		for _, c := range checkers {
			findings, _ := c.Run()
			for _, f := range findings {
				result.Add(f)
			}
		}
	}

	if checker := gcpchecks.NewCheckerFromEnv(); checker != nil {
		findings, _ := checker.Run()
		for _, f := range findings {
			result.Add(f)
		}
	}

	token := os.Getenv("GITHUB_TOKEN")
	owner := os.Getenv("GITHUB_OWNER")
	if token != "" && owner != "" {
		checker := ghchecks.NewChecker(token, owner)
		findings, _ := checker.Run()
		for _, f := range findings {
			result.Add(f)
		}
	}

	return result
}
