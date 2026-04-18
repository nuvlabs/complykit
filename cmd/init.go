package cmd

import (
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/manifoldco/promptui"
	"github.com/spf13/cobra"

	"github.com/complykit/complykit/internal/config"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Interactive setup wizard — configure integrations and alerts",
	RunE:  runInit,
}

func init() {
	rootCmd.AddCommand(initCmd)
}

func runInit(cmd *cobra.Command, args []string) error {
	bold := color.New(color.Bold)
	cyan := color.New(color.FgCyan)
	green := color.New(color.FgGreen, color.Bold)

	fmt.Println()
	bold.Println("  ComplyKit Setup Wizard")
	cyan.Println("  Let's configure your compliance scanning in 2 minutes.\n")

	if config.Exists() {
		confirm := promptui.Prompt{
			Label:     "  .complykit.yml already exists. Overwrite",
			IsConfirm: true,
		}
		if _, err := confirm.Run(); err != nil {
			fmt.Println("  Keeping existing config.")
			return nil
		}
	}

	cfg := &config.Config{}

	// ── Framework ───────────────────────────────────────────────────
	frameworkSel := promptui.Select{
		Label: "  Primary compliance framework",
		Items: []string{"soc2", "hipaa", "cis"},
	}
	_, cfg.Framework, _ = frameworkSel.Run()

	// ── AWS ─────────────────────────────────────────────────────────
	fmt.Println()
	bold.Println("  AWS")
	awsSel := promptui.Prompt{Label: "  Enable AWS scanning", IsConfirm: true}
	if _, err := awsSel.Run(); err == nil {
		cfg.AWS.Enabled = true

		profilePrompt := promptui.Prompt{
			Label:   "  AWS profile (leave blank for default)",
			Default: os.Getenv("AWS_PROFILE"),
		}
		cfg.AWS.Profile, _ = profilePrompt.Run()

		regionPrompt := promptui.Prompt{
			Label:   "  AWS region",
			Default: envOr("AWS_DEFAULT_REGION", "us-east-1"),
		}
		cfg.AWS.Region, _ = regionPrompt.Run()
	}

	// ── GCP ─────────────────────────────────────────────────────────
	fmt.Println()
	bold.Println("  GCP")
	gcpSel := promptui.Prompt{Label: "  Enable GCP scanning", IsConfirm: true}
	if _, err := gcpSel.Run(); err == nil {
		cfg.GCP.Enabled = true
		projPrompt := promptui.Prompt{
			Label:   "  GCP project ID",
			Default: envOr("GCP_PROJECT_ID", envOr("GOOGLE_CLOUD_PROJECT", "")),
		}
		cfg.GCP.ProjectID, _ = projPrompt.Run()
	}

	// ── GitHub ──────────────────────────────────────────────────────
	fmt.Println()
	bold.Println("  GitHub")
	ghSel := promptui.Prompt{Label: "  Enable GitHub scanning", IsConfirm: true}
	if _, err := ghSel.Run(); err == nil {
		cfg.GitHub.Enabled = true
		ownerPrompt := promptui.Prompt{
			Label:   "  GitHub org or username",
			Default: os.Getenv("GITHUB_OWNER"),
		}
		cfg.GitHub.Owner, _ = ownerPrompt.Run()
		fmt.Println("  Note: set GITHUB_TOKEN env var with a token that has `repo` and `read:org` scopes")
	}

	// ── Alerts ──────────────────────────────────────────────────────
	fmt.Println()
	bold.Println("  Alerts")
	alertSel := promptui.Select{
		Label: "  Alert channel for compliance regressions",
		Items: []string{"none", "slack", "email", "both"},
	}
	_, alertChoice, _ := alertSel.Run()

	if alertChoice == "slack" || alertChoice == "both" {
		webhookPrompt := promptui.Prompt{
			Label: "  Slack webhook URL",
			Mask:  '*',
		}
		cfg.Alerts.SlackWebhook, _ = webhookPrompt.Run()
	}

	if alertChoice == "email" || alertChoice == "both" {
		emailToPrompt := promptui.Prompt{Label: "  Alert email address (to)"}
		cfg.Alerts.EmailTo, _ = emailToPrompt.Run()

		emailFromPrompt := promptui.Prompt{Label: "  From email address"}
		cfg.Alerts.EmailFrom, _ = emailFromPrompt.Run()

		smtpHostPrompt := promptui.Prompt{Label: "  SMTP host", Default: "smtp.gmail.com"}
		cfg.Alerts.SMTPHost, _ = smtpHostPrompt.Run()

		smtpPortPrompt := promptui.Prompt{Label: "  SMTP port", Default: "587"}
		portStr, _ := smtpPortPrompt.Run()
		fmt.Sscanf(portStr, "%d", &cfg.Alerts.SMTPPort)

		smtpUserPrompt := promptui.Prompt{Label: "  SMTP username"}
		cfg.Alerts.SMTPUser, _ = smtpUserPrompt.Run()

		smtpPassPrompt := promptui.Prompt{Label: "  SMTP password (app password)", Mask: '*'}
		cfg.Alerts.SMTPPass, _ = smtpPassPrompt.Run()
	}

	// ── Output dir ──────────────────────────────────────────────────
	fmt.Println()
	outPrompt := promptui.Prompt{
		Label:   "  Report output directory",
		Default: config.DefaultOutputDir(),
	}
	cfg.OutputDir, _ = outPrompt.Run()

	// ── Save ────────────────────────────────────────────────────────
	if err := config.Save(cfg); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	fmt.Println()
	green.Println("  ✓ Config saved to .complykit.yml")
	fmt.Println()
	fmt.Println("  Next steps:")
	fmt.Println("    comply scan              — run a full scan")
	fmt.Println("    comply watch             — start continuous monitoring")
	fmt.Println("    comply fix               — see remediation steps")
	fmt.Println("    comply policy generate   — generate SOC2 policy documents")
	fmt.Println()

	return nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
