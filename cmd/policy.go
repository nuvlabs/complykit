package cmd

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
	"github.com/manifoldco/promptui"
	"github.com/spf13/cobra"

	"github.com/complykit/complykit/internal/config"
	"github.com/complykit/complykit/internal/policy"
)

var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Generate SOC2-required policy documents",
}

var policyGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate all required policy documents as markdown files",
	Example: `  comply policy generate
  comply policy generate --out ./policies --company "Acme Inc"`,
	RunE: runPolicyGenerate,
}

var (
	flagPolicyOut     string
	flagPolicyCompany string
	flagPolicyOwner   string
	flagPolicyTitle   string
)

func init() {
	policyGenerateCmd.Flags().StringVar(&flagPolicyOut, "out", "./policies", "Output directory for policy documents")
	policyGenerateCmd.Flags().StringVar(&flagPolicyCompany, "company", "", "Company name (prompted if not set)")
	policyGenerateCmd.Flags().StringVar(&flagPolicyOwner, "owner", "", "Policy owner name")
	policyGenerateCmd.Flags().StringVar(&flagPolicyTitle, "title", "", "Policy owner title")
	policyCmd.AddCommand(policyGenerateCmd)
	policyCmd.AddCommand(policyListCmd)
	rootCmd.AddCommand(policyCmd)
}

var policyListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all available policy templates",
	Run: func(cmd *cobra.Command, args []string) {
		bold := color.New(color.Bold)
		cyan := color.New(color.FgCyan)
		dim := color.New(color.Faint)

		fmt.Println()
		bold.Println("  Available Policy Templates")
		fmt.Println()
		for _, t := range policy.All() {
			cyan.Printf("  %-30s", t.Title)
			dim.Printf("  %s\n", strings.Join(t.Controls, ", "))
		}
		fmt.Println()
	},
}

func runPolicyGenerate(cmd *cobra.Command, args []string) error {
	bold := color.New(color.Bold)
	green := color.New(color.FgGreen, color.Bold)
	dim := color.New(color.Faint)

	framework := "soc2"
	if cfg, err := config.Load(); err == nil {
		framework = cfg.Framework
		if flagPolicyOut == "./policies" && cfg.OutputDir != "" {
			flagPolicyOut = cfg.OutputDir + "/policies"
		}
	}

	// prompt for missing values
	if flagPolicyCompany == "" {
		p := promptui.Prompt{Label: "  Company name"}
		flagPolicyCompany, _ = p.Run()
	}
	if flagPolicyOwner == "" {
		p := promptui.Prompt{Label: "  Policy owner name", Default: "Head of Engineering"}
		flagPolicyOwner, _ = p.Run()
	}
	if flagPolicyTitle == "" {
		p := promptui.Prompt{Label: "  Policy owner title", Default: "CTO"}
		flagPolicyTitle, _ = p.Run()
	}

	fmt.Println()
	bold.Printf("  Generating %s policy documents...\n\n", strings.ToUpper(framework))

	written, err := policy.Generate(flagPolicyOut, flagPolicyCompany, flagPolicyOwner, flagPolicyTitle, framework)
	if err != nil {
		return err
	}

	for _, path := range written {
		green.Print("  ✓ ")
		dim.Println(path)
	}

	fmt.Println()
	bold.Printf("  %d policy documents written to %s\n", len(written), flagPolicyOut)
	fmt.Println()
	fmt.Println("  These templates cover the following SOC2 controls:")
	fmt.Println("    CC6.1-6.7  Access Control")
	fmt.Println("    CC7.3-7.5  Incident Response")
	fmt.Println("    CC8.1      Change Management")
	fmt.Println("    CC9.2      Vendor Management")
	fmt.Println()
	fmt.Println("  Next: edit each file to match your actual processes,")
	fmt.Println("  then share with your auditor.")
	fmt.Println()

	return nil
}
