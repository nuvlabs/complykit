package cmd

import (
	"fmt"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var ciCmd = &cobra.Command{
	Use:   "ci",
	Short: "Generate CI/CD integration templates",
	Example: `  comply ci github    # GitHub Actions workflow
  comply ci gitlab    # GitLab CI template`,
}

var ciGitHubCmd = &cobra.Command{
	Use:   "github",
	Short: "Print a GitHub Actions workflow for comply scan",
	RunE: func(cmd *cobra.Command, args []string) error {
		framework, _ := cmd.Flags().GetString("framework")
		fmt.Print(githubActionsTemplate(framework))
		color.New(color.Faint).Println("\n# Save as: .github/workflows/complykit.yml")
		color.New(color.Faint).Println("# Add COMPLYKIT_API_KEY to your GitHub repo secrets.")
		return nil
	},
}

var ciGitLabCmd = &cobra.Command{
	Use:   "gitlab",
	Short: "Print a GitLab CI template for comply scan",
	RunE: func(cmd *cobra.Command, args []string) error {
		framework, _ := cmd.Flags().GetString("framework")
		fmt.Print(gitlabCITemplate(framework))
		color.New(color.Faint).Println("\n# Add to your .gitlab-ci.yml or include it as a template.")
		color.New(color.Faint).Println("# Set COMPLYKIT_URI and COMPLYKIT_API_KEY as CI/CD variables.")
		return nil
	},
}

func init() {
	ciGitHubCmd.Flags().String("framework", "soc2", "Compliance framework: soc2, hipaa, cis")
	ciGitLabCmd.Flags().String("framework", "soc2", "Compliance framework: soc2, hipaa, cis")
	ciCmd.AddCommand(ciGitHubCmd, ciGitLabCmd)
	rootCmd.AddCommand(ciCmd)
}

func githubActionsTemplate(framework string) string {
	return fmt.Sprintf(`name: ComplyKit Compliance Scan

on:
  schedule:
    - cron: '0 2 * * 1'   # every Monday at 2am UTC
  push:
    branches: [main]
  workflow_dispatch:        # allow manual runs

jobs:
  compliance:
    name: Compliance Scan (%s)
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Install ComplyKit
        run: |
          curl -sSfL https://raw.githubusercontent.com/nuvlabs/complykit/main/install.sh | sh
          echo "$HOME/.local/bin" >> $GITHUB_PATH

      - name: Run compliance scan
        env:
          AWS_ACCESS_KEY_ID:     ${{ secrets.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          AWS_REGION:            ${{ secrets.AWS_REGION }}
          GITHUB_TOKEN:          ${{ secrets.COMPLYKIT_GITHUB_TOKEN }}
          GITHUB_OWNER:          ${{ github.repository_owner }}
          COMPLYKIT_API_KEY:     ${{ secrets.COMPLYKIT_API_KEY }}
          COMPLYKIT_URI:         ${{ secrets.COMPLYKIT_URI }}
        run: |
          comply scan --framework %s --push

      - name: Upload scan report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: compliance-report
          path: complykit-report.json
          retention-days: 90
`, framework, framework)
}

func gitlabCITemplate(framework string) string {
	return fmt.Sprintf(`# ComplyKit Compliance Scan
# Add COMPLYKIT_URI and COMPLYKIT_API_KEY to CI/CD → Variables

compliance-scan:
  stage: test
  image: alpine:latest
  rules:
    - if: '$CI_PIPELINE_SOURCE == "schedule"'
    - if: '$CI_COMMIT_BRANCH == "main"'
    - when: manual
  variables:
    FRAMEWORK: %s
  script:
    - apk add --no-cache curl
    - curl -sSfL https://raw.githubusercontent.com/nuvlabs/complykit/main/install.sh | sh
    - export PATH="$HOME/.local/bin:$PATH"
    - comply scan --framework $FRAMEWORK --push
  artifacts:
    when: always
    paths:
      - complykit-report.json
    expire_in: 90 days
  allow_failure: false
`, framework)
}
