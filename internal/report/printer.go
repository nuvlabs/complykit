package report

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
	"github.com/complykit/complykit/internal/engine"
)

var (
	bold    = color.New(color.Bold)
	pass    = color.New(color.FgGreen)
	fail    = color.New(color.FgRed)
	skip    = color.New(color.FgYellow)
	cyan    = color.New(color.FgCyan)
	dim     = color.New(color.Faint)
	red     = color.New(color.FgRed, color.Bold)
	green   = color.New(color.FgGreen, color.Bold)
)

func PrintResult(result *engine.ScanResult, framework string) {
	fmt.Println()
	bold.Printf("  Scan Results — %s\n", strings.ToUpper(framework))
	fmt.Println(strings.Repeat("─", 72))

	currentIntegration := ""
	for _, f := range result.Findings {
		if f.Integration != currentIntegration {
			currentIntegration = f.Integration
			fmt.Println()
			cyan.Printf("  [%s]\n", currentIntegration)
		}

		switch f.Status {
		case engine.StatusPass:
			pass.Print("  ✓ ")
			fmt.Println(f.Title)
		case engine.StatusFail:
			fail.Print("  ✗ ")
			fmt.Print(f.Title)
			if f.Severity != "" {
				dim.Printf(" [%s]", f.Severity)
			}
			fmt.Println()
			if len(f.Controls) > 0 {
				refs := []string{}
				for _, c := range f.Controls {
					refs = append(refs, fmt.Sprintf("%s %s", strings.ToUpper(string(c.Framework)), c.ID))
				}
				dim.Printf("    → %s\n", strings.Join(refs, " · "))
			}
		case engine.StatusSkip:
			skip.Print("  ~ ")
			fmt.Printf("%s", f.Title)
			if f.Detail != "" {
				dim.Printf(" (skipped: %s)", f.Detail)
			}
			fmt.Println()
		}
	}

	fmt.Println()
	fmt.Println(strings.Repeat("─", 72))
	printScore(result)
	fmt.Println()
}

func printScore(result *engine.ScanResult) {
	total := result.Passed + result.Failed

	scoreColor := green
	if result.Score < 50 {
		scoreColor = red
	} else if result.Score < 80 {
		scoreColor = color.New(color.FgYellow, color.Bold)
	}

	fmt.Printf("  Score: ")
	scoreColor.Printf("%d/100", result.Score)
	fmt.Printf("  |  ")
	green.Printf("%d passed", result.Passed)
	fmt.Printf("  |  ")
	fail.Printf("%d failed", result.Failed)
	if result.Skipped > 0 {
		fmt.Printf("  |  ")
		skip.Printf("%d skipped", result.Skipped)
	}
	fmt.Printf("  |  %d total\n", total)

	if result.Failed > 0 {
		fmt.Println()
		fmt.Println("  Remediation steps for failed checks:")
		for i, f := range result.Findings {
			if f.Status != engine.StatusFail || f.Remediation == "" {
				continue
			}
			fmt.Println()
			bold.Printf("  %d. %s\n", i+1, f.Title)
			for _, line := range strings.Split(f.Remediation, "\n") {
				dim.Printf("     %s\n", line)
			}
		}
	}
}
