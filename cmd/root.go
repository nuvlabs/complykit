package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/complykit/complykit/internal/credentials"
)

var rootCmd = &cobra.Command{
	Use:           "comply",
	Short:         "ComplyKit — compliance-as-code for small teams",
	SilenceUsage:  true,
	SilenceErrors: true,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		color.New(color.FgRed).Fprintf(os.Stderr, "\n  Error: %v\n\n", err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.SetHelpFunc(richHelp)
}

func richHelp(cmd *cobra.Command, _ []string) {
	bold   := color.New(color.Bold)
	cyan   := color.New(color.FgCyan)
	green  := color.New(color.FgGreen)
	yellow := color.New(color.FgYellow)
	dim    := color.New(color.Faint)

	// Logo
	cyan.Println(`
   ██████╗ ██████╗ ███╗   ███╗██████╗ ██╗   ██╗    ██╗  ██╗██╗████████╗
  ██╔════╝██╔═══██╗████╗ ████║██╔══██╗██║   ██║    ██║ ██╔╝██║╚══██╔══╝
  ██║     ██║   ██║██╔████╔██║██████╔╝██║   ██║    █████╔╝ ██║   ██║
  ██║     ██║   ██║██║╚██╔╝██║██╔═══╝ ██║   ██║    ██╔═██╗ ██║   ██║
  ╚██████╗╚██████╔╝██║ ╚═╝ ██║██║     ╚██████╔╝    ██║  ██╗██║   ██║
   ╚═════╝ ╚═════╝ ╚═╝     ╚═╝╚═╝      ╚═════╝     ╚═╝  ╚═╝╚═╝   ╚═╝  `)

	bold.Println("  Compliance-as-code for startups · SOC 2 · HIPAA · CIS")
	fmt.Println()

	// Auth status line
	creds, _ := credentials.Load()
	if creds != nil {
		green.Printf("  ● Logged in as %s  →  %s\n", creds.Email, creds.URI)
	} else {
		yellow.Println("  ○ Not logged in  (run: comply login --uri <server-url>)")
	}
	fmt.Println()

	// Sub-command help (comply scan --help etc.)
	if cmd != rootCmd {
		bold.Printf("  %s\n\n", strings.ToUpper(cmd.Short))
		if cmd.Example != "" {
			bold.Println("  EXAMPLES")
			for _, line := range strings.Split(cmd.Example, "\n") {
				fmt.Printf("  %s\n", line)
			}
			fmt.Println()
		}
		bold.Println("  FLAGS")
		for _, line := range strings.Split(cmd.Flags().FlagUsages(), "\n") {
			if strings.TrimSpace(line) != "" {
				fmt.Printf("    %s\n", line)
			}
		}
		fmt.Println()
		dim.Println("  Run `comply --help` to see all commands.")
		fmt.Println()
		return
	}

	// Root help — commands grouped
	bold.Println("  USAGE")
	fmt.Println("    comply <command> [flags]")
	fmt.Println()

	type entry struct{ name, desc string }
	groups := []struct {
		title string
		items []entry
	}{
		{"GETTING STARTED", []entry{
			{"login",  "Authenticate with a ComplyKit server and save credentials"},
			{"logout", "Remove saved credentials"},
		}},
		{"SCANNING", []entry{
			{"scan",  "Run compliance checks against your infrastructure"},
			{"watch", "Continuously scan on a schedule"},
		}},
		{"DASHBOARD", []entry{
			{"serve", "Start the local compliance dashboard (default :8080)"},
		}},
		{"RESULTS", []entry{
			{"evidence", "List and manage saved scan evidence"},
			{"share",    "Create a shareable link for a scan result"},
		}},
		{"ADMINISTRATION", []entry{
			{"admin", "Manage orgs, users and API keys (requires DATABASE_URL)"},
		}},
	}

	for _, g := range groups {
		bold.Printf("  %s\n", g.title)
		for _, c := range g.items {
			fmt.Printf("    %-18s %s\n", cyan.Sprint(c.name), c.desc)
		}
		fmt.Println()
	}

	// Quick start
	bold.Println("  QUICK START")
	type step struct{ n, cmd, note string }
	steps := []step{
		{"1", "comply login --uri https://app.complykit.io", "authenticate with the server"},
		{"2", "comply scan --framework soc2 --push",        "scan AWS/GCP/GitHub and push results"},
		{"3", "comply serve",                               "open local dashboard at :8080"},
	}
	for _, s := range steps {
		dim.Printf("    %s  ", s.n)
		green.Printf("%-52s", s.cmd)
		dim.Printf("# %s\n", s.note)
	}
	fmt.Println()

	dim.Println("  Run `comply <command> --help` for detailed flags and examples.")
	fmt.Println()
}
