package cmd

import (
	"fmt"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/complykit/complykit/internal/credentials"
)

var whoamiCmd = &cobra.Command{
	Use:   "whoami",
	Short: "Show current login status and token expiry",
	RunE:  runWhoami,
}

func init() {
	rootCmd.AddCommand(whoamiCmd)
}

func runWhoami(cmd *cobra.Command, args []string) error {
	bold   := color.New(color.Bold)
	green  := color.New(color.FgGreen)
	red    := color.New(color.FgRed)
	yellow := color.New(color.FgYellow)
	dim    := color.New(color.Faint)

	creds, err := credentials.Load()
	if err != nil {
		return err
	}

	fmt.Println()

	if creds == nil {
		red.Println("  ✗ Not logged in")
		fmt.Println()
		dim.Println("  Run: comply login --uri <server>")
		fmt.Println()
		return nil
	}

	if creds.IsExpired() {
		red.Println("  ✗ Session expired")
		fmt.Println()
		fmt.Printf("  %-12s %s\n", "Email:",  creds.Email)
		fmt.Printf("  %-12s %s\n", "Server:", creds.URI)
		fmt.Println()
		yellow.Printf("  Token expired. Re-authenticate:\n")
		fmt.Printf("  comply login --uri %s\n\n", creds.URI)
		return nil
	}

	days := creds.DaysUntilExpiry()

	bold.Println("  Logged in")
	fmt.Println()
	fmt.Printf("  %-12s %s\n", "Email:",  creds.Email)
	fmt.Printf("  %-12s %s\n", "Server:", creds.URI)

	if creds.ExpiresAt != "" {
		t, _ := time.Parse(time.RFC3339, creds.ExpiresAt)
		if days <= 3 {
			yellow.Printf("  %-12s %s (%d days left — expiring soon!)\n", "Expires:", t.Format("2006-01-02"), days)
		} else {
			fmt.Printf("  %-12s %s (%d days left)\n", "Expires:", t.Format("2006-01-02"), days)
		}
	}

	fmt.Println()
	green.Println("  Ready to scan. Run: comply scan --framework soc2 --push")
	fmt.Println()
	return nil
}
