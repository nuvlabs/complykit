package cmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/complykit/complykit/internal/evidence"
	"github.com/complykit/complykit/internal/share"
)

var (
	flagSharePort  string
	flagShareDays  int
	flagShareLabel string
	flagShareHost  string
)

var shareCmd = &cobra.Command{
	Use:   "share [record-id]",
	Short: "Generate a read-only auditor link for a scan report",
	Example: `  comply share                        # share latest scan
  comply share 20240115-143022        # share specific record
  comply share --days 7 --label "Q1 Audit"
  comply share list                   # show active share links`,
	RunE: runShare,
}

var shareListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all active share links",
	RunE:  runShareList,
}

func init() {
	shareCmd.Flags().StringVar(&flagShareHost, "host", "http://localhost:8080", "Base URL (set to your public domain when deployed)")
	shareCmd.Flags().IntVar(&flagShareDays, "days", 30, "Link expiry in days")
	shareCmd.Flags().StringVar(&flagShareLabel, "label", "", "Label for this link (e.g. 'Q1 Audit')")
	shareCmd.AddCommand(shareListCmd)
	rootCmd.AddCommand(shareCmd)
}

func runShare(cmd *cobra.Command, args []string) error {
	bold := color.New(color.Bold)
	green := color.New(color.FgGreen, color.Bold)
	dim := color.New(color.Faint)
	cyan := color.New(color.FgCyan)

	store := evidence.NewStore("")

	var recordID string
	if len(args) > 0 {
		recordID = args[0]
	} else {
		rec, err := store.Latest()
		if err != nil || rec == nil {
			return fmt.Errorf("no scans found — run `comply scan` first")
		}
		recordID = rec.ID
	}

	// verify record exists
	records, _ := store.List()
	found := false
	for _, r := range records {
		if r.ID == recordID {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("record not found: %s", recordID)
	}

	ttl := time.Duration(flagShareDays) * 24 * time.Hour
	link, err := share.Create(recordID, flagShareLabel, ttl)
	if err != nil {
		return fmt.Errorf("failed to create share link: %w", err)
	}

	shareURL := fmt.Sprintf("%s/share/%s", strings.TrimRight(flagShareHost, "/"), link.Token)

	fmt.Println()
	bold.Println("  Share link created")
	fmt.Println()
	cyan.Printf("  %s\n", shareURL)
	fmt.Println()
	dim.Printf("  Record:  %s\n", recordID)
	dim.Printf("  Expires: %s (%d days)\n", link.ExpiresAt.Format("2006-01-02"), flagShareDays)
	if flagShareLabel != "" {
		dim.Printf("  Label:   %s\n", flagShareLabel)
	}
	fmt.Println()
	green.Println("  Send this link to your auditor. It's read-only and expires automatically.")
	fmt.Println()
	fmt.Println("  To serve the dashboard publicly:")
	fmt.Println("    comply serve --port 8080")
	fmt.Println("    # then deploy behind nginx/caddy with TLS")
	fmt.Println()

	return nil
}

func runShareList(cmd *cobra.Command, args []string) error {
	bold := color.New(color.Bold)
	dim := color.New(color.Faint)
	green := color.New(color.FgGreen)
	red := color.New(color.FgRed)

	links, err := share.ListLinks()
	if err != nil || len(links) == 0 {
		fmt.Println("\n  No share links created yet. Run `comply share` to create one.")
		return nil
	}

	fmt.Println()
	bold.Printf("  Share Links (%d)\n\n", len(links))
	dim.Printf("  %-22s  %-18s  %-12s  %s\n", "RECORD ID", "EXPIRES", "STATUS", "LABEL")
	dim.Println("  " + strings.Repeat("─", 70))

	for _, l := range links {
		expired := time.Now().After(l.ExpiresAt)
		status := green.Sprint("active")
		if expired {
			status = red.Sprint("expired")
		}
		label := l.Label
		if label == "" {
			label = "—"
		}
		fmt.Printf("  %-22s  %-18s  %-12s  %s\n",
			l.RecordID,
			l.ExpiresAt.Format("2006-01-02"),
			status,
			label,
		)
	}
	fmt.Println()
	return nil
}
