package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/complykit/complykit/internal/credentials"
)

var shareCmd = &cobra.Command{
	Use:   "share",
	Short: "Manage shareable read-only links for scan reports",
}

var shareCreateCmd = &cobra.Command{
	Use:   "create <scan-id>",
	Short: "Create a shareable link for a specific scan",
	Example: `  comply share create <scan-id> --label "Q1 Audit" --expires 30d
  comply share create <scan-id> --expires 7d`,
	Args: cobra.ExactArgs(1),
	RunE: runShareCreate,
}

var shareListCmd = &cobra.Command{
	Use:   "list",
	Short: "List your active share links",
	RunE:  runShareList,
}

var shareRevokeCmd = &cobra.Command{
	Use:   "revoke <share-id>",
	Short: "Revoke a share link",
	Args:  cobra.ExactArgs(1),
	RunE:  runShareRevoke,
}

func init() {
	shareCreateCmd.Flags().String("label", "", "Label for the link (e.g. 'Q1 Audit')")
	shareCreateCmd.Flags().String("expires", "30d", "Expiry duration: 1d, 7d, 30d, 90d")
	shareCmd.AddCommand(shareCreateCmd, shareListCmd, shareRevokeCmd)
	rootCmd.AddCommand(shareCmd)
}

// requireCreds delegates to the shared auth check in authcheck.go
func requireCreds() (*credentials.Credentials, error) {
	return requireValidCreds()
}

func apiReq(method, path string, body any, creds *credentials.Credentials) (*http.Response, error) {
	var reqBody *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		reqBody = bytes.NewReader(b)
	} else {
		reqBody = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, creds.URI+path, reqBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+creds.Token)
	return http.DefaultClient.Do(req)
}

func runShareCreate(cmd *cobra.Command, args []string) error {
	scanID := args[0]
	label, _ := cmd.Flags().GetString("label")
	expires, _ := cmd.Flags().GetString("expires")

	creds, err := requireCreds()
	if err != nil {
		return err
	}

	bold  := color.New(color.Bold)
	green := color.New(color.FgGreen)
	cyan  := color.New(color.FgCyan)
	dim   := color.New(color.Faint)

	resp, err := apiReq("POST", "/api/shares", map[string]string{
		"scan_id":    scanID,
		"label":      label,
		"expires_in": expires,
	}, creds)
	if err != nil {
		return fmt.Errorf("could not reach server: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("token expired — run: comply login --uri %s", creds.URI)
	}
	if resp.StatusCode != http.StatusCreated {
		var e map[string]string
		json.NewDecoder(resp.Body).Decode(&e)
		return fmt.Errorf("server error: %s", e["error"])
	}

	var result struct {
		Token     string `json:"token"`
		URL       string `json:"url"`
		ExpiresAt string `json:"expires_at"`
		Label     string `json:"label"`
	}
	json.NewDecoder(resp.Body).Decode(&result)

	fullURL := strings.TrimRight(creds.URI, "/") + result.URL

	fmt.Println()
	bold.Println("  Share link created")
	fmt.Println()
	cyan.Printf("  %s\n", fullURL)
	fmt.Println()
	dim.Printf("  Scan:    %s\n", scanID)
	dim.Printf("  Expires: %s\n", result.ExpiresAt)
	if result.Label != "" && result.Label != "Shared link" {
		dim.Printf("  Label:   %s\n", result.Label)
	}
	fmt.Println()
	green.Println("  Send this link to your auditor. It's read-only and expires automatically.")
	fmt.Println()
	return nil
}

func runShareList(cmd *cobra.Command, args []string) error {
	creds, err := requireCreds()
	if err != nil {
		return err
	}

	resp, err := apiReq("GET", "/api/shares", nil, creds)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var links []struct {
		ID             string `json:"id"`
		Label          string `json:"label"`
		URL            string `json:"url"`
		ExpiresAt      string `json:"expires_at"`
		CreatedByEmail string `json:"created_by_email"`
		Expired        bool   `json:"expired"`
	}
	json.NewDecoder(resp.Body).Decode(&links)

	if len(links) == 0 {
		fmt.Println("\n  No share links yet. Run `comply share create <scan-id>` to create one.")
		return nil
	}

	bold := color.New(color.Bold)
	dim  := color.New(color.Faint)
	green := color.New(color.FgGreen)
	red   := color.New(color.FgRed)

	fmt.Println()
	bold.Printf("  Share Links (%d)\n\n", len(links))
	dim.Printf("  %-38s  %-12s  %-20s  %s\n", "ID", "EXPIRES", "CREATED BY", "LABEL")
	dim.Println("  " + strings.Repeat("─", 90))

	for _, l := range links {
		status := green.Sprint("●")
		if l.Expired {
			status = red.Sprint("○")
		}
		exp, _ := time.Parse(time.RFC3339, l.ExpiresAt)
		fmt.Printf("  %s %-36s  %-12s  %-20s  %s\n",
			status, l.ID, exp.Format("2006-01-02"), l.CreatedByEmail, l.Label)
		dim.Printf("    %s%s\n\n", strings.TrimRight(creds.URI, "/"), l.URL)
	}
	return nil
}

func runShareRevoke(cmd *cobra.Command, args []string) error {
	shareID := args[0]
	creds, err := requireCreds()
	if err != nil {
		return err
	}

	resp, err := apiReq("DELETE", "/api/shares/"+shareID, nil, creds)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var e map[string]string
		json.NewDecoder(resp.Body).Decode(&e)
		return fmt.Errorf("%s", e["error"])
	}

	color.New(color.FgYellow).Printf("  Share link %s revoked.\n", shareID)
	return nil
}
