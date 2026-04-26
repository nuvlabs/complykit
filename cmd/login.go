package cmd

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/manifoldco/promptui"
	"github.com/spf13/cobra"

	"github.com/complykit/complykit/internal/credentials"
)

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate with a ComplyKit server and save credentials",
	Long: `Authenticate with a ComplyKit server and save credentials.

The URI should point to the ComplyKit API server (port 8080), not the web client (port 3000).`,
	Example: `  comply login --uri http://localhost:8080   # local Docker server
  comply login --uri https://api.complykit.io  # production API`,
	RunE: runLogin,
}

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Remove saved credentials",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := credentials.Clear(); err != nil {
			return err
		}
		color.New(color.FgYellow).Println("  Logged out.")
		return nil
	},
}

func init() {
	loginCmd.Flags().String("uri", "", "ComplyKit API server URL (e.g. http://localhost:8080)")
	loginCmd.Flags().String("email", "", "Email address (prompted if omitted)")
	loginCmd.Flags().String("password", "", "Password (prompted if omitted)")
	rootCmd.AddCommand(loginCmd)
	rootCmd.AddCommand(logoutCmd)
}

func runLogin(cmd *cobra.Command, args []string) error {
	bold  := color.New(color.Bold)
	green := color.New(color.FgGreen)
	cyan  := color.New(color.FgCyan)

	uri, _ := cmd.Flags().GetString("uri")
	if uri == "" {
		p := promptui.Prompt{Label: "Server URL", Default: "http://localhost:8080"}
		var err error
		uri, err = p.Run()
		if err != nil {
			return err
		}
	}
	uri = strings.TrimRight(uri, "/")

	email, _ := cmd.Flags().GetString("email")
	if email == "" {
		p := promptui.Prompt{Label: "Email"}
		var err error
		email, err = p.Run()
		if err != nil {
			return err
		}
	}

	password, _ := cmd.Flags().GetString("password")
	if password == "" {
		p := promptui.Prompt{Label: "Password", Mask: '●'}
		var err error
		password, err = p.Run()
		if err != nil {
			return err
		}
	}

	fmt.Println()
	cyan.Printf("  Connecting to %s...\n", uri)

	body, _ := json.Marshal(map[string]string{"email": email, "password": password})
	resp, err := http.Post(uri+"/api/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("could not reach server: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("invalid email or password")
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned %d", resp.StatusCode)
	}

	var result struct {
		Token string `json:"token"`
		Email string `json:"email"`
		OrgID string `json:"org_id"`
		Role  string `json:"role"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("unexpected response: %w", err)
	}

	if err := credentials.Save(&credentials.Credentials{
		URI:       uri,
		Token:     result.Token,
		Email:     result.Email,
		OrgID:     result.OrgID,
		ExpiresAt: jwtExpiry(result.Token),
	}); err != nil {
		return fmt.Errorf("could not save credentials: %w", err)
	}

	expiry := jwtExpiry(result.Token)
	expiryDisplay := "unknown"
	if expiry != "" {
		if t, err := time.Parse(time.RFC3339, expiry); err == nil {
			expiryDisplay = fmt.Sprintf("%s (%d days)", t.Format("2006-01-02"), int(time.Until(t).Hours()/24))
		}
	}

	fmt.Println()
	bold.Println("  Login successful!")
	fmt.Printf("  %-12s %s\n", "Email:",   result.Email)
	fmt.Printf("  %-12s %s\n", "Role:",    result.Role)
	fmt.Printf("  %-12s %s\n", "Server:",  uri)
	fmt.Printf("  %-12s %s\n", "Expires:", expiryDisplay)
	fmt.Println()
	green.Println("  Run `comply scan --framework soc2` to push your first scan.")
	fmt.Println()
	return nil
}

// jwtExpiry decodes the exp claim from a JWT without verifying the signature.
func jwtExpiry(tokenStr string) string {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Exp == 0 {
		return ""
	}
	return time.Unix(claims.Exp, 0).UTC().Format(time.RFC3339)
}
