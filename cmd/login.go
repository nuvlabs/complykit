package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/fatih/color"
	"github.com/manifoldco/promptui"
	"github.com/spf13/cobra"

	"github.com/complykit/complykit/internal/credentials"
)

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate with a ComplyKit server and save credentials",
	Example: `  comply login --uri https://app.complykit.io
  comply login --uri http://localhost:8080`,
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
	loginCmd.Flags().String("uri", "", "ComplyKit server URL (e.g. https://app.complykit.io)")
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
		URI:   uri,
		Token: result.Token,
		Email: result.Email,
		OrgID: result.OrgID,
	}); err != nil {
		return fmt.Errorf("could not save credentials: %w", err)
	}

	fmt.Println()
	bold.Println("  Login successful!")
	fmt.Printf("  %-10s %s\n", "Email:", result.Email)
	fmt.Printf("  %-10s %s\n", "Role:", result.Role)
	fmt.Printf("  %-10s %s\n", "Server:", uri)
	fmt.Printf("  %-10s ~/.complykit/credentials.json\n", "Saved:")
	fmt.Println()
	green.Println("  Run `comply scan --framework soc2` to push your first scan.")
	fmt.Println()
	return nil
}
