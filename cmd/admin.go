package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	appdb "github.com/complykit/complykit/internal/db"
)

var adminCmd = &cobra.Command{
	Use:   "admin",
	Short: "Manage orgs, users and API keys (requires DATABASE_URL)",
}

var createOrgCmd = &cobra.Command{
	Use:   "create-org",
	Short: "Create a new organization",
	Example: `  comply admin create-org --slug acme --name "Acme Corp"`,
	RunE: func(cmd *cobra.Command, args []string) error {
		slug, _ := cmd.Flags().GetString("slug")
		name, _ := cmd.Flags().GetString("name")
		if slug == "" || name == "" {
			return fmt.Errorf("--slug and --name are required")
		}
		db, err := connectDB()
		if err != nil {
			return err
		}
		defer db.Close()
		org, err := db.GetOrCreateOrg(context.Background(), slug, name)
		if err != nil {
			return err
		}
		color.Green("✓ Org created")
		fmt.Printf("  ID:   %s\n", org.ID)
		fmt.Printf("  Slug: %s\n", org.Slug)
		fmt.Printf("  Name: %s\n", org.Name)
		return nil
	},
}

var createUserCmd = &cobra.Command{
	Use:   "create-user",
	Short: "Create a user for an org",
	Example: `  comply admin create-user --org acme --email user@acme.com --password secret --role member`,
	RunE: func(cmd *cobra.Command, args []string) error {
		orgSlug, _ := cmd.Flags().GetString("org")
		email, _ := cmd.Flags().GetString("email")
		password, _ := cmd.Flags().GetString("password")
		role, _ := cmd.Flags().GetString("role")
		if orgSlug == "" || email == "" || password == "" {
			return fmt.Errorf("--org, --email and --password are required")
		}
		db, err := connectDB()
		if err != nil {
			return err
		}
		defer db.Close()
		ctx := context.Background()
		org, err := db.GetOrgBySlug(ctx, orgSlug)
		if err != nil {
			return fmt.Errorf("org %q not found — run create-org first", orgSlug)
		}
		user, err := db.CreateUser(ctx, org.ID, email, password, role)
		if err != nil {
			return err
		}
		color.Green("✓ User created")
		fmt.Printf("  ID:    %s\n", user.ID)
		fmt.Printf("  Email: %s\n", user.Email)
		fmt.Printf("  Org:   %s\n", org.Slug)
		fmt.Printf("  Role:  %s\n", user.Role)
		return nil
	},
}

var createAPIKeyCmd = &cobra.Command{
	Use:   "create-apikey",
	Short: "Create an API key for an org (used by the CLI to push scan results)",
	Example: `  comply admin create-apikey --org acme --name "ci-pipeline"`,
	RunE: func(cmd *cobra.Command, args []string) error {
		orgSlug, _ := cmd.Flags().GetString("org")
		name, _ := cmd.Flags().GetString("name")
		if orgSlug == "" || name == "" {
			return fmt.Errorf("--org and --name are required")
		}
		db, err := connectDB()
		if err != nil {
			return err
		}
		defer db.Close()
		ctx := context.Background()
		org, err := db.GetOrgBySlug(ctx, orgSlug)
		if err != nil {
			return fmt.Errorf("org %q not found", orgSlug)
		}
		rawKey, meta, err := db.CreateAPIKey(ctx, org.ID, name)
		if err != nil {
			return err
		}
		color.Green("✓ API key created — save this, it won't be shown again")
		fmt.Printf("  Key:  %s\n", rawKey)
		fmt.Printf("  ID:   %s\n", meta.ID)
		fmt.Printf("  Org:  %s\n", org.Slug)
		fmt.Printf("  Name: %s\n", meta.Name)
		return nil
	},
}

var resetPasswordCmd = &cobra.Command{
	Use:   "reset-password",
	Short: "Reset a user's password (super admin — no org restriction)",
	Example: `  comply admin reset-password --email user@acme.com --password newpass`,
	RunE: func(cmd *cobra.Command, args []string) error {
		email, _ := cmd.Flags().GetString("email")
		password, _ := cmd.Flags().GetString("password")
		if email == "" || password == "" {
			return fmt.Errorf("--email and --password are required")
		}
		db, err := connectDB()
		if err != nil {
			return err
		}
		defer db.Close()
		// Pass SystemOrgID so no org restriction is applied
		if err := db.ResetPassword(context.Background(), appdb.SystemOrgID, email, password); err != nil {
			return err
		}
		color.Green("✓ Password reset for %s", email)
		return nil
	},
}

func init() {
	createOrgCmd.Flags().String("slug", "", "URL-safe identifier (e.g. acme)")
	createOrgCmd.Flags().String("name", "", "Display name")

	createUserCmd.Flags().String("org", "", "Org slug")
	createUserCmd.Flags().String("email", "", "User email")
	createUserCmd.Flags().String("password", "", "Password")
	createUserCmd.Flags().String("role", "member", "Role: admin or member")

	createAPIKeyCmd.Flags().String("org", "", "Org slug")
	createAPIKeyCmd.Flags().String("name", "", "Key name/label")

	resetPasswordCmd.Flags().String("email", "", "User email")
	resetPasswordCmd.Flags().String("password", "", "New password")

	adminCmd.AddCommand(createOrgCmd, createUserCmd, createAPIKeyCmd, resetPasswordCmd)
	rootCmd.AddCommand(adminCmd)
}

func connectDB() (*appdb.DB, error) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		return nil, fmt.Errorf("DATABASE_URL is not set")
	}
	return appdb.Connect(context.Background(), dsn)
}
