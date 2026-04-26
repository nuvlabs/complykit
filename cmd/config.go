package cmd

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/complykit/complykit/internal/credentials"
)

// configCmd is intentionally hidden from root -h.
// Users discover it via `comply config --help`.
var configCmd = &cobra.Command{
	Use:    "config",
	Short:  "Manage cloud provider credentials and scan settings",
	Hidden: true, // keeps root -h clean
}

var configSetCmd = &cobra.Command{
	Use:   "set <key> <value>",
	Short: "Set a configuration value",
	Example: `  comply config set aws-profile        prod
  comply config set aws-region         us-east-1
  comply config set github-token       ghp_xxxx
  comply config set github-owner       myorg
  comply config set gcp-project        my-project-id
  comply config set gcp-credentials    /path/to/key.json
  comply config set azure-subscription xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
  comply config set azure-client-id    xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
  comply config set azure-client-secret <secret>
  comply config set azure-tenant-id    xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		key, value := args[0], args[1]

		cfg, err := credentials.LoadConfig()
		if err != nil {
			return err
		}

		if err := setConfigKey(cfg, key, value); err != nil {
			return err
		}

		if err := credentials.SaveConfig(cfg); err != nil {
			return err
		}

		color.New(color.FgGreen).Printf("  ✓ %s saved\n", key)
		return nil
	},
}

var configUnsetCmd = &cobra.Command{
	Use:     "unset <key>",
	Short:   "Remove a configuration value",
	Example: `  comply config unset github-token`,
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := credentials.LoadConfig()
		if err != nil {
			return err
		}
		if err := setConfigKey(cfg, args[0], ""); err != nil {
			return err
		}
		if err := credentials.SaveConfig(cfg); err != nil {
			return err
		}
		color.New(color.FgYellow).Printf("  %s unset\n", args[0])
		return nil
	},
}

var configShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show current configuration",
	RunE: func(cmd *cobra.Command, args []string) error {
		bold := color.New(color.Bold)
		dim  := color.New(color.Faint)
		cyan := color.New(color.FgCyan)

		cfg, err := credentials.LoadConfig()
		if err != nil {
			return err
		}

		fmt.Println()
		bold.Println("  Cloud Provider Configuration")
		dim.Println("  ~/.complykit/config.json\n")

		groups := []struct {
			title string
			keys  []struct{ label, field string }
		}{
			{"AWS", []struct{ label, field string }{
				{"aws-profile",  "AWSProfile"},
				{"aws-region",   "AWSRegion"},
				{"aws-key-id",   "AWSAccessKeyID"},
			}},
			{"GitHub", []struct{ label, field string }{
				{"github-owner", "GitHubOwner"},
				{"github-token", "GitHubToken"},
			}},
			{"GCP", []struct{ label, field string }{
				{"gcp-project",     "GCPProject"},
				{"gcp-credentials", "GCPCredentials"},
			}},
			{"Azure", []struct{ label, field string }{
				{"azure-subscription", "AzureSubscriptionID"},
				{"azure-tenant-id",    "AzureTenantID"},
				{"azure-client-id",    "AzureClientID"},
				{"azure-client-secret","AzureClientSecret"},
			}},
		}

		v := reflect.ValueOf(cfg).Elem()
		t := v.Type()

		for _, g := range groups {
			bold.Printf("  %s\n", g.title)
			for _, k := range g.keys {
				var val string
				for i := 0; i < t.NumField(); i++ {
					if t.Field(i).Name == k.field {
						val = v.Field(i).String()
						break
					}
				}
				if val == "" {
					dim.Printf("    %-26s %s\n", k.label, "—")
				} else {
					display := val
					// mask secrets
					if strings.Contains(k.label, "token") || strings.Contains(k.label, "secret") || strings.Contains(k.label, "key") {
						if len(val) > 8 {
							display = val[:6] + strings.Repeat("•", len(val)-6)
						} else {
							display = strings.Repeat("•", len(val))
						}
					}
					fmt.Printf("    %-26s ", k.label)
					cyan.Println(display)
				}
			}
			fmt.Println()
		}

		dim.Println("  To update: comply config set <key> <value>")
		dim.Println("  Env vars always take precedence over config file values.\n")
		return nil
	},
}

func init() {
	configCmd.AddCommand(configSetCmd, configUnsetCmd, configShowCmd)
	rootCmd.AddCommand(configCmd)
}

var configKeyMap = map[string]string{
	"aws-profile":          "AWSProfile",
	"aws-region":           "AWSRegion",
	"aws-access-key-id":    "AWSAccessKeyID",
	"aws-secret-key":       "AWSSecretAccessKey",
	"github-token":         "GitHubToken",
	"github-owner":         "GitHubOwner",
	"gcp-project":          "GCPProject",
	"gcp-credentials":      "GCPCredentials",
	"azure-subscription":   "AzureSubscriptionID",
	"azure-client-id":      "AzureClientID",
	"azure-client-secret":  "AzureClientSecret",
	"azure-tenant-id":      "AzureTenantID",
}

func setConfigKey(cfg *credentials.Config, key, value string) error {
	fieldName, ok := configKeyMap[key]
	if !ok {
		keys := make([]string, 0, len(configKeyMap))
		for k := range configKeyMap {
			keys = append(keys, k)
		}
		return fmt.Errorf("unknown key %q\n\n  Valid keys:\n    %s", key, strings.Join(keys, "\n    "))
	}
	v := reflect.ValueOf(cfg).Elem().FieldByName(fieldName)
	if !v.IsValid() {
		return fmt.Errorf("internal error: field %s not found", fieldName)
	}
	v.SetString(value)
	return nil
}
