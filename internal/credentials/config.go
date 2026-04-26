package credentials

import (
	"encoding/json"
	"os"
	"path/filepath"
)

const configFilename = ".complykit/config.json"

// Config stores cloud provider credentials and scan preferences.
// Values here are used as fallbacks when env vars are not set.
type Config struct {
	// AWS
	AWSProfile         string `json:"aws_profile,omitempty"`
	AWSRegion          string `json:"aws_region,omitempty"`
	AWSAccessKeyID     string `json:"aws_access_key_id,omitempty"`
	AWSSecretAccessKey string `json:"aws_secret_access_key,omitempty"`

	// GitHub
	GitHubToken string `json:"github_token,omitempty"`
	GitHubOwner string `json:"github_owner,omitempty"`

	// GCP
	GCPProject     string `json:"gcp_project,omitempty"`
	GCPCredentials string `json:"gcp_credentials,omitempty"` // path to service account JSON

	// Azure
	AzureSubscriptionID string `json:"azure_subscription_id,omitempty"`
	AzureClientID       string `json:"azure_client_id,omitempty"`
	AzureClientSecret   string `json:"azure_client_secret,omitempty"`
	AzureTenantID       string `json:"azure_tenant_id,omitempty"`
}

func configPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, configFilename), nil
}

func LoadConfig() (*Config, error) {
	p, err := configPath()
	if err != nil {
		return &Config{}, nil
	}
	data, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return &Config{}, nil
		}
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return &Config{}, nil
	}
	return &c, nil
}

func SaveConfig(c *Config) error {
	p, err := configPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, data, 0600)
}

// ApplyToEnv sets env vars from config for any that are not already set.
func (c *Config) ApplyToEnv() {
	setIfEmpty := func(key, val string) {
		if val != "" && os.Getenv(key) == "" {
			os.Setenv(key, val)
		}
	}
	setIfEmpty("AWS_PROFILE", c.AWSProfile)
	setIfEmpty("AWS_REGION", c.AWSRegion)
	setIfEmpty("AWS_ACCESS_KEY_ID", c.AWSAccessKeyID)
	setIfEmpty("AWS_SECRET_ACCESS_KEY", c.AWSSecretAccessKey)
	setIfEmpty("GITHUB_TOKEN", c.GitHubToken)
	setIfEmpty("GITHUB_OWNER", c.GitHubOwner)
	setIfEmpty("GCP_PROJECT_ID", c.GCPProject)
	setIfEmpty("GOOGLE_APPLICATION_CREDENTIALS", c.GCPCredentials)
	setIfEmpty("AZURE_SUBSCRIPTION_ID", c.AzureSubscriptionID)
	setIfEmpty("AZURE_CLIENT_ID", c.AzureClientID)
	setIfEmpty("AZURE_CLIENT_SECRET", c.AzureClientSecret)
	setIfEmpty("AZURE_TENANT_ID", c.AzureTenantID)
}
