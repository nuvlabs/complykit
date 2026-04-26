package credentials

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const filename = ".complykit/credentials.json"

type Credentials struct {
	URI       string `json:"uri"`
	Token     string `json:"token"`
	Email     string `json:"email"`
	OrgID     string `json:"org_id"`
	ExpiresAt string `json:"expires_at,omitempty"` // RFC3339
}

func path() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, filename), nil
}

func Save(c *Credentials) error {
	p, err := path()
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

func Load() (*Credentials, error) {
	p, err := path()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // not logged in — not an error
		}
		return nil, err
	}
	var c Credentials
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("corrupted credentials file: %w", err)
	}
	return &c, nil
}

// IsExpired returns true if the saved token has expired.
func (c *Credentials) IsExpired() bool {
	if c.ExpiresAt == "" {
		return false // old token without expiry — assume valid
	}
	t, err := time.Parse(time.RFC3339, c.ExpiresAt)
	if err != nil {
		return false
	}
	return time.Now().After(t)
}

// DaysUntilExpiry returns how many days until the token expires.
func (c *Credentials) DaysUntilExpiry() int {
	if c.ExpiresAt == "" {
		return -1
	}
	t, err := time.Parse(time.RFC3339, c.ExpiresAt)
	if err != nil {
		return -1
	}
	return int(time.Until(t).Hours() / 24)
}

func Clear() error {
	p, err := path()
	if err != nil {
		return err
	}
	err = os.Remove(p)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
