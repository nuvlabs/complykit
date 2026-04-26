package cmd

import (
	"fmt"

	"github.com/fatih/color"

	"github.com/complykit/complykit/internal/credentials"
)

// requireValidCreds loads credentials and fails clearly if missing or expired.
func requireValidCreds() (*credentials.Credentials, error) {
	creds, err := credentials.Load()
	if err != nil {
		return nil, err
	}
	if creds == nil {
		return nil, credError("Not logged in.", "comply login --uri <server>")
	}
	if creds.IsExpired() {
		return nil, credError("Session expired.", fmt.Sprintf("comply login --uri %s", creds.URI))
	}
	return creds, nil
}

func credError(reason, fix string) error {
	fmt.Println()
	color.New(color.FgRed).Printf("  ✗ %s\n", reason)
	fmt.Printf("  Re-authenticate: %s\n\n", fix)
	// Return sentinel so callers don't double-print
	return fmt.Errorf("")
}
