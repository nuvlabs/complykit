package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update comply to the latest version",
	RunE:  runUpdate,
}

func init() {
	rootCmd.AddCommand(updateCmd)
}

func runUpdate(cmd *cobra.Command, args []string) error {
	bold   := color.New(color.Bold)
	green  := color.New(color.FgGreen)
	cyan   := color.New(color.FgCyan)
	yellow := color.New(color.FgYellow)

	fmt.Println()
	bold.Println("  Checking for updates...")

	latest, err := fetchLatestVersion()
	if err != nil {
		return fmt.Errorf("could not check for updates: %w", err)
	}

	current := appVersion
	if current == "dev" {
		yellow.Println("  Running dev build — skipping version check.")
		fmt.Println()
		return nil
	}

	if normalise(latest) == normalise(current) {
		green.Printf("  comply %s is already up to date.\n\n", current)
		return nil
	}

	cyan.Printf("  New version available: %s → %s\n\n", current, latest)

	switch detectInstallMethod() {
	case "brew":
		return runUpgrade("brew", []string{"upgrade", "nuvlabs/tap/complykit"},
			"brew upgrade nuvlabs/tap/complykit")

	case "go":
		return runUpgrade("go", []string{"install", "github.com/complykit/complykit@latest"},
			"go install github.com/complykit/complykit@latest")

	default:
		// Binary install — download and replace self
		return selfUpdate(latest)
	}
}

func fetchLatestVersion() (string, error) {
	resp, err := http.Get("https://api.github.com/repos/nuvlabs/complykit/releases/latest")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var result struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	return strings.TrimPrefix(result.TagName, "v"), nil
}

func normalise(v string) string {
	return strings.TrimPrefix(strings.TrimSpace(v), "v")
}

// detectInstallMethod checks how comply was installed.
func detectInstallMethod() string {
	exe, err := os.Executable()
	if err != nil {
		return "unknown"
	}
	exe = strings.ToLower(exe)

	// Homebrew paths: /opt/homebrew/... or /usr/local/Cellar/...
	if strings.Contains(exe, "homebrew") || strings.Contains(exe, "cellar") {
		return "brew"
	}
	// go install lands in ~/go/bin
	if strings.Contains(exe, "go/bin") {
		return "go"
	}
	return "binary"
}

func runUpgrade(bin string, args []string, _ string) error {
	green := color.New(color.FgGreen)
	cyan  := color.New(color.FgCyan)

	quietEnv := append(os.Environ(),
		"HOMEBREW_NO_AUTO_UPDATE=1",
		"HOMEBREW_NO_ENV_HINTS=1",
		"HOMEBREW_NO_INSTALL_CLEANUP=1",
	)

	// For brew: refresh only the nuvlabs tap first (avoids full noisy auto-update
	// but ensures we see the latest formula version before upgrading).
	if bin == "brew" {
		tap := exec.Command("brew", "tap", "nuvlabs/tap")
		tap.Env = quietEnv
		tap.CombinedOutput() // ignore errors — tap refresh is best-effort
	}

	c := exec.Command(bin, args...)
	c.Env = quietEnv

	out, err := c.CombinedOutput()
	output := strings.TrimSpace(string(out))

	if err != nil {
		fmt.Fprintf(os.Stderr, "\n%s\n", output)
		return fmt.Errorf("update failed")
	}

	// Brew exits 0 even when nothing changed — detect and report honestly
	if strings.Contains(output, "already installed") || strings.Contains(output, "already up-to-date") {
		green.Println("  comply is already up to date.")
		fmt.Println()
		return nil
	}

	green.Println("  ✓ comply updated successfully!")
	cyan.Println("  Run `comply --version` to confirm.")
	fmt.Println()
	return nil
}

func selfUpdate(latest string) error {
	dim    := color.New(color.Faint)
	green  := color.New(color.FgGreen)
	yellow := color.New(color.FgYellow)

	goos   := runtime.GOOS
	goarch := runtime.GOARCH

	// Map Go arch names to GoReleaser archive names
	archMap := map[string]string{"amd64": "amd64", "arm64": "arm64"}
	arch, ok := archMap[goarch]
	if !ok {
		return fmt.Errorf("unsupported architecture: %s", goarch)
	}

	osMap := map[string]string{"darwin": "darwin", "linux": "linux", "windows": "windows"}
	osName, ok := osMap[goos]
	if !ok {
		return fmt.Errorf("unsupported OS: %s", goos)
	}

	ext := "tar.gz"
	if goos == "windows" {
		ext = "zip"
	}

	url := fmt.Sprintf(
		"https://github.com/nuvlabs/complykit/releases/download/v%s/comply_%s_%s.%s",
		latest, osName, arch, ext,
	)

	dim.Printf("  Downloading: %s\n\n", url)

	// For binary installs, tell them to re-download — self-replace is complex and risky
	yellow.Println("  Binary install detected.")
	fmt.Println()
	fmt.Println("  Download the latest release for your platform:")
	fmt.Printf("  %s\n\n", url)
	green.Printf("  Or install via Homebrew (recommended on macOS):\n")
	fmt.Println("    brew tap nuvlabs/tap && brew install complykit")
	fmt.Println()
	return nil
}
