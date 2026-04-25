# ComplyKit Developer Guide

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Project Structure](#2-project-structure)
3. [Core Concepts](#3-core-concepts)
4. [Adding a New Check](#4-adding-a-new-check)
5. [Adding a New Integration](#5-adding-a-new-integration)
6. [Adding a New Framework](#6-adding-a-new-framework)
7. [CLI Commands](#7-cli-commands)
8. [Evidence Vault](#8-evidence-vault)
9. [Share Links](#9-share-links)
10. [Web Dashboard](#10-web-dashboard)
11. [Testing](#11-testing)
12. [Building & Releasing](#12-building--releasing)

---

## 1. Architecture Overview

```
CLI (cobra)
    │
    ├── cmd/scan.go          ← orchestrates checkers, collects findings
    │        │
    │   ┌────▼─────────────────────────────┐
    │   │         Checker Interface         │
    │   │  Run() ([]Finding, error)         │
    │   │  Integration() string             │
    │   └──┬──────────────┬────────────────┘
    │      │              │
    │  AWS Checker    GitHub Checker   GCP Checker ...
    │      │
    │   Findings → engine.ScanResult
    │
    ├── cmd/serve.go         ← HTTP server, embeds dashboard.html
    ├── cmd/share.go         ← JWT-signed read-only links
    ├── cmd/watch.go         ← polling loop + diff + alerts
    ├── cmd/fix.go           ← filter failures, print remediation
    ├── cmd/evidence.go      ← browse evidence vault
    └── cmd/policy.go        ← generate markdown policy docs
```

**Data flow for `comply scan`:**

```
1. Load AWS/GCP/GitHub credentials (env + flags + .complykit.yml)
2. For each checker: Run() → []Finding
3. Aggregate into ScanResult (score, pass/fail counts)
4. Print terminal report (internal/report/printer.go)
5. Auto-save to ~/.complykit/evidence/scan-<timestamp>.json
6. Optionally: write JSON (--output), write PDF (--pdf)
```

---

## 2. Project Structure

```
complykit/
├── main.go                          entry point
├── comply                           compiled binary (gitignored)
│
├── cmd/                             CLI layer (cobra commands)
│   ├── root.go                      banner + Execute()
│   ├── scan.go                      comply scan
│   ├── fix.go                       comply fix
│   ├── watch.go                     comply watch
│   ├── serve.go                     comply serve
│   ├── share.go                     comply share
│   ├── evidence.go                  comply evidence
│   ├── policy.go                    comply policy
│   ├── init.go                      comply init
│   └── dashboard.html               embedded web UI (go:embed)
│
├── internal/
│   ├── engine/
│   │   ├── types.go                 Finding, ScanResult, Checker, Severity, Status
│   │   └── types_test.go
│   │
│   ├── checks/
│   │   ├── aws/
│   │   │   ├── iam.go               root MFA, password policy, console MFA
│   │   │   ├── s3.go                public access block, encryption
│   │   │   ├── cloudtrail.go        trail enabled, multi-region
│   │   │   └── securitygroups.go    open SSH/RDP
│   │   ├── gcp/
│   │   │   └── gcp.go               service account keys, GCS IAM, org policy
│   │   └── github/
│   │       └── github.go            branch protection, public repos, Dependabot
│   │
│   ├── evidence/
│   │   ├── store.go                 save/list/latest evidence records
│   │   └── store_test.go
│   │
│   ├── report/
│   │   ├── printer.go               colored terminal output
│   │   ├── json.go                  JSON report writer
│   │   ├── json_test.go
│   │   └── pdf.go                   PDF report generator (go-pdf/fpdf)
│   │
│   ├── policy/
│   │   ├── templates.go             5 SOC2 policy doc templates
│   │   └── templates_test.go
│   │
│   ├── share/
│   │   └── share.go                 JWT token create/verify/list
│   │
│   ├── alert/
│   │   └── alert.go                 Slack webhook + SMTP email
│   │
│   └── config/
│       └── config.go                .complykit.yml load/save
│
├── web/
│   └── dashboard.html               source copy of the dashboard
│
├── docs/
│   ├── idea.md
│   ├── plan.md
│   ├── control-mapping.md
│   ├── developer-guide.md           ← this file
│   └── compliance-details.md
│
├── .github/
│   └── workflows/
│       └── compliance.yml           GitHub Actions CI workflow
│
├── Formula/
│   └── complykit.rb                 Homebrew formula
│
├── go.mod / go.sum
├── README.md
├── LICENSE                          Apache 2.0
├── CONTRIBUTING.md
└── .gitignore
```

---

## 3. Core Concepts

### Finding

The atomic unit of a check result:

```go
type Finding struct {
    CheckID     string       // unique snake_case ID: "aws_iam_root_mfa"
    Title       string       // human sentence: "Root account MFA not enabled"
    Status      Status       // pass | fail | skip
    Severity    Severity     // critical | high | medium | low
    Integration string       // "AWS/IAM", "GitHub", "GCP"
    Resource    string       // what was checked: "root", "3 buckets", "users"
    Detail      string       // extra context (used for skip reason)
    Remediation string       // step-by-step fix instructions
    Controls    []ControlRef // frameworks + control IDs this maps to
}
```

### ScanResult

Aggregates all findings from all checkers:

```go
type ScanResult struct {
    Findings []Finding
    Passed   int
    Failed   int
    Skipped  int
    Score    int  // Passed / (Passed + Failed) * 100
}
// skipped findings do NOT affect the score
```

### Checker Interface

Every integration implements this:

```go
type Checker interface {
    Run() ([]Finding, error)
    Integration() string  // displayed in terminal and dashboard
}
```

### ControlRef

Maps a finding to a compliance control:

```go
type ControlRef struct {
    Framework Framework  // soc2 | hipaa | cis
    ID        string     // "CC6.1", "164.312(d)", "1.5"
}
```

---

## 4. Adding a New Check

### Step 1 — Write the check method

Add a method to the relevant checker file. Follow this pattern exactly:

```go
func (c *IAMChecker) checkHardwareMFA() []engine.Finding {
    out, err := c.client.GetAccountSummary(context.Background(), &iam.GetAccountSummaryInput{})
    if err != nil {
        // always return a skip — never crash, never return error for API issues
        return []engine.Finding{skip("aws_iam_hardware_mfa", "Hardware MFA for Root", err.Error())}
    }

    if out.SummaryMap["AccountHardwareMFAEnabled"] == 1 {
        return []engine.Finding{pass(
            "aws_iam_hardware_mfa",
            "Root account uses hardware MFA",
            "AWS/IAM", "root",
            soc2("CC6.1"), cis("1.14"),
        )}
    }

    return []engine.Finding{fail(
        "aws_iam_hardware_mfa",
        "Root account does not use hardware MFA",
        "AWS/IAM", "root",
        engine.SeverityMedium,
        "Purchase a hardware security key (YubiKey) and register it:\n"+
            "  AWS Console → IAM → Dashboard → Activate MFA → Hardware TOTP token",
        soc2("CC6.1"), cis("1.14"),
    )}
}
```

### Step 2 — Call it from Run()

```go
func (c *IAMChecker) Run() ([]engine.Finding, error) {
    var findings []engine.Finding
    findings = append(findings, c.checkRootMFA()...)
    findings = append(findings, c.checkPasswordPolicy()...)
    findings = append(findings, c.checkHardwareMFA()...)  // ← add here
    return findings, nil
}
```

### Step 3 — Update control-mapping.md

Add the check to `docs/control-mapping.md` under the relevant control.

### Step 4 — Write a test

```go
func TestIAM_CheckHardwareMFA_Pass(t *testing.T) {
    // use a mock client or integration test against LocalStack
    findings := []engine.Finding{
        {CheckID: "aws_iam_hardware_mfa", Status: engine.StatusPass},
    }
    for _, f := range findings {
        if f.Status != engine.StatusPass {
            t.Errorf("expected pass, got %s", f.Status)
        }
    }
}
```

### Check ID naming convention

```
<integration>_<service>_<what>

aws_iam_root_mfa
aws_s3_public_access_block
aws_cloudtrail_multiregion
gcp_iam_sa_keys
github_branch_protection
```

---

## 5. Adding a New Integration

### Step 1 — Create the package

```
internal/checks/azure/azure.go
```

### Step 2 — Implement the Checker interface

```go
package azure

import (
    "github.com/complykit/complykit/internal/engine"
)

type Checker struct {
    subscriptionID string
    // Azure SDK client fields
}

func NewCheckerFromEnv() *Checker {
    subID := os.Getenv("AZURE_SUBSCRIPTION_ID")
    if subID == "" {
        return nil
    }
    return &Checker{subscriptionID: subID}
}

func (c *Checker) Integration() string { return "Azure" }

func (c *Checker) Run() ([]engine.Finding, error) {
    var findings []engine.Finding
    findings = append(findings, c.checkSecurityCenter()...)
    // add more checks...
    return findings, nil
}
```

### Step 3 — Wire into scan.go and watch.go

In `cmd/scan.go`, add alongside the GCP block:

```go
if checker := azurechecks.NewCheckerFromEnv(); checker != nil {
    dim.Printf("  Scanning %s...\n", checker.Integration())
    findings, _ := checker.Run()
    for _, f := range findings {
        result.Add(f)
    }
} else {
    dim.Println("  Skipping Azure (set AZURE_SUBSCRIPTION_ID to enable)")
}
```

### Step 4 — Add to config struct

In `internal/config/config.go`:

```go
type Config struct {
    // ...
    Azure AzureConfig `yaml:"azure,omitempty"`
}

type AzureConfig struct {
    SubscriptionID string `yaml:"subscription_id,omitempty"`
    Enabled        bool   `yaml:"enabled"`
}
```

---

## 6. Adding a New Framework

### Step 1 — Add the constant

```go
// internal/engine/types.go
const (
    FrameworkSOC2   Framework = "soc2"
    FrameworkHIPAA  Framework = "hipaa"
    FrameworkCIS    Framework = "cis"
    FrameworkISO27001 Framework = "iso27001"  // ← new
)
```

### Step 2 — Add control refs to your checks

```go
func iso(id string) engine.ControlRef {
    return engine.ControlRef{Framework: engine.FrameworkISO27001, ID: id}
}

// then in your finding:
soc2("CC6.1"), iso("A.9.1.1"),
```

### Step 3 — Update CLI flag help

In `cmd/scan.go`:
```go
scanCmd.Flags().StringVarP(&flagFramework, "framework", "f", "soc2",
    "Compliance framework: soc2, hipaa, cis, iso27001")
```

### Step 4 — Document it

Add a section to `docs/control-mapping.md` and `docs/compliance-details.md`.

---

## 7. CLI Commands

All commands live in `cmd/` and are registered in `init()` via `rootCmd.AddCommand()`.

### Adding a new command

```go
// cmd/mycommand.go
package cmd

import (
    "github.com/spf13/cobra"
)

var myCmd = &cobra.Command{
    Use:   "mycommand [args]",
    Short: "One-line description",
    RunE:  runMyCommand,
}

func init() {
    myCmd.Flags().StringVar(&myFlag, "flag", "default", "flag description")
    rootCmd.AddCommand(myCmd)
}

func runMyCommand(cmd *cobra.Command, args []string) error {
    // implementation
    return nil
}
```

### Accessing config in commands

```go
cfg, err := config.Load()
if err != nil {
    // no config — either prompt or use defaults/flags
}
```

---

## 8. Evidence Vault

Evidence records are stored as JSON in `~/.complykit/evidence/`:

```
~/.complykit/evidence/
├── scan-20260418-091532-4821.json
├── scan-20260417-154201-2034.json
└── .share-secret          ← HMAC key (never commit)
```

**Record schema:**

```json
{
  "id": "20260418-091532-4821",
  "collected_at": "2026-04-18T09:15:32Z",
  "framework": "soc2",
  "score": 72,
  "passed": 9,
  "failed": 4,
  "skipped": 1,
  "findings": [ ...engine.Finding... ]
}
```

**API:**

```go
store := evidence.NewStore("")         // defaults to ~/.complykit/evidence/
store.Save(result, "soc2")             // auto-called by comply scan
store.List()                           // []Record, newest first
store.Latest()                         // *Record or nil
```

---

## 9. Share Links

Share links are JWT tokens signed with a per-install HMAC secret stored in `~/.complykit/evidence/.share-secret`.

**Token payload:**

```json
{
  "record_id": "20260418-091532-4821",
  "sub": "complykit-share",
  "iat": 1713434132,
  "exp": 1716026132
}
```

**`comply serve`** handles `/share/<token>`:
1. Calls `share.Verify(token)` — validates signature + expiry
2. Injects `window.__SHARE_RECORD_ID = "<id>"` into the dashboard HTML
3. Dashboard JS detects this, hides nav, loads only that record via `/api/record/<id>`

**To add IP allowlisting or password protection** — wrap the `/share/` handler in middleware before registering with the mux.

---

## 10. Web Dashboard

The dashboard (`cmd/dashboard.html`) is a single self-contained HTML file embedded into the binary via `//go:embed dashboard.html`.

**API endpoints served by `comply serve`:**

| Endpoint | Response |
|----------|----------|
| `GET /` | dashboard HTML |
| `GET /api/latest` | latest `evidence.Record` as JSON |
| `GET /api/history` | `[]summary` (no findings, keeps payload small) |
| `GET /api/record/:id` | full `evidence.Record` for that id |
| `GET /share/:token` | dashboard pre-loaded with specific record (read-only) |

**To modify the dashboard:**
1. Edit `web/dashboard.html` (the source copy)
2. Copy to `cmd/dashboard.html` (`cp web/dashboard.html cmd/dashboard.html`)
3. Rebuild — `go build -o comply .`

The `web/` copy is the source of truth. `cmd/` copy is what gets embedded.

---

## 11. Testing

### Run all tests

```bash
go test ./...
```

### Run with coverage

```bash
go test ./... -coverprofile=coverage.out
go tool cover -html=coverage.out
```

### Test a specific package

```bash
go test ./internal/evidence/...
go test ./internal/engine/... -v
```

### What to test

| Package | What to test |
|---------|-------------|
| `engine` | Score math, Add() behavior for each Status |
| `evidence` | Save creates file, List sorts correctly, Latest returns newest |
| `report` | JSON output is valid, fields populated correctly |
| `policy` | All templates generate, company name interpolated |
| `checks/aws` | Pass case (mock), fail case (mock), skip on API error |
| `checks/github` | Pass/fail/skip using mock GitHub client |

### Testing AWS/GCP checks

Use a local mock or table-driven tests with dependency injection:

```go
type mockIAMClient interface {
    GetAccountSummary(ctx context.Context, ...) (*iam.GetAccountSummaryOutput, error)
}

type IAMChecker struct {
    client mockIAMClient
}

// in tests:
checker := &IAMChecker{client: &fakeIAMClient{mfaEnabled: true}}
findings := checker.checkRootMFA()
```

---

## 12. Building & Releasing

### Development build

```bash
go build -o comply .
```

### Cross-compile for all platforms

```bash
GOOS=linux   GOARCH=amd64 go build -ldflags="-s -w" -o dist/comply-linux-amd64 .
GOOS=linux   GOARCH=arm64 go build -ldflags="-s -w" -o dist/comply-linux-arm64 .
GOOS=darwin  GOARCH=amd64 go build -ldflags="-s -w" -o dist/comply-darwin-amd64 .
GOOS=darwin  GOARCH=arm64 go build -ldflags="-s -w" -o dist/comply-darwin-arm64 .
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o dist/comply-windows-amd64.exe .
```

### Release checklist

- [ ] Bump version in `main.go` (add `var version = "0.1.0"`)
- [ ] `go mod tidy`
- [ ] `go test ./...` all green
- [ ] Cross-compile all platforms
- [ ] `sha256sum dist/*` — update `Formula/complykit.rb`
- [ ] `git tag v0.1.0 && git push origin v0.1.0`
- [ ] Create GitHub release with binaries attached
- [ ] Update Homebrew tap repo

### GoReleaser (recommended for v0.2+)

```yaml
# .goreleaser.yml
builds:
  - env: [CGO_ENABLED=0]
    goos: [linux, darwin, windows]
    goarch: [amd64, arm64]
    ldflags: ["-s -w -X main.version={{.Version}}"]

brews:
  - tap:
      owner: complykit
      name: homebrew-tap
    homepage: https://github.com/complykit/complykit
    description: Compliance-as-code for startups
```

```bash
goreleaser release --clean
```
