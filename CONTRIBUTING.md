# Contributing to ComplyKit

## Getting started

```bash
git clone https://github.com/complykit/complykit
cd complykit
go build -o comply .
go test ./...
```

## Adding a check

1. Find or create a checker file under `internal/checks/<integration>/`
2. Add a method that returns `[]engine.Finding`
3. Map findings to SOC2/HIPAA/CIS controls in `docs/control-mapping.md`
4. Write a test — at minimum test pass and fail cases

```go
func (c *MyChecker) checkSomething() []engine.Finding {
    // ... call cloud API ...
    if compliant {
        return []engine.Finding{pass("my_check_id", "Description passes", soc2("CC6.1"))}
    }
    return []engine.Finding{fail(
        "my_check_id", "Description of the failure",
        "Integration/Service", "resource name",
        engine.SeverityHigh,
        "Step-by-step remediation instructions",
        soc2("CC6.1"), cis("2.1"),
    )}
}
```

## Adding a framework

1. Add a new `Framework` constant in `internal/engine/types.go`
2. Add control refs to `docs/control-mapping.md`
3. Update `--framework` flag help in `cmd/scan.go`

## Pull request checklist

- [ ] `go build ./...` passes
- [ ] `go test ./...` passes
- [ ] New checks have at least one test
- [ ] Control mapping updated in `docs/control-mapping.md`
- [ ] `go vet ./...` clean

## Project structure

```
cmd/           CLI commands (cobra)
internal/
  engine/      Core types: Finding, ScanResult, Checker interface
  checks/aws/  AWS checks (IAM, S3, CloudTrail, EC2)
  checks/gcp/  GCP checks (IAM, GCS, org policies)
  checks/github/ GitHub checks (branch protection, Dependabot, etc.)
  evidence/    Local evidence vault (timestamped JSON records)
  report/      Terminal printer, JSON writer, PDF generator
  policy/      SOC2 policy document templates
  share/       JWT-signed auditor share links
  config/      .complykit.yml loader/saver
  alert/       Slack + email notifications
docs/          Architecture, plans, control mapping reference
web/           Dashboard HTML (embedded into binary via go:embed)
```
