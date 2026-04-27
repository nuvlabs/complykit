# ComplyKit

**Compliance-as-code for startups.** One command to scan your AWS, GCP, Azure, Kubernetes, and Terraform against SOC 2, HIPAA, CIS, ISO 27001, and PCI DSS.

```
comply scan --framework soc2

  ComplyKit — SOC2 Scan

  Scanning AWS/IAM...
  Scanning AWS/S3...
  Scanning AWS/CloudTrail...
  Scanning GitHub...

  [AWS/IAM]
  ✓ Root account MFA enabled
  ✗ 3 IAM users missing MFA: alice, bob, carol  [high]
    → SOC2 CC6.1 · HIPAA 164.312(d) · CIS 1.10

  [AWS/S3]
  ✓ All S3 buckets have server-side encryption
  ✗ 2 buckets missing public access block  [critical]
    → SOC2 CC6.6 · CIS 2.1.2

  Score: 72/100  |  9 passed  |  4 failed
```

---

## Why ComplyKit

Existing tools (Vanta, Drata, Secureframe) cost $15–30k/year and require a dedicated compliance team to operate. ComplyKit is built for **engineering-led startups** that need to close their first enterprise deal.

| | Vanta / Drata | ComplyKit Free CLI | ComplyKit Pro |
|---|---|---|---|
| Price | $15–30k/year | Free forever | $299/month |
| Onboarding | Weeks | 2 minutes | 2 minutes |
| Scans | Automated | Unlimited | Unlimited |
| Frameworks | SOC2 / HIPAA | SOC2 · HIPAA · CIS · ISO 27001 · PCI DSS | SOC2 · HIPAA · CIS · ISO 27001 · PCI DSS |
| Terminal + JSON + PDF output | No | ✓ | ✓ |
| Policy document templates | Add-on | ✓ | ✓ |
| Remediation steps (`comply fix`) | Limited | ✓ | ✓ |
| Local evidence vault | No | ✓ (local only) | ✓ (cloud-hosted) |
| Web dashboard | Hosted | localhost only | Hosted (any browser) |
| Checks catalog (enable/disable) | No | — | ✓ (super admin) |
| Auditor share links | No | — | ✓ (JWT-signed, expiring) |
| Slack / email alerts | Add-on | — | ✓ |
| Team seats | Unlimited | 1 | 5 |
| Open source | No | Apache 2.0 | Apache 2.0 |

**The key difference:** Free CLI runs entirely on your machine — perfect for scanning
and fixing issues yourself. Pro adds the hosted layer: a dashboard your whole team
can access, share links you send to auditors, and alerts that fire when something
regresses — without keeping your laptop open.

> See [full pricing breakdown →](docs/pricing.md)

---

## Install

**Homebrew (macOS/Linux)**
```bash
brew install complykit/tap/complykit
```

**Go**
```bash
go install github.com/complykit/complykit@latest
```

**Binary releases** — [github.com/complykit/complykit/releases](https://github.com/complykit/complykit/releases)

---

## Quick start

```bash
# 1. configure (2 minutes)
comply init

# 2. scan
comply scan --framework soc2

# 3. see how to fix failures
comply fix

# 4. open the web dashboard
comply serve
# → http://localhost:8080

# 5. share with your auditor
comply share --label "Q1 Audit"
# → http://your-server/share/<token>  (read-only, expires in 30 days)
```

---

## Commands

| Command | Description |
|---------|-------------|
| `comply init` | Interactive setup — configure integrations and alerts |
| `comply scan` | Scan AWS / GCP / Azure / Kubernetes / Terraform / GitHub |
| `comply fix [id]` | Show step-by-step remediation for failures |
| `comply watch` | Continuous scanning with regression alerts |
| `comply serve` | Web dashboard at localhost:8080 |
| `comply share` | Generate auditor share link (JWT-signed, expires) |
| `comply ci github` | Generate GitHub Actions workflow template |
| `comply ci gitlab` | Generate GitLab CI pipeline template |
| `comply evidence list` | Browse the local evidence vault |
| `comply policy generate` | Generate SOC2 policy document templates |
| `comply login` | Authenticate with ComplyKit cloud |
| `comply whoami` | Show current authenticated user and token expiry |
| `comply update` | Auto-update CLI (detects brew / go / binary) |
| `comply config` | Manage cloud credentials |
| `comply admin` | Manage orgs, users, and API keys (Pro) |

---

## Supported frameworks

| Framework | Checks |
|-----------|--------|
| SOC2 Type 1/2 | CC6.1-9, CC7.1-5, CC8.1, CC9.1-2 |
| HIPAA Security Rule | §164.312(a)-(e) |
| CIS AWS Foundations v1.4 | CIS 1.x, 2.x, 3.x, 4.x |
| ISO 27001:2022 | A.5–A.8 control families |
| PCI DSS v4.0 | Requirements 1–12 |

## Supported integrations

- **AWS** — IAM, S3, CloudTrail, CloudWatch, EC2 Security Groups, RDS, KMS, ECR, EKS, GuardDuty, WAF, Config, Access Analyzer
- **GCP** — IAM Service Accounts, Cloud Storage, Org Policies
- **Azure** — IAM, AKS, Key Vault, Active Directory, Security policies
- **Kubernetes** — Pod security, RBAC, network policies, resource limits
- **Terraform / IaC** — Static analysis of infrastructure-as-code
- **GitHub** — Branch protection, Dependabot, Secret scanning, Actions, Public repos
- **Custom** — Define your own controls in `complykit.yaml`

---

## CI/CD

Generate and add compliance scanning to every PR:

```bash
comply ci github   # generates .github/workflows/compliance.yml
comply ci gitlab   # generates .gitlab-ci.yml compliance job
```

Or drop in the action directly:

```yaml
# .github/workflows/compliance.yml
- uses: complykit/complykit-action@v1
  with:
    framework: soc2
    aws-role-arn: ${{ secrets.AWS_ROLE_ARN }}
```

---

## Configuration

`comply init` generates `.complykit.yml`:

```yaml
framework: soc2
aws:
  enabled: true
  profile: ""
  region: us-east-1
github:
  enabled: true
  owner: my-org
alerts:
  slack_webhook: https://hooks.slack.com/...
  email_to: cto@mycompany.com
```

---

## Evidence vault

Every scan is automatically saved to `.complykit-evidence/` as timestamped JSON — a local audit trail that you control.

```bash
comply evidence list   # browse history
comply evidence show   # inspect latest
```

---

## Policy documents

Generate the 5 policy documents required for SOC2 Type 1:

```bash
comply policy generate --company "Acme Inc" --out ./policies
```

Produces: Access Control, Incident Response, Change Management, Data Classification, Vendor Management.

---

## Custom controls

Define your own checks in `complykit.yaml` without writing Go:

```yaml
custom_controls:
  - id: CUSTOM-001
    title: "All production databases must have backups enabled"
    framework: soc2
    severity: high
```

Custom controls appear alongside built-in checks in scan output and the web dashboard.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Adding a new check takes ~20 lines of Go.

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
