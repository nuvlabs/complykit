# ComplyKit

**Compliance-as-code for startups.** One command to scan your AWS, GCP, and GitHub against SOC2, HIPAA, and CIS benchmarks.

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

| | Vanta / Drata | ComplyKit |
|---|---|---|
| Price | $15–30k/year | Free CLI · $299/mo Pro |
| Onboarding | Weeks | `brew install complykit && comply init` |
| Output | Dashboard | Terminal + JSON + PDF + Web UI |
| Open source | No | Yes (Apache 2.0) |

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
| `comply scan` | Scan AWS / GCP / GitHub for compliance issues |
| `comply fix [id]` | Show step-by-step remediation for failures |
| `comply watch` | Continuous scanning with regression alerts |
| `comply serve` | Web dashboard at localhost:8080 |
| `comply share` | Generate auditor share link (JWT-signed, expires) |
| `comply evidence list` | Browse the local evidence vault |
| `comply policy generate` | Generate SOC2 policy document templates |

---

## Supported frameworks

| Framework | Checks |
|-----------|--------|
| SOC2 Type 1/2 | CC6.1-9, CC7.1-5, CC8.1, CC9.1-2 |
| HIPAA Security Rule | §164.312(a)-(e) |
| CIS AWS Foundations v1.4 | CIS 1.x, 2.x, 3.x, 4.x |

## Supported integrations

- **AWS** — IAM, S3, CloudTrail, EC2 Security Groups
- **GCP** — IAM Service Accounts, Cloud Storage, Org Policies
- **GitHub** — Branch protection, Dependabot, Secret scanning, Public repos

---

## CI/CD

Add compliance scanning to every PR:

```yaml
# .github/workflows/compliance.yml
- uses: complykit/complykit-action@v1
  with:
    framework: soc2
    aws-role-arn: ${{ secrets.AWS_ROLE_ARN }}
```

Or use the [workflow template](.github/workflows/compliance.yml) directly.

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

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Adding a new check takes ~20 lines of Go.

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
