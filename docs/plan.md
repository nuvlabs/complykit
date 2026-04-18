# ComplyKit — Build Plan

## Architecture Overview

```
┌─────────────────────────────────────────────┐
│                  CLI Tool                   │
│  comply scan / comply fix / comply report   │
└──────────────┬──────────────────────────────┘
               │ OAuth / API keys
       ┌───────▼──────────────┐
       │     Integrations     │
       │  AWS · GCP · Azure   │
       │  GitHub · GitLab     │
       │  Okta · Google Wksp  │
       │  Datadog · PagerDuty │
       └───────┬──────────────┘
               │
       ┌───────▼──────────────┐
       │    Control Engine    │  ← maps findings to SOC2/HIPAA/ISO controls
       │      (the moat)      │
       └───────┬──────────────┘
               │
       ┌───────▼──────────────┐
       │      Dashboard       │  evidence vault + audit trail + reports
       └──────────────────────┘
```

---

## Phase 1 — CLI Scanner (Weeks 1–4)

**Goal:** Ship a working open-source CLI that engineers can run in minutes.

### Integrations (MVP)
- [ ] AWS (via boto3 / AWS SDK)
- [ ] GitHub (via REST API)

### Checks to implement (~40 for SOC2 Type 1)
**AWS**
- [ ] CloudTrail enabled in all regions
- [ ] S3 bucket public access block
- [ ] S3 bucket encryption at rest
- [ ] RDS encryption enabled
- [ ] IAM root MFA enforced
- [ ] IAM password policy strength
- [ ] VPC flow logs enabled
- [ ] Security groups: no 0.0.0.0/0 on port 22/3389
- [ ] EBS volumes encrypted

**GitHub**
- [ ] Branch protection enabled on main/master
- [ ] Required PR reviews enforced
- [ ] No public repositories with sensitive names
- [ ] Dependabot alerts enabled
- [ ] Secret scanning enabled

### CLI Commands
```bash
comply scan --framework soc2          # run all checks
comply scan --framework hipaa         # HIPAA subset
comply report --format pdf            # generate PDF report
comply fix <control-id>               # show remediation steps
comply watch                          # re-scan on infra changes
```

### Output Format
```
[AWS]  ✓ CloudTrail enabled
[AWS]  ✗ S3 buckets not encrypted (CIS 2.1.1)
[AWS]  ✗ MFA not enforced on IAM root (SOC2 CC6.1)
[GH]   ✓ Branch protection enabled
[GH]   ✗ 3 repos have public visibility (SOC2 CC6.6)

Score: 61/100 | 12 critical gaps | Est. audit-ready: ~6 weeks
```

### Tech Stack (CLI)
- Language: Python or Go (Go preferred for single binary distribution)
- Config: YAML-based control definitions
- Output: terminal (rich/color) + JSON + PDF

---

## Phase 2 — Dashboard & Evidence Vault (Weeks 5–8)

**Goal:** Give teams a persistent view of compliance posture + shareable audit reports.

### Features
- [ ] Web dashboard (Next.js or React)
- [ ] Evidence vault: auto-store API responses as timestamped evidence
- [ ] Compliance score trend over time (graph)
- [ ] Shareable read-only report link for auditors
- [ ] Slack/email alerts on regressions
- [ ] Policy document templates (acceptable use, access control, etc.)

### Backend
- [ ] REST API (FastAPI or Node/Express)
- [ ] PostgreSQL for evidence storage
- [ ] S3 for evidence file attachments
- [ ] Auth: OAuth (Google/GitHub SSO)

### Deployment
- [ ] Docker + docker-compose for local dev
- [ ] Deploy to Railway / Render / Fly.io (low ops overhead)

---

## Phase 3 — Monetization (Weeks 9–12)

### Pricing Tiers

| Plan       | Price         | Features                                                   |
|------------|---------------|------------------------------------------------------------|
| Free       | $0            | CLI scan, basic terminal report, 1 framework               |
| Pro        | $299/month    | Evidence vault, auditor sharing, Slack alerts, 2 frameworks|
| Team       | $799/month    | All frameworks, team access, policy templates, priority support |
| Enterprise | Custom        | SSO, custom controls, SLA, dedicated onboarding            |

### Payment
- [ ] Stripe integration
- [ ] Usage-based billing option (per scan / per integration)

---

## Go-To-Market Plan

### Step 1 — Open Source Distribution
- Publish CLI to GitHub as open source (Apache 2.0)
- Submit to Hacker News "Show HN"
- Post in r/devops, r/aws, r/netsec
- List on Awesome Security lists

### Step 2 — Content Moat
- Write "SOC2 for Startups in 2025" guide (high search intent)
- "AWS SOC2 checklist" — targets engineers Googling before audits
- Build in public on Twitter/X + LinkedIn

### Step 3 — Audit Firm Partnerships
- Partner with boutique SOC2 audit firms
- Offer white-label reports + referral fees
- Auditors send you leads in exchange for making their job easier

### Step 4 — Direct Outreach
- Target startups that just raised Series A (have money, need compliance for enterprise deals)
- Search Crunchbase for recent funding rounds in B2B SaaS
- Cold email founders/CTOs: "Saw you raised — are you getting asked for SOC2 yet?"

---

## Control Mapping Schema (Core Data Model)

```yaml
controls:
  - id: CC6.1
    framework: soc2
    title: "Logical Access Security"
    description: "Entity restricts logical access to systems"
    checks:
      - integration: aws
        resource: iam
        rule: root_mfa_enabled
        severity: critical
      - integration: aws
        resource: iam
        rule: password_policy_min_length_14
        severity: high
    remediation: |
      1. Enable MFA on AWS root account
      2. Go to IAM → Account settings → Enable MFA
      3. Use hardware MFA key or authenticator app
```

---

## Milestones

| Week | Milestone                                          |
|------|----------------------------------------------------|
| 1    | Repo setup, CLI scaffold, AWS auth working         |
| 2    | 20 AWS checks implemented                         |
| 3    | 15 GitHub checks + SOC2 control mapping            |
| 4    | PDF report generation, publish to GitHub           |
| 5    | Dashboard scaffold + auth                          |
| 6    | Evidence vault working                             |
| 7    | Auditor sharing link + Slack alerts                |
| 8    | Beta launch, first 5 paying customers              |
| 10   | Stripe billing live                                |
| 12   | 20 paying customers, $6k MRR                       |

---

## Risks & Mitigations

| Risk                                    | Mitigation                                           |
|-----------------------------------------|------------------------------------------------------|
| Vanta drops price to compete            | Compete on simplicity + engineer experience, not price|
| Compliance frameworks change            | Version-controlled control definitions (community PRs)|
| AWS/GitHub change APIs                  | Abstraction layer + integration tests                |
| Sales cycle too long                    | Land via CLI (bottoms-up), expand to paid dashboard  |
| False positives erode trust             | Conservative checks only; flag uncertain as "review" |
