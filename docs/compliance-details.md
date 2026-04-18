# Compliance Requirements — What You Actually Need

This document explains what SOC2, HIPAA, and CIS actually require in plain language,
what evidence you need to collect, and how ComplyKit maps to each requirement.

---

## Part 1 — SOC2

### What is SOC2?

SOC2 (Service Organization Control 2) is an audit framework created by the AICPA.
It's not a law — it's a voluntary standard. But in practice, most enterprise B2B
customers **require** a SOC2 report before signing contracts above ~$50k/year.

### Type 1 vs Type 2

| | SOC2 Type 1 | SOC2 Type 2 |
|---|---|---|
| What it proves | Controls are designed correctly | Controls actually worked over time |
| Time period | Point-in-time (one day) | 6–12 month observation window |
| Time to get | 1–3 months | 6–12 months |
| Cost | $15–30k | $25–50k |
| What customers want | "Get started" | Enterprise deals, financial sector |

**Recommendation for early-stage startups:** Get Type 1 first. It unblocks deals
and gives you 6–12 months to build toward Type 2.

---

### The 5 Trust Service Criteria (TSC)

SOC2 is organized around 5 criteria. Most startups only need **Security (CC)**.
The others (Availability, Confidentiality, Processing Integrity, Privacy) are
optional add-ons that larger customers may request.

---

### CC6 — Logical and Physical Access Controls

This is the most important category. It's about who can access what.

#### CC6.1 — Logical access security

**What it means:** You have controls that restrict who can log into your systems.

**What auditors check:**
- Is MFA required for all production system access?
- Is there a formal access provisioning process?
- Are passwords strong enough?
- Do you have an IAM/SSO system?

**Evidence you need:**
- Screenshot of AWS IAM password policy
- Screenshot showing MFA enabled on all IAM users
- Access request/approval emails or tickets
- List of users with production access

**ComplyKit checks:**
- `aws_iam_root_mfa` — root account MFA
- `aws_iam_console_mfa` — all IAM users MFA
- `aws_iam_password_policy` — password strength

---

#### CC6.2 — Prior to issuing credentials, registered and authorized

**What it means:** You don't give access to just anyone — there's an approval process.

**What auditors check:**
- Is there a written process for requesting access?
- Who approves new access requests?
- Is it documented?

**Evidence you need:**
- HR/onboarding checklist showing access provisioning steps
- Ticket or email showing approval for at least 2–3 users
- Access Control Policy document

**ComplyKit checks:**
- `aws_iam_unused_credentials` — flags stale accounts (no process = stale accounts)

---

#### CC6.3 — Access removal

**What it means:** When someone leaves, their access is revoked promptly.

**What auditors check:**
- What's your offboarding process?
- How quickly is access revoked after termination?
- Do you do periodic access reviews?

**Evidence you need:**
- Offboarding checklist
- Example of an account being disabled (redacted screenshot)
- Quarterly access review records

**ComplyKit checks:**
- `aws_iam_unused_credentials` — flags credentials unused >90 days

---

#### CC6.6 — External threats

**What it means:** You protect your systems from external attacks.

**What auditors check:**
- Are S3 buckets private?
- Are security group rules restrictive (no 0.0.0.0/0)?
- Do you have WAF or DDoS protection?

**Evidence you need:**
- AWS Config or Security Hub screenshot
- S3 bucket settings showing no public access
- Security group rules showing no unrestricted SSH/RDP

**ComplyKit checks:**
- `aws_s3_public_access_block`
- `aws_sg_open_ssh`
- `aws_sg_open_rdp`
- `github_public_repos`

---

#### CC6.7 — Transmission and storage of data

**What it means:** Data is encrypted in transit and at rest.

**What auditors check:**
- Is data encrypted at rest in S3, RDS, EBS?
- Is all traffic over TLS 1.2+?
- Are encryption keys managed (KMS)?

**Evidence you need:**
- S3 encryption settings screenshot
- RDS encryption enabled screenshot
- Load balancer HTTPS listener configuration

**ComplyKit checks:**
- `aws_s3_encryption`
- (RDS encryption — coming in v0.2)

---

#### CC6.8 — Prevention of malware

**What it means:** You have controls to detect and prevent malicious software.

**What auditors check:**
- Do you use vulnerability scanning?
- Are dependencies kept up to date?
- Do you use GuardDuty or equivalent?

**Evidence you need:**
- GuardDuty enabled screenshot
- Dependabot alerts enabled on GitHub repos
- Dependency update cadence evidence

**ComplyKit checks:**
- `github_dependabot`
- `github_secret_scanning`

---

### CC7 — System Operations

#### CC7.1 — Detection of vulnerabilities

**What it means:** You actively look for security vulnerabilities.

**What auditors check:**
- Do you run vulnerability scans?
- Do you have a process for patching critical CVEs?

**Evidence you need:**
- AWS Inspector or third-party scanner results
- Dependabot or Snyk report showing vulnerabilities addressed
- Patch cadence policy

---

#### CC7.2 — Monitoring for anomalies

**What it means:** You have logging that would detect a breach.

**What auditors check:**
- Is CloudTrail enabled in all regions?
- Are there alerts on suspicious activity?
- Do you review logs regularly?

**Evidence you need:**
- CloudTrail configuration showing multi-region trail
- CloudWatch Alarms or equivalent
- Log retention policy (minimum 1 year)

**ComplyKit checks:**
- `aws_cloudtrail_enabled`
- `aws_cloudtrail_multiregion`

---

#### CC7.3 — Incident evaluation

**What it means:** When something suspicious is detected, you investigate it.

**What auditors check:**
- Do you have an incident response policy?
- Can you show examples of incidents being triaged?

**Evidence you need:**
- Incident Response Policy (generated by `comply policy generate`)
- Example of an alert being triaged (even a false positive)
- On-call runbook

---

### CC8 — Change Management

#### CC8.1 — Change management process

**What it means:** You don't push untested code directly to production.

**What auditors check:**
- Is branch protection enabled on main?
- Are pull request reviews required?
- Are there automated tests?
- Is there a rollback procedure?

**Evidence you need:**
- GitHub branch protection settings screenshot
- Example PR showing peer review
- CI/CD pipeline showing tests pass before deploy

**ComplyKit checks:**
- `github_branch_protection`

---

### CC9 — Risk Mitigation

#### CC9.2 — Vendor risk management

**What it means:** You understand the security posture of your third-party tools.

**What auditors check:**
- Do you have a vendor list?
- Have you reviewed each vendor's security posture?
- Are there DPAs in place with vendors that handle your data?

**Evidence you need:**
- Vendor inventory spreadsheet (20–30 vendors is typical)
- SOC2 reports or security questionnaires from key vendors
- DPAs or security addendums in vendor contracts
- Vendor Management Policy document

---

### SOC2 Evidence Collection Checklist

Use `comply evidence list` to track scan history. For each audit you also need:

**Policies (generated by `comply policy generate`):**
- [ ] Access Control Policy
- [ ] Incident Response Policy
- [ ] Change Management Policy
- [ ] Data Classification Policy
- [ ] Vendor Management Policy

**Screenshots and records:**
- [ ] AWS IAM: MFA enabled on all users
- [ ] AWS IAM: Password policy configured
- [ ] AWS CloudTrail: Multi-region trail enabled
- [ ] AWS S3: Public access block on all buckets
- [ ] AWS S3: Encryption enabled on all buckets
- [ ] GitHub: Branch protection on main
- [ ] GitHub: Dependabot enabled
- [ ] Vendor inventory list
- [ ] Access review records (quarterly)
- [ ] Onboarding/offboarding checklists
- [ ] Background check policy

---

## Part 2 — HIPAA

### What is HIPAA?

HIPAA (Health Insurance Portability and Accountability Act) is a **US federal law**.
If you handle Protected Health Information (PHI) — patient data, medical records,
diagnoses — you are legally required to comply.

PHI includes: names, addresses, birthdates, SSNs, medical record numbers, health
plan numbers, IP addresses when combined with health data, and more.

### Who needs to comply?

- **Covered Entities:** hospitals, health insurers, healthcare providers
- **Business Associates:** any company that receives PHI from a covered entity
  (this includes most health-tech SaaS companies)

If you're a health-tech startup, you almost certainly need a **Business Associate Agreement (BAA)** with your customers and must comply with HIPAA.

---

### HIPAA Security Rule — Technical Safeguards (§164.312)

The Security Rule defines technical controls for PHI. This is what ComplyKit maps to.

#### §164.312(a)(1) — Access Control

**What it means:** Only authorized users can access PHI.

**Required:**
- Unique user identification — no shared accounts
- Emergency access procedure — documented break-glass process
- Automatic logoff — sessions time out

**What auditors check:**
- Are there shared accounts in your systems?
- Is there MFA on all access to PHI systems?
- Do you have a documented emergency access procedure?

**ComplyKit checks:**
- `aws_iam_root_mfa`
- `aws_iam_password_policy`

---

#### §164.312(a)(2)(iv) — Encryption and Decryption

**What it means:** PHI must be encrypted when stored.

**Required (Addressable — meaning you must implement or document why not):**
- Encryption of data at rest
- AES-256 or equivalent

**ComplyKit checks:**
- `aws_s3_encryption`
- `gcp_gcs_uniform_iam`

---

#### §164.312(b) — Audit Controls

**What it means:** You must record and examine activity in systems that contain PHI.

**Required:**
- Hardware/software activity logs
- Log retention (typically 6 years)
- Regular log review

**Evidence you need:**
- CloudTrail logs showing audit trail
- Log retention policy
- Example of a log review or alert investigation

**ComplyKit checks:**
- `aws_cloudtrail_enabled`
- `aws_cloudtrail_multiregion`

---

#### §164.312(c)(1) — Integrity Controls

**What it means:** PHI must not be improperly altered or destroyed.

**Required (Addressable):**
- Mechanisms to authenticate PHI (verify it hasn't been tampered with)
- S3 versioning or similar

---

#### §164.312(d) — Person Authentication

**What it means:** You must verify that the person accessing PHI is who they claim to be.

**Required:**
- Multi-factor authentication for all access to PHI

**ComplyKit checks:**
- `aws_iam_root_mfa`
- `aws_iam_console_mfa`

---

#### §164.312(e)(1) — Transmission Security

**What it means:** PHI must be encrypted in transit.

**Required (Addressable):**
- TLS 1.2+ for all data transmission
- No PHI over unencrypted channels (HTTP, FTP)

**Evidence you need:**
- Load balancer config showing HTTPS only
- SSL certificate configuration
- No HTTP listeners

---

### HIPAA Evidence Checklist

**Policies required (go beyond `comply policy generate` for HIPAA):**
- [ ] HIPAA Privacy Policy
- [ ] HIPAA Security Policy
- [ ] Breach Notification Policy (72-hour notification requirement)
- [ ] Business Associate Agreement template
- [ ] Workforce Training records (annual HIPAA training required)

**Technical evidence:**
- [ ] MFA on all systems containing PHI
- [ ] Encryption at rest (AES-256) for all PHI storage
- [ ] Encryption in transit (TLS 1.2+) verified
- [ ] Audit logs enabled and retained 6 years
- [ ] Access control list for PHI systems
- [ ] Automatic session timeout configured
- [ ] Penetration test results (annual recommended)

**HIPAA-specific requirements NOT covered by ComplyKit (manual):**
- BAAs signed with all business associates
- Workforce training completion records
- Risk assessment (annual, required by law)
- Physical safeguards (office security, device disposal)
- Privacy Rule compliance (patient rights, notice of privacy practices)

---

## Part 3 — CIS AWS Foundations Benchmark

### What is CIS?

The Center for Internet Security (CIS) publishes the AWS Foundations Benchmark —
a set of technical controls for hardening AWS accounts. It's not a certification
you get, but it's commonly used as a baseline security standard and is often
referenced in SOC2 audits.

CIS benchmarks are free to download at cisecurity.org.

---

### Level 1 vs Level 2

| | CIS Level 1 | CIS Level 2 |
|---|---|---|
| Scope | Baseline, minimal performance impact | More restrictive, may affect usability |
| Recommendation | Implement all Level 1 | Implement if security is critical |

---

### CIS Section 1 — IAM

| Check ID | Title | Severity | ComplyKit |
|----------|-------|----------|-----------|
| 1.1 | Avoid use of root account for day-to-day tasks | Critical | Manual |
| 1.2 | MFA enabled for all IAM users with console access | High | `aws_iam_console_mfa` |
| 1.3 | Credentials unused 90+ days disabled | Medium | `aws_iam_unused_credentials` |
| 1.4 | Access keys rotated every 90 days | Medium | v0.2 |
| 1.5 | MFA enabled for root | Critical | `aws_iam_root_mfa` |
| 1.6 | Hardware MFA for root | Medium | v0.2 |
| 1.7 | No root access keys | Critical | v0.2 |
| 1.8 | IAM password policy: min 14 chars | High | `aws_iam_password_policy` |
| 1.9 | Password expiry max 90 days | Medium | `aws_iam_password_policy` |
| 1.10 | Password reuse: prevent last 24 | Low | `aws_iam_password_policy` |
| 1.11 | No more than 1 active access key per user | Medium | v0.2 |
| 1.12 | Credentials unused 90+ days removed | Medium | `aws_iam_unused_credentials` |
| 1.14 | Hardware MFA for root | Medium | v0.2 |

---

### CIS Section 2 — Storage

| Check ID | Title | Severity | ComplyKit |
|----------|-------|----------|-----------|
| 2.1.1 | S3 encryption at rest | High | `aws_s3_encryption` |
| 2.1.2 | S3 public access block | Critical | `aws_s3_public_access_block` |
| 2.2 | EBS encryption enabled by default | High | v0.2 |
| 2.3 | RDS encryption at rest | High | v0.2 |

---

### CIS Section 3 — Logging

| Check ID | Title | Severity | ComplyKit |
|----------|-------|----------|-----------|
| 3.1 | CloudTrail enabled in all regions | Critical | `aws_cloudtrail_enabled` |
| 3.2 | CloudTrail log file validation enabled | Medium | v0.2 |
| 3.3 | CloudTrail S3 bucket not publicly accessible | High | v0.2 |
| 3.4 | CloudTrail log integration with CloudWatch Logs | Medium | v0.2 |
| 3.5 | AWS Config enabled in all regions | Medium | v0.2 |
| 3.6 | S3 bucket access logging enabled | Low | v0.2 |
| 3.9 | VPC flow logging enabled | Medium | v0.2 |
| 3.10 | Object-level logging for read events on S3 | Low | v0.2 |
| 3.11 | Object-level logging for write events on S3 | Low | v0.2 |

---

### CIS Section 4 — Networking

| Check ID | Title | Severity | ComplyKit |
|----------|-------|----------|-----------|
| 4.1 | No security group allows 0.0.0.0/0 on port 22 | Critical | `aws_sg_open_ssh` |
| 4.2 | No security group allows 0.0.0.0/0 on port 3389 | Critical | `aws_sg_open_rdp` |
| 4.3 | Default security group restricts all traffic | High | v0.2 |
| 4.4 | VPC peering does not allow unrestricted routing | Medium | v0.2 |

---

## Part 4 — Comparison: What Each Framework Requires

| Requirement | SOC2 | HIPAA | CIS |
|-------------|------|-------|-----|
| MFA on all users | CC6.1 ✓ | §164.312(d) ✓ | 1.2 ✓ |
| Encrypted data at rest | CC6.7 ✓ | §164.312(a)(2)(iv) ✓ | 2.1 ✓ |
| Encrypted data in transit | CC6.7 | §164.312(e)(1) | — |
| Audit logging | CC7.2 ✓ | §164.312(b) ✓ | 3.1 ✓ |
| Access reviews (quarterly) | CC6.3 | §164.312(a)(1) | — |
| Incident response plan | CC7.3 | §164.308(a)(6) | — |
| Vulnerability management | CC7.1 | §164.308(a)(8) | — |
| Change management | CC8.1 | — | — |
| Vendor management | CC9.2 | BAA requirement | — |
| Physical security | Optional | §164.310 | — |
| Annual risk assessment | Implied | Required by law | — |
| Workforce training | Implied | Required by law | — |

---

## Part 5 — Getting Audit-Ready: Timeline

### Month 1 — Foundation

- [ ] Run `comply init` + `comply scan` — get your baseline score
- [ ] Fix all **critical** findings first
- [ ] Generate policy docs: `comply policy generate`
- [ ] Tailor each policy to your actual processes (30 min each)
- [ ] Start `comply watch` to catch regressions

### Month 2 — Evidence collection

- [ ] Fix all **high** severity findings
- [ ] Set up quarterly access reviews (recurring calendar invite)
- [ ] Run background checks on employees with production access
- [ ] Build vendor inventory (list every SaaS tool you use)
- [ ] Collect BAAs from any vendors handling sensitive data
- [ ] Enable GuardDuty + Security Hub in AWS

### Month 3 — Audit preparation

- [ ] Engage an audit firm (budget $15–25k for Type 1)
- [ ] Run `comply scan --pdf report.pdf` and share with auditor
- [ ] Use `comply share --label "Pre-audit scan"` for auditor access
- [ ] Address any gaps the auditor surfaces in their pre-audit review
- [ ] Fix remaining **medium** findings

### Month 4 — Audit

- [ ] Auditor interviews (typically 2–4 hours total)
- [ ] Provide evidence from `comply evidence list`
- [ ] Receive draft report → review → final report
- [ ] SOC2 Type 1 certificate issued

### Months 6–12 — Type 2 observation period

- [ ] Keep `comply watch` running — catch regressions immediately
- [ ] Document any security incidents (even minor ones)
- [ ] Run quarterly access reviews (with records)
- [ ] Conduct annual penetration test
- [ ] Renew audit for Type 2

---

## Part 6 — Audit Firm Selection

### Budget

| Firm type | Cost range | Best for |
|-----------|-----------|---------|
| Big 4 (Deloitte, PwC, etc.) | $50–100k | Enterprise customers, financial sector |
| Mid-tier (Schellman, Coalfire) | $25–50k | Series B+, regulated industries |
| Boutique / startup-focused | $12–25k | Seed to Series A |

### Startup-friendly audit firms

- **Prescient Assurance** — focused on tech startups, faster timelines
- **Johanson Group** — competitive pricing, startup experience
- **A-LIGN** — scalable, good tooling integration
- **Secureframe / Drata / Vanta** — also offer audit firm partnerships

### What to ask before hiring

1. What is your average time-to-report for Type 1?
2. Do you accept ComplyKit scan reports as evidence?
3. What evidence format do you prefer (PDF, JSON, screenshots)?
4. What is your process if we need to remediate during the audit window?
5. Can we get a fixed-price quote?
