package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"
)

var funcMap = template.FuncMap{
	"lower": strings.ToLower,
	"upper": strings.ToUpper,
}

type PolicyData struct {
	CompanyName   string
	Framework     string
	Date          string
	Year          string
	ReviewCycle   string
	OwnerName     string
	OwnerTitle    string
}

type PolicyTemplate struct {
	ID          string
	Title       string
	Filename    string
	Controls    []string
	Description string
	Body        string
}

func Generate(outDir, companyName, ownerName, ownerTitle, framework string) ([]string, error) {
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return nil, fmt.Errorf("cannot create output dir: %w", err)
	}

	data := PolicyData{
		CompanyName: companyName,
		Framework:   strings.ToUpper(framework),
		Date:        time.Now().Format("January 2, 2006"),
		Year:        time.Now().Format("2006"),
		ReviewCycle: "Annual",
		OwnerName:   ownerName,
		OwnerTitle:  ownerTitle,
	}

	var written []string
	for _, tmpl := range All() {
		path := filepath.Join(outDir, tmpl.Filename)
		if err := writePolicy(tmpl, data, path); err != nil {
			return written, fmt.Errorf("failed to write %s: %w", tmpl.Title, err)
		}
		written = append(written, path)
	}
	return written, nil
}

func writePolicy(tmpl PolicyTemplate, data PolicyData, path string) error {
	t, err := template.New(tmpl.ID).Funcs(funcMap).Parse(tmpl.Body)
	if err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return t.Execute(f, data)
}

func All() []PolicyTemplate {
	return []PolicyTemplate{
		accessControlPolicy(),
		incidentResponsePolicy(),
		changeManagementPolicy(),
		dataClassificationPolicy(),
		vendorManagementPolicy(),
	}
}

func accessControlPolicy() PolicyTemplate {
	return PolicyTemplate{
		ID: "access_control", Title: "Access Control Policy",
		Filename: "access-control-policy.md",
		Controls: []string{"CC6.1", "CC6.2", "CC6.3"},
		Body: `# Access Control Policy

**Company:** {{.CompanyName}}
**Effective Date:** {{.Date}}
**Review Cycle:** {{.ReviewCycle}}
**Owner:** {{.OwnerName}}, {{.OwnerTitle}}
**Framework:** {{.Framework}}

---

## 1. Purpose

This policy establishes requirements for controlling access to {{.CompanyName}}'s
systems, data, and infrastructure to prevent unauthorized access.

## 2. Scope

This policy applies to all employees, contractors, and third-party vendors who
access {{.CompanyName}} systems or data.

## 3. Access Provisioning

### 3.1 Principle of Least Privilege
All users are granted the minimum level of access required to perform their job
functions. Access requests must be approved by the data owner or their delegate.

### 3.2 User Account Creation
- All user accounts must be uniquely identified and tied to a named individual.
- Shared or generic accounts are prohibited except for service accounts.
- Account creation requires written approval from the user's manager.

### 3.3 Multi-Factor Authentication
- MFA is required for all accounts with access to production systems.
- MFA is required for all cloud console access (AWS, GCP, Azure).
- Acceptable MFA methods: TOTP authenticator app or hardware security key.

## 4. Access Reviews

### 4.1 Quarterly Reviews
Access rights for all users are reviewed quarterly by data owners and managers.
Users who no longer require access must be de-provisioned within 5 business days.

### 4.2 Termination
Upon employee termination, all access is revoked within 24 hours of the
termination date. HR is responsible for notifying IT/Security immediately.

## 5. Password Requirements

- Minimum 14 characters
- Must include uppercase, lowercase, numbers, and symbols
- Must not reuse the last 10 passwords
- Must be changed every 90 days for privileged accounts

## 6. Remote Access

All remote access to internal systems must use an approved VPN. Direct SSH
access to production systems is prohibited; all access must route through
a bastion host or session manager with full audit logging.

## 7. Audit Logging

All access events to production systems are logged and retained for a minimum
of 12 months. Logs are reviewed for anomalies on a weekly basis.

## 8. Violations

Violations of this policy may result in disciplinary action up to and including
termination. Suspected violations should be reported to security@{{.CompanyName | lower}}.com.

---

*Last reviewed: {{.Date}} by {{.OwnerName}}*
`,
	}
}

func incidentResponsePolicy() PolicyTemplate {
	return PolicyTemplate{
		ID: "incident_response", Title: "Incident Response Policy",
		Filename: "incident-response-policy.md",
		Controls: []string{"CC7.3", "CC7.4", "CC7.5"},
		Body: `# Incident Response Policy

**Company:** {{.CompanyName}}
**Effective Date:** {{.Date}}
**Review Cycle:** {{.ReviewCycle}}
**Owner:** {{.OwnerName}}, {{.OwnerTitle}}
**Framework:** {{.Framework}}

---

## 1. Purpose

This policy defines {{.CompanyName}}'s process for identifying, managing, and
recovering from security incidents to minimize impact on operations and data.

## 2. Incident Classification

| Severity | Description | Response SLA |
|----------|-------------|--------------|
| P0 — Critical | Active breach, data exfiltration, full outage | 15 minutes |
| P1 — High | Suspected breach, partial outage, ransomware | 1 hour |
| P2 — Medium | Vulnerability exploited, degraded service | 4 hours |
| P3 — Low | Suspicious activity, minor policy violation | 24 hours |

## 3. Incident Response Phases

### Phase 1 — Detection & Reporting
Security incidents may be identified via:
- Automated alerts (CloudTrail, GuardDuty, SIEM)
- Employee reports to security@{{.CompanyName | lower}}.com
- Customer reports
- Third-party notification

All suspected incidents must be reported immediately to the Security Lead.

### Phase 2 — Containment
The on-call responder must:
1. Confirm the incident is real (not a false positive)
2. Isolate affected systems to prevent further damage
3. Preserve evidence (do not delete logs)
4. Notify the incident response team

### Phase 3 — Eradication
1. Identify the root cause
2. Remove malware, revoke compromised credentials
3. Patch or remediate the exploited vulnerability

### Phase 4 — Recovery
1. Restore systems from known-good backups
2. Verify system integrity before bringing back online
3. Monitor closely for 48 hours post-recovery

### Phase 5 — Post-Incident Review
A post-mortem must be completed within 5 business days including:
- Timeline of events
- Root cause analysis
- Lessons learned
- Action items with owners and due dates

## 4. Data Breach Notification

If a breach involves personal data, {{.CompanyName}} will:
- Notify affected customers within 72 hours of discovery
- File regulatory notifications as required (GDPR, CCPA, HIPAA)
- Provide breach notification to authorities if required

## 5. Contacts

| Role | Responsibility |
|------|---------------|
| Security Lead | Incident commander |
| Engineering Lead | Technical response |
| Legal Counsel | Regulatory notifications |
| CEO/Exec | Customer/press communications |

---

*Last reviewed: {{.Date}} by {{.OwnerName}}*
`,
	}
}

func changeManagementPolicy() PolicyTemplate {
	return PolicyTemplate{
		ID: "change_management", Title: "Change Management Policy",
		Filename: "change-management-policy.md",
		Controls: []string{"CC8.1"},
		Body: `# Change Management Policy

**Company:** {{.CompanyName}}
**Effective Date:** {{.Date}}
**Review Cycle:** {{.ReviewCycle}}
**Owner:** {{.OwnerName}}, {{.OwnerTitle}}
**Framework:** {{.Framework}}

---

## 1. Purpose

This policy ensures that all changes to {{.CompanyName}}'s production systems
are made in a controlled, tested, and approved manner.

## 2. Scope

Applies to all changes to production infrastructure, applications, databases,
and configuration managed by {{.CompanyName}} engineering.

## 3. Change Categories

| Category | Definition | Approval Required |
|----------|------------|-------------------|
| Standard | Pre-approved, low-risk, routine | None (follow runbook) |
| Normal | Planned change with review | Peer + Tech Lead |
| Emergency | Critical fix for active incident | Post-hoc review within 24h |

## 4. Change Process

### 4.1 Normal Changes
1. Create a pull request with description of change and rollback plan
2. At least 1 peer review approval required
3. All automated tests must pass (CI/CD green)
4. Deploy to staging environment first
5. Tech Lead approval before production deployment
6. Document in change log

### 4.2 Emergency Changes
Emergency changes may bypass standard review but must:
- Have at least one other engineer aware and monitoring
- Be documented immediately after deployment
- Undergo full post-hoc review within 24 hours

## 5. Prohibited Actions

- Direct commits to the main/production branch
- Deployment without passing automated tests
- Schema migrations without rollback scripts
- Disabling security controls without written approval

## 6. Rollback

Every change must have a documented rollback procedure. Engineers must be
prepared to rollback within 30 minutes of a failed deployment.

---

*Last reviewed: {{.Date}} by {{.OwnerName}}*
`,
	}
}

func dataClassificationPolicy() PolicyTemplate {
	return PolicyTemplate{
		ID: "data_classification", Title: "Data Classification Policy",
		Filename: "data-classification-policy.md",
		Controls: []string{"CC6.5", "CC6.7"},
		Body: `# Data Classification Policy

**Company:** {{.CompanyName}}
**Effective Date:** {{.Date}}
**Review Cycle:** {{.ReviewCycle}}
**Owner:** {{.OwnerName}}, {{.OwnerTitle}}
**Framework:** {{.Framework}}

---

## 1. Purpose

This policy defines how {{.CompanyName}} classifies and handles data to ensure
appropriate protection throughout its lifecycle.

## 2. Data Classification Levels

### Level 1 — Public
Data intentionally made available to the public.
- Marketing materials, public documentation, open source code
- No special handling required

### Level 2 — Internal
Data for internal use only, not for external distribution.
- Internal processes, non-sensitive business data
- Must not be shared externally without approval

### Level 3 — Confidential
Sensitive business data that would cause harm if disclosed.
- Customer lists, financials, employee data, source code
- Encrypted at rest and in transit
- Access restricted to need-to-know

### Level 4 — Restricted
Highly sensitive data subject to regulatory requirements.
- PII, PHI, payment card data, credentials, encryption keys
- Encrypted at rest (AES-256) and in transit (TLS 1.2+)
- Access logged and audited
- Must not be stored in logs, source code, or unencrypted storage

## 3. Data Handling Requirements

| Level | Encryption at Rest | Encryption in Transit | Access Logging | Retention |
|-------|-------------------|----------------------|----------------|-----------|
| Public | Optional | Optional | No | No limit |
| Internal | Recommended | Required | No | 3 years |
| Confidential | Required | Required | Yes | 7 years |
| Restricted | Required (AES-256) | Required (TLS 1.2+) | Yes | Per regulation |

## 4. Data Disposal

All data must be disposed of securely when no longer needed:
- Digital: cryptographic erasure or secure wipe (DoD 5220.22-M)
- Physical media: shredding by certified vendor

---

*Last reviewed: {{.Date}} by {{.OwnerName}}*
`,
	}
}

func vendorManagementPolicy() PolicyTemplate {
	return PolicyTemplate{
		ID: "vendor_management", Title: "Vendor Management Policy",
		Filename: "vendor-management-policy.md",
		Controls: []string{"CC9.2"},
		Body: `# Vendor Management Policy

**Company:** {{.CompanyName}}
**Effective Date:** {{.Date}}
**Review Cycle:** {{.ReviewCycle}}
**Owner:** {{.OwnerName}}, {{.OwnerTitle}}
**Framework:** {{.Framework}}

---

## 1. Purpose

This policy establishes requirements for managing third-party vendors and
service providers that have access to {{.CompanyName}} systems or data.

## 2. Vendor Risk Assessment

Before onboarding a vendor, the following must be assessed:
- Type of data the vendor will access (see Data Classification Policy)
- Vendor's security posture (SOC2 report, ISO 27001, security questionnaire)
- Data processing and subprocessor arrangements
- Business continuity and disaster recovery capabilities

## 3. Risk Tiers

| Tier | Criteria | Review Frequency |
|------|----------|-----------------|
| High | Access to Restricted/Confidential data | Annual + on change |
| Medium | Access to Internal data | Annual |
| Low | No data access | On contract change |

## 4. Contractual Requirements

All vendors handling {{.CompanyName}} data must sign:
- Data Processing Agreement (DPA)
- Confidentiality / NDA
- Security addendum for Tier 1 vendors

## 5. Ongoing Monitoring

- Annual review of all active vendors
- Immediate review triggered by: vendor breach notification, change in scope,
  change in ownership, or failed security assessment
- Vendors must notify {{.CompanyName}} within 72 hours of any security incident
  that may affect our data

## 6. Offboarding

Upon contract termination:
1. Revoke all access within 24 hours
2. Confirm data deletion within 30 days
3. Obtain written confirmation of data destruction

---

*Last reviewed: {{.Date}} by {{.OwnerName}}*
`,
	}
}
