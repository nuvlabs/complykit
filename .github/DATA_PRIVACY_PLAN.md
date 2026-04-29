# Data Privacy & Database Security — Implementation Plan

Covers every compliance framework ComplyKit supports.  
Organized **framework → requirement → check**, then broken into implementable phases.

All three database hosting types are covered in every phase:
- **Managed** — RDS, Cloud SQL, Azure SQL
- **Container** — Kubernetes / ECS
- **Self-hosted** — EC2/Linux, on-premises

---

## Framework Requirements Map

### PCI DSS v4.0

| Requirement | Description | Checks |
|---|---|---|
| Req 3.3 / 3.4 | Stored cardholder data encrypted; PAN unreadable | `aws_rds_encryption` (exists), `k8s_db_pvc_encrypted`, `aws_ec2_db_ebs_encrypted`, `tf_db_storage_encrypted`, `db_pii_column_detection`, `db_pii_data_sampling` |
| Req 4.2.1 | Strong cryptography in transit | `aws_rds_ssl_enforcement`, `k8s_db_tls_enabled`, `db_tls_connection_test` |
| Req 7.2.1 | Least-privilege access to cardholder data | `aws_rds_overprivileged_iam`, `aws_rds_no_public_access`, `k8s_db_network_policy`, `aws_ec2_db_sg_exposure` |
| Req 8.2 / 8.3 | Unique IDs, no shared credentials, rotation | `aws_rds_iam_auth`, `aws_secrets_manager_rotation`, `db_default_accounts`, `github_db_credentials` |
| Req 10.2.1 | Audit log all access to cardholder data | `aws_rds_audit_logging`, `aws_cloudtrail_rds_events`, `k8s_db_audit_logging`, `aws_ec2_db_cloudwatch_logs` |

---

### HIPAA Security Rule

| Requirement | Description | Checks |
|---|---|---|
| §164.312(a)(1) | Access control — unique user IDs, auto logoff | `aws_rds_iam_auth`, `db_default_accounts`, `db_unused_accounts` |
| §164.312(a)(2)(iv) | Encryption and decryption of PHI | `aws_rds_encryption` (exists), `k8s_db_pvc_encrypted`, `aws_ec2_db_ebs_encrypted`, `db_pii_column_detection` |
| §164.312(b) | Audit controls — log access to PHI systems | `aws_rds_audit_logging`, `aws_cloudtrail_rds_events`, `aws_ec2_db_cloudwatch_logs` |
| §164.312(c)(1) | Integrity — protect PHI from improper alteration | `aws_rds_deletion_protection`, `aws_rds_automated_backups` |
| §164.312(e)(1) | Transmission security — encrypt PHI in transit | `aws_rds_ssl_enforcement`, `k8s_db_tls_enabled`, `db_tls_connection_test` |

---

### SOC 2 Type II

| Control | Description | Checks |
|---|---|---|
| CC6.1 | Logical access — network-level isolation | `aws_rds_no_public_access`, `aws_ec2_db_no_public_ip`, `k8s_db_no_public_service`, `aws_ec2_db_sg_exposure` |
| CC6.3 | Role-based access — least privilege | `aws_rds_overprivileged_iam`, `db_unused_accounts`, `k8s_db_network_policy` |
| CC6.7 | Encryption at rest and in transit | All encryption + SSL checks |
| CC7.2 | Monitoring — detect anomalies | `aws_rds_audit_logging`, `aws_cloudtrail_rds_events`, `k8s_db_audit_logging` |
| CC9.1 | Risk mitigation — backups, resilience | `aws_rds_automated_backups`, `aws_rds_deletion_protection`, `aws_rds_multi_az` |

---

### ISO 27001:2022

| Control | Description | Checks |
|---|---|---|
| A.8.24 | Use of cryptography | All encryption at rest and in-transit checks |
| A.9.2.3 | Privileged access rights management | `aws_rds_overprivileged_iam`, `db_default_accounts`, `aws_rds_no_master_user_exposed` |
| A.9.4.1 | Information access restriction | `k8s_db_network_policy`, `aws_ec2_db_sg_exposure`, `aws_rds_no_public_access` |
| A.9.4.3 | Password management system | `aws_secrets_manager_rotation`, `github_db_credentials` |
| A.12.4.1 | Event logging | `aws_rds_audit_logging`, `aws_cloudtrail_rds_events`, `aws_ec2_db_cloudwatch_logs` |

---

### CIS AWS Foundations v1.4

| Benchmark | Description | Checks |
|---|---|---|
| 2.3.1 | RDS encryption at rest | `aws_rds_encryption` (exists) |
| 2.3.2 | RDS auto minor version upgrade | `aws_rds_auto_minor_upgrade` |
| 2.3.3 | RDS instances not publicly accessible | `aws_rds_no_public_access` |

---

## Complete Check Inventory

### Encryption at Rest

| Check ID | Hosting | API / Method | Frameworks |
|---|---|---|---|
| `aws_rds_encryption` | Managed | `DescribeDBInstances.StorageEncrypted` | SOC2 CC6.7, HIPAA 164.312(a)(2)(iv), PCI 3.4, ISO A.8.24, CIS 2.3.1 |
| `k8s_db_pvc_encrypted` | Container | K8s API: StorageClass `encrypted=true` on DB PVCs | SOC2 CC6.7, HIPAA 164.312(a)(2)(iv), PCI 3.4, ISO A.8.24 |
| `aws_ec2_db_ebs_encrypted` | EC2/Linux | EC2 API: EBS volumes on DB-tagged instances | SOC2 CC6.7, HIPAA 164.312(a)(2)(iv), PCI 3.4, ISO A.8.24 |
| `tf_db_storage_encrypted` | IaC | Terraform: `storage_encrypted = false` in `aws_db_instance` / `aws_rds_cluster` | SOC2 CC6.7, PCI 3.4, ISO A.8.24 |
| `k8s_etcd_encryption` | Container | K8s API: etcd EncryptionConfig present | SOC2 CC6.7, PCI 3.4, ISO A.8.24 |

### Encryption in Transit

| Check ID | Hosting | API / Method | Frameworks |
|---|---|---|---|
| `aws_rds_ssl_enforcement` | Managed | `DescribeDBParameterGroups`: `rds.force_ssl=1` (PG) / `require_secure_transport=ON` (MySQL) | SOC2 CC6.7, HIPAA 164.312(e), PCI 4.2.1, ISO A.8.24 |
| `k8s_db_tls_enabled` | Container | K8s: DB pod env vars / config for TLS cert paths present | SOC2 CC6.7, HIPAA 164.312(e), PCI 4.2.1 |
| `tf_db_ssl_mode` | IaC | Terraform: `parameter_group` missing `rds.force_ssl` | SOC2 CC6.7, PCI 4.2.1 |
| `db_tls_connection_test` | All | `comply db scan`: attempt cleartext connection — must be rejected | PCI 4.2.1, HIPAA 164.312(e) |

### Network Isolation

| Check ID | Hosting | API / Method | Frameworks |
|---|---|---|---|
| `aws_rds_no_public_access` | Managed | `DescribeDBInstances.PubliclyAccessible = false` | SOC2 CC6.1, PCI 7.2.1, ISO A.9.4.1, CIS 2.3.3 |
| `aws_ec2_db_no_public_ip` | EC2/Linux | EC2 API: DB-tagged instances have no public IP | SOC2 CC6.1, PCI 7.2.1, ISO A.9.4.1 |
| `aws_ec2_db_sg_exposure` | EC2/Linux | EC2 API: SG on DB instances allows port 5432/3306/1433/27017 from `0.0.0.0/0` | SOC2 CC6.1, PCI 1.3, ISO A.9.4.1 |
| `k8s_db_no_public_service` | Container | K8s API: Service type for DB pods is not `LoadBalancer` / `NodePort` | SOC2 CC6.1, PCI 7.2.1 |
| `k8s_db_network_policy` | Container | K8s API: NetworkPolicy exists restricting ingress to DB pods | SOC2 CC6.3, PCI 7.2.1, HIPAA 164.312(a)(1), ISO A.9.4.1 |
| `tf_db_public_access` | IaC | Terraform: `publicly_accessible = true` | SOC2 CC6.1, PCI 1.3 |

### Access Control & Identity

| Check ID | Hosting | API / Method | Frameworks |
|---|---|---|---|
| `aws_rds_iam_auth` | Managed | `DescribeDBInstances.IAMDatabaseAuthenticationEnabled` | SOC2 CC6.1, HIPAA 164.312(a)(1), PCI 8.2, ISO A.9.2.3 |
| `aws_rds_overprivileged_iam` | Managed | IAM: roles/users with `rds:*` or `rds:Connect` on `*` | SOC2 CC6.3, PCI 7.2.1, ISO A.9.2.3 |
| `aws_rds_no_master_user_exposed` | Managed | `DescribeDBInstances`: master username is not `admin`, `root`, `sa` | PCI 8.2, ISO A.9.2.3 |
| `k8s_db_not_root` | Container | K8s API: DB container `securityContext.runAsUser != 0` | SOC2 CC6.1, PCI 7.2.1 |
| `k8s_db_secret_not_configmap` | Container | K8s API: no ConfigMap containing DB connection string keywords | SOC2 CC6.1, PCI 8.3, ISO A.9.4.3 |
| `db_default_accounts` | All | `comply db scan`: default DB users (`postgres`, `root`, `sa`, `mysql`) active | PCI 8.2.1, HIPAA 164.312(a)(1), ISO A.9.2.3 |
| `db_unused_accounts` | All | `comply db scan`: DB users with no login in 90+ days | SOC2 CC6.3, PCI 8.2.6, ISO A.9.2.5 |

### Secrets & Credential Hygiene

| Check ID | Hosting | API / Method | Frameworks |
|---|---|---|---|
| `aws_secrets_manager_rotation` | Managed / EC2 | Secrets Manager API: DB secrets have automatic rotation enabled | SOC2 CC6.1, PCI 8.3.9, ISO A.9.4.3 |
| `github_db_credentials` | All | GitHub: scan repo for DB connection strings / passwords in code or `.env` files | SOC2 CC6.1, PCI 8.3, ISO A.9.4.3 |
| `tf_db_hardcoded_password` | IaC | Terraform: `password =` literal string in `aws_db_instance` | SOC2 CC6.1, PCI 8.3, ISO A.9.4.3 |

### Audit Logging

| Check ID | Hosting | API / Method | Frameworks |
|---|---|---|---|
| `aws_rds_audit_logging` | Managed | `DescribeDBInstances`: CloudWatch Logs exports include `audit`, `error`, `general` | SOC2 CC7.2, HIPAA 164.312(b), PCI 10.2.1, ISO A.12.4.1 |
| `aws_cloudtrail_rds_events` | Managed | CloudTrail: data events for RDS enabled | SOC2 CC7.2, HIPAA 164.312(b), PCI 10.2, ISO A.12.4.1 |
| `k8s_db_audit_logging` | Container | K8s API: audit policy captures `RequestResponse` for DB namespaces | SOC2 CC7.2, PCI 10.2, ISO A.12.4.1 |
| `aws_ec2_db_cloudwatch_logs` | EC2/Linux | CloudWatch: log groups exist for DB instance (by tag/name match) | SOC2 CC7.2, HIPAA 164.312(b), PCI 10.2, ISO A.12.4.1 |

### Resilience & Backup

| Check ID | Hosting | API / Method | Frameworks |
|---|---|---|---|
| `aws_rds_automated_backups` | Managed | `DescribeDBInstances.BackupRetentionPeriod >= 7` | SOC2 CC9.1, HIPAA 164.310(d), ISO A.12.3.1 |
| `aws_rds_deletion_protection` | Managed | `DescribeDBInstances.DeletionProtection = true` | SOC2 CC9.1, ISO A.12.3.1 |
| `aws_rds_multi_az` | Managed | `DescribeDBInstances.MultiAZ = true` | SOC2 A1.2 |
| `aws_rds_auto_minor_upgrade` | Managed | `DescribeDBInstances.AutoMinorVersionUpgrade = true` | CIS 2.3.2 |

### Data Discovery (`comply db scan`)

| Check ID | What It Scans | Frameworks |
|---|---|---|
| `db_pii_column_detection` | Schema: column names matching `ssn`, `social_security`, `tax_id`, `dob`, `passport`, `credit_card`, `card_number`, `cvv`, `pan` | PCI 3.3, HIPAA 164.312(a)(2)(iv) |
| `db_pii_data_sampling` | Sample up to 1,000 rows: regex for SSN `\d{3}-\d{2}-\d{4}`, CC Luhn check, email `@`, phone patterns | PCI 3.4, HIPAA 164.312(a)(2)(iv) |
| `db_tls_connection_test` | Attempt cleartext TCP connection — compliant DB must reject it | PCI 4.2.1, HIPAA 164.312(e) |
| `db_rls_on_pii_tables` | PII-flagged tables: PostgreSQL row-level security (RLS) enabled | SOC2 CC6.3, PCI 7.2 |
| `db_schema_audit_table` | Audit/event log table exists for PII tables (INSERT/UPDATE/DELETE triggers or log table) | PCI 10.2, SOC2 CC7.2 |

### Cloud-native PII Detection

| Check ID | Cloud | Frameworks |
|---|---|---|
| `aws_macie_enabled` | AWS Macie enabled and active | PCI 3, HIPAA 164.312(a)(2)(iv), ISO A.8.24 |
| `aws_macie_findings` | Active Macie HIGH/CRITICAL findings for SSN/CC/PHI in S3 | PCI 3, HIPAA |
| `gcp_dlp_job_active` | GCP DLP inspection job scanning Cloud Storage | PCI 3, HIPAA |

---

## Phases

### Phase 1 — Encryption at Rest + in Transit
**~1–2 days · no new credentials required**

New/extended files:
- `internal/checks/aws/rds.go` — add `ssl_enforcement`, `no_public_access`, `deletion_protection`, `automated_backups`, `iam_auth`, `multi_az`, `auto_minor_upgrade`
- `internal/checks/aws/ec2db.go` — new file: `ebs_encrypted`, `no_public_ip`, `sg_exposure`
- `internal/checks/kubernetes/dbsecurity.go` — new file: `pvc_encrypted`, `etcd_encryption`, `tls_enabled`, `no_public_service`
- `internal/checks/terraform/terraform.go` — add `db_storage_encrypted`, `db_public_access`, `db_ssl_mode`
- `internal/engine/controls.go` — ControlMap entries for all new IDs
- `internal/engine/registry.go` — Registry entries for all new IDs
- `cmd/scan.go` — wire `EC2DBChecker`, `K8sDBSecurityChecker`

Frameworks fully addressed: **PCI Req 3.4, 4.2.1 · HIPAA 164.312(a)(2)(iv), 164.312(e) · SOC2 CC6.7 · ISO A.8.24 · CIS 2.3.x**

---

### Phase 2 — Access Control + Network Isolation
**~1–2 days · extends existing AWS IAM + K8s API**

New/extended files:
- `internal/checks/aws/rds.go` — add `overprivileged_iam`, `no_master_user_exposed`
- `internal/checks/aws/ec2db.go` — add `sg_exposure` (may overlap Phase 1, refine here)
- `internal/checks/kubernetes/dbsecurity.go` — add `not_root`, `network_policy`, `secret_not_configmap`
- `internal/checks/aws/dbaccess.go` — new file: IAM access review for RDS

Frameworks fully addressed: **PCI Req 1, 7, 8.2 · HIPAA 164.312(a)(1) · SOC2 CC6.1, CC6.3 · ISO A.9.2.3, A.9.4.1**

---

### Phase 3 — Secrets & Credential Hygiene
**~1 day · extends GitHub + Secrets Manager checks**

New/extended files:
- `internal/checks/github/secrets.go` — new file: scan for DB connection strings
- `internal/checks/aws/rds.go` — add `secrets_manager_rotation`
- `internal/checks/terraform/terraform.go` — add `db_hardcoded_password`

Frameworks fully addressed: **PCI Req 8.3 · SOC2 CC6.1 · ISO A.9.4.3**

---

### Phase 4 — Audit Logging
**~1–2 days · CloudTrail + RDS + K8s audit APIs**

New/extended files:
- `internal/checks/aws/rds.go` — add `audit_logging`
- `internal/checks/aws/cloudtrail.go` — add `rds_data_events`
- `internal/checks/aws/ec2db.go` — add `cloudwatch_logs`
- `internal/checks/kubernetes/dbsecurity.go` — add `audit_logging`

Frameworks fully addressed: **PCI Req 10 · HIPAA 164.312(b) · SOC2 CC7.2 · ISO A.12.4.1**

---

### Phase 5 — `comply db scan` (Data Discovery)
**~3–4 days · new command + new package + DSN-based connection**

Works for **all hosting types** — pass any Postgres / MySQL DSN:

```bash
comply db scan --dsn "postgres://readonly:pass@host:5432/mydb" --framework pci
comply db scan --dsn "mysql://readonly:pass@host:3306/mydb" --framework hipaa
```

New files:
- `cmd/dbscan.go` — new command wired into root
- `internal/checks/database/scanner.go` — DSN connect, schema fetch, row sampling
- `internal/checks/database/pii.go` — PII column name patterns + regex engine
- `internal/checks/database/accounts.go` — default/unused account checks
- `internal/checks/database/tls.go` — cleartext connection test

Frameworks fully addressed: **PCI Req 3.3, 3.4, 4.2.1, 8.2.1 · HIPAA 164.312(a)(2)(iv) · SOC2 CC6.3**

---

### Phase 6 — Cloud-native PII Detection (Macie + GCP DLP)
**~2 days · AWS + GCP native scanner APIs**

New files:
- `internal/checks/aws/macie.go` — Macie enabled + active findings
- `internal/checks/gcp/dlp.go` — DLP inspection job status

Frameworks fully addressed: **PCI Req 3 · HIPAA 164.312(a)(2)(iv) · ISO A.8.24**

---

## Configuration

Users declare database hosting type in `complykit.yaml`:

```yaml
databases:
  - type: rds          # AWS managed — uses RDS + IAM APIs
  - type: kubernetes   # container — uses K8s API
    namespace: data
  - type: ec2          # self-hosted on EC2 — uses EC2 + CloudWatch APIs
    tag: Role=database
  - type: onprem       # on-premises — only comply db scan can reach
    dsn: "${DB_DSN}"
```

If not declared, ComplyKit auto-detects:
- Finds RDS instances via `DescribeDBInstances` → runs Managed checks
- Finds K8s pods whose image matches `postgres|mysql|mongo|redis` → runs Container checks
- Finds EC2 instances tagged `Role=database` or `db` in name → runs EC2 checks

---

## Summary

| Phase | Checks Added | Days | Hosting Coverage |
|---|---|---|---|
| 1 — Encryption | 13 | 1–2 | Managed + Container + EC2 + IaC |
| 2 — Access Control | 8 | 1–2 | Managed + Container + EC2 |
| 3 — Secrets | 3 | 1 | All |
| 4 — Audit Logging | 4 | 1–2 | Managed + Container + EC2 |
| 5 — DB Scan | 5 | 3–4 | All (DSN-based, including on-prem) |
| 6 — Cloud PII | 3 | 2 | AWS + GCP |
| **Total** | **36** | **9–13** | |
