# ComplyKit — Coverage Plan

Frameworks tracked: **SOC2** (Trust Services Criteria) · **HIPAA** (Security Rule) · **CIS** (Benchmarks)

Legend: ✅ implemented · 🔲 todo

---

## 1. AWS

### 1.1 Identity & Access Management

| Check | ID | SOC2 | HIPAA | CIS | Status |
|---|---|---|---|---|---|
| Root account MFA enabled | `aws_iam_root_mfa` | CC6.1 | 164.312(d) | 1.5 | ✅ |
| No root access keys | `aws_iam_root_access_keys` | CC6.1 | — | 1.4 | ✅ |
| IAM password policy strength | `aws_iam_password_policy` | CC6.1 | 164.308(a)(5)(ii)(D) | 1.8 | ✅ |
| Unused credentials >90 days | `aws_iam_unused_credentials` | CC6.2 | 164.308(a)(5)(ii)(C) | 1.12 | ✅ |
| Access key rotation <90 days | `aws_iam_access_key_rotation` | CC6.1 | 164.308(a)(5)(ii)(D) | 1.14 | ✅ |
| Console users have MFA | `aws_iam_console_mfa` | CC6.1 | 164.312(d) | 1.10 | ✅ |
| No admin policies attached directly to users | — | CC6.3 | 164.308(a)(3) | 1.16 | ✅ |
| IAM users receive permissions via groups only | — | CC6.3 | 164.308(a)(3) | 1.15 | ✅ |
| Support role exists | — | CC6.3 | — | 1.17 | ✅ |
| IAM Access Analyzer enabled | — | CC6.3 | — | 1.20 | ✅ |
| Hardware MFA for root | — | CC6.1 | 164.312(d) | 1.6 | ✅ |
| Password policy prevents reuse (24 passwords) | — | CC6.1 | 164.308(a)(5) | 1.9 | ✅ |
| One active access key per user | — | CC6.1 | — | 1.13 | ✅ |

### 1.2 S3

| Check | ID | SOC2 | HIPAA | CIS | Status |
|---|---|---|---|---|---|
| Public access block enabled per bucket | `aws_s3_public_access_block` | CC6.6 | 164.312(e)(1) | 2.1.2 | ✅ |
| Server-side encryption enabled | `aws_s3_encryption` | CC6.7 | 164.312(e)(1) | 2.1.1 | ✅ |
| Account-level public access block | — | CC6.6 | 164.312(e)(1) | 2.1.4 | ✅ |
| MFA delete enabled | — | CC6.7 | 164.312(c)(1) | 2.1.3 | ✅ |
| Versioning enabled | — | CC7.2 | 164.312(c)(1) | 2.1.5 | ✅ |
| Access logging enabled | — | CC7.2 | 164.312(b) | 3.6 | ✅ |

### 1.3 CloudTrail

| Check | ID | SOC2 | HIPAA | CIS | Status |
|---|---|---|---|---|---|
| Trail exists and logging enabled | `aws_cloudtrail_enabled` / `aws_cloudtrail_logging` | CC7.2 | 164.312(b) | 3.1 | ✅ |
| Multi-region trail | `aws_cloudtrail_multiregion` | CC7.2 | 164.312(b) | 3.1 | ✅ |
| Log file validation enabled | `aws_cloudtrail_log_validation` | CC7.2 | 164.312(b) | 3.2 | ✅ |
| S3 bucket for CloudTrail not public | — | CC7.2 | 164.312(b) | 3.3 | ✅ |
| CloudTrail integrated with CloudWatch logs | — | CC7.2 | 164.312(b) | 3.4 | ✅ |
| CloudTrail logs encrypted with KMS CMK | — | CC6.7 | 164.312(a)(2)(iv) | 3.7 | ✅ |
| CloudWatch alarm: root account login | — | CC7.2 | 164.312(b) | 3.3 | ✅ |
| CloudWatch alarm: unauthorized API calls | — | CC7.2 | 164.312(b) | 3.1 | ✅ |
| CloudWatch alarm: console login without MFA | — | CC6.1 | 164.312(d) | 3.2 | ✅ |

### 1.4 Networking

| Check | ID | SOC2 | HIPAA | CIS | Status |
|---|---|---|---|---|---|
| No security groups open SSH to 0.0.0.0/0 | `aws_sg_open_ssh` | CC6.6 | 164.312(e)(2)(i) | 4.1 | ✅ |
| No security groups open RDP to 0.0.0.0/0 | `aws_sg_open_rdp` | CC6.6 | 164.312(e)(2)(i) | 4.2 | ✅ |
| VPC flow logs enabled | `aws_vpc_flow_logs` | CC6.6 | 164.312(b) | 3.9 | ✅ |
| Default security group restricts all traffic | — | CC6.6 | 164.312(e)(2)(i) | 5.4 | ✅ |
| No unrestricted inbound on common ports | — | CC6.6 | 164.312(e)(2)(i) | 4.3–4.13 | ✅ |
| VPC peering route tables least-privilege | — | CC6.6 | 164.312(e)(2)(i) | 5.5 | ✅ |

### 1.5 Encryption & Key Management

| Check | ID | SOC2 | HIPAA | CIS | Status |
|---|---|---|---|---|---|
| EBS default encryption enabled | `aws_ebs_encryption` | CC6.7 | 164.312(a)(2)(iv) | 2.2.1 | ✅ |
| RDS encryption at rest | `aws_rds_encryption` | CC6.7 | 164.312(a)(2)(iv) | 2.3.1 | ✅ |
| KMS CMK rotation enabled | — | CC6.7 | 164.312(a)(2)(iv) | 3.8 | ✅ |
| EFS encryption at rest | — | CC6.7 | 164.312(a)(2)(iv) | 2.4.1 | ✅ |
| Secrets Manager used (not plaintext in SSM/env) | — | CC6.7 | 164.312(a)(2)(iv) | — | ✅ |
| RDS no public snapshots | — | CC6.6 | 164.312(e)(1) | 2.3.2 | ✅ |

### 1.6 Monitoring & Config

| Check | ID | SOC2 | HIPAA | CIS | Status |
|---|---|---|---|---|---|
| AWS Config enabled and recording | `aws_config_enabled` | CC7.2 | — | 3.5 | ✅ |
| GuardDuty enabled | `aws_guardduty_enabled` | CC6.8 | 164.308(a)(1)(ii)(D) | 3.10 | ✅ |
| Security Hub enabled | — | CC6.8 | 164.308(a)(1)(ii)(D) | — | ✅ |
| AWS Inspector v2 enabled | — | CC7.1 | 164.308(a)(5)(ii)(B) | — | ✅ |
| SNS topic exists for CloudWatch alarms | — | CC7.2 | 164.312(b) | 3.x | ✅ |

### 1.7 EKS

| Check | ID | SOC2 | HIPAA | CIS | Status |
|---|---|---|---|---|---|
| API endpoint not open to 0.0.0.0/0 | `aws_eks_endpoint_public` | CC6.6 | 164.312(e)(2)(i) | 5.4.1 | ✅ |
| Secrets envelope encryption (KMS) | `aws_eks_secrets_encryption` | CC6.7 | 164.312(a)(2)(iv) | 5.3.1 | ✅ |
| Control plane logging (api/audit/auth) | `aws_eks_logging` | CC7.2 | 164.312(b) | 5.1.1 | ✅ |
| Node groups use custom launch templates (IMDSv2) | `aws_eks_imdsv2` | CC6.6 | — | 5.4.2 | ✅ |
| Pod security admission enforced | — | CC6.6 | 164.312(a)(1) | 5.2.1 | ✅ |
| RBAC — no anonymous auth | — | CC6.3 | 164.308(a)(3) | 5.1.1 | ✅ |
| Node groups not using deprecated AMI types | — | CC7.1 | — | 5.4.3 | ✅ |

### 1.8 ECR

| Check | ID | SOC2 | HIPAA | CIS | Status |
|---|---|---|---|---|---|
| Scan-on-push enabled | `aws_ecr_scan_on_push` | CC7.1 | 164.308(a)(5)(ii)(B) | 5.1 | ✅ |
| No CRITICAL/HIGH CVEs in latest images | `aws_ecr_vulnerabilities` | CC7.1 | 164.308(a)(5)(ii)(B) | 5.2 | ✅ |
| Immutable image tags enabled | — | CC7.1 | — | 5.3 | ✅ |
| Lifecycle policy configured | — | CC7.1 | — | 5.4 | ✅ |
| Repository policy not public | — | CC6.6 | 164.312(e)(1) | 5.5 | ✅ |

---

## 2. GCP

### 2.1 IAM

| Check | ID | SOC2 | HIPAA | CIS | Status |
|---|---|---|---|---|---|
| No service accounts with user-managed keys | `gcp_iam_sa_keys` | CC6.1/CC6.2 | 164.308(a)(3)(ii)(A) | 1.4 | ✅ |
| Domain-restricted sharing policy enforced | `gcp_org_domain_restrict` | CC6.1/CC6.6 | 164.308(a)(4)(i) | 1.8 | ✅ |
| No users with primitive roles (Owner/Editor) | — | CC6.3 | 164.308(a)(3) | 1.1 | ✅ |
| Corporate credentials only (no gmail accounts) | — | CC6.1 | 164.308(a)(3) | 1.2 | ✅ |
| No service account has project Owner role | — | CC6.3 | 164.308(a)(3) | 1.5 | ✅ |
| Service account keys rotated <90 days | — | CC6.1 | 164.308(a)(5) | 1.7 | ✅ |

### 2.2 Audit & Logging

| Check | ID | SOC2 | HIPAA | CIS | Status |
|---|---|---|---|---|---|
| Cloud Audit Logs DATA_READ+WRITE for allServices | `gcp_audit_logs` | CC7.2 | 164.312(b) | 2.1 | ✅ |
| Log sink configured (export to GCS/BigQuery) | — | CC7.2 | 164.312(b) | 2.2 | ✅ |
| Log metric: project ownership changes | — | CC7.2 | 164.312(b) | 2.4 | ✅ |
| Log metric: audit config changes | — | CC7.2 | 164.312(b) | 2.5 | ✅ |
| Log metric: custom role changes | — | CC7.2 | 164.312(b) | 2.6 | ✅ |

### 2.3 Networking

| Check | ID | SOC2 | HIPAA | CIS | Status |
|---|---|---|---|---|---|
| No firewall rules allow SSH from 0.0.0.0/0 | `gcp_firewall_ssh` | CC6.6 | 164.312(e)(2)(i) | 3.1 | ✅ |
| No firewall rules allow RDP from 0.0.0.0/0 | `gcp_firewall_rdp` | CC6.6 | 164.312(e)(2)(i) | 3.2 | ✅ |
| VPC flow logs on all subnets | `gcp_vpc_flow_logs` | CC6.6 | 164.312(b) | 3.8 | ✅ |
| No default network exists | — | CC6.6 | 164.312(e)(2)(i) | 3.1 | ✅ |
| DNS logging enabled on all VPCs | — | CC7.2 | 164.312(b) | 3.7 | ✅ |

### 2.4 Storage (GCS)

| Check | ID | SOC2 | HIPAA | CIS | Status |
|---|---|---|---|---|---|
| No GCS buckets publicly accessible | `gcp_gcs_public_access` | CC6.6 | 164.312(e)(1) | 5.1 | ✅ |
| GCS uniform bucket-level access enabled | `gcp_gcs_uniform_iam` | CC6.6/CC6.7 | 164.312(e)(1) | 5.2 | ✅ |
| GCS bucket versioning enabled | — | CC7.2 | 164.312(c)(1) | 5.3 | ✅ |
| GCS bucket logging enabled | — | CC7.2 | 164.312(b) | 5.4 | ✅ |
| GCS bucket encryption with CMEK | — | CC6.7 | 164.312(a)(2)(iv) | 5.5 | ✅ |

### 2.5 Compute & Cloud SQL

| Check | ID | SOC2 | HIPAA | CIS | Status |
|---|---|---|---|---|---|
| Cloud SQL SSL required | `gcp_cloudsql_ssl` | CC6.7 | 164.312(a)(2)(iv) | 6.3.7 | ✅ |
| Cloud SQL no public IP | `gcp_cloudsql_public_ip` | CC6.6 | 164.312(e)(2)(i) | 6.4 | ✅ |
| Cloud SQL automated backups enabled | — | CC9.1 | 164.308(a)(7) | 6.7 | ✅ |
| VM OS login enabled | — | CC6.1 | 164.308(a)(3) | 4.4 | ✅ |
| VM project-wide SSH keys disabled | — | CC6.1 | 164.308(a)(3) | 4.3 | ✅ |
| VM shielded VM enabled | — | CC6.6 | — | 4.8 | ✅ |
| VM serial port access disabled | — | CC6.6 | 164.312(e)(2)(i) | 4.5 | ✅ |
| VM disk encryption with CMEK | — | CC6.7 | 164.312(a)(2)(iv) | 4.7 | ✅ |

### 2.6 GKE

| Check | ID | SOC2 | HIPAA | CIS | Status |
|---|---|---|---|---|---|
| Private nodes enabled | `gcp_gke_private_cluster` | CC6.6 | 164.312(e)(2)(i) | 6.6.1 | ✅ |
| Workload Identity enabled | `gcp_gke_workload_identity` | CC6.1 | 164.308(a)(3)(ii)(A) | 6.2.1 | ✅ |
| Network policy enabled | `gcp_gke_network_policy` | CC6.6 | 164.312(e)(2)(i) | 6.6.7 | ✅ |
| Master authorized networks | `gcp_gke_master_auth_networks` | CC6.6 | 164.312(e)(2)(i) | 6.6.2 | ✅ |
| Shielded nodes enabled | `gcp_gke_shielded_nodes` | CC6.6 | — | 6.5.3 | ✅ |
| Legacy metadata endpoints disabled | `gcp_gke_legacy_metadata` | CC6.6 | — | 6.4.1 | ✅ |
| Node auto-upgrade enabled | — | CC7.1 | 164.308(a)(5) | 6.5.2 | ✅ |
| Binary Authorization enabled | — | CC7.1 | — | 6.10.1 | ✅ |
| Intranode visibility enabled | — | CC6.6 | — | 6.6.5 | ✅ |
| Release channel configured | — | CC7.1 | — | 6.5.1 | ✅ |

---

## 3. Azure

### 3.1 IAM & Identity

| Check | ID | SOC2 | HIPAA | CIS | Status |
|---|---|---|---|---|---|
| Defender for Cloud (Standard tier) | `az_defender` | CC6.8 | 164.308(a)(1)(ii)(D) | 2.1 | ✅ |
| MFA required for all users | — | CC6.1 | 164.312(d) | 1.1.1 | ✅ |
| No guest users with admin roles | — | CC6.3 | 164.308(a)(3) | 1.3 | ✅ |
| Privileged Identity Management (PIM) used | — | CC6.3 | 164.308(a)(3) | 1.14 | ✅ |
| Conditional access policy requires MFA | — | CC6.1 | 164.312(d) | 1.2.1 | ✅ |
| No custom subscription owner roles | — | CC6.3 | 164.308(a)(3) | 1.21 | ✅ |

### 3.2 Storage

| Check | ID | SOC2 | HIPAA | CIS | Status |
|---|---|---|---|---|---|
| Storage accounts enforce HTTPS only | `az_storage_https` | CC6.7 | 164.312(e)(2)(ii) | 3.1 | ✅ |
| No public blob access on storage accounts | `az_storage_public` | CC6.6 | 164.312(e)(1) | 3.7 | ✅ |
| Minimum TLS 1.2 enforced | — | CC6.7 | 164.312(e)(2)(ii) | 3.4 | ✅ |
| Infrastructure encryption enabled | — | CC6.7 | 164.312(a)(2)(iv) | 3.2 | ✅ |
| Storage access logging enabled | — | CC7.2 | 164.312(b) | 3.10–3.12 | ✅ |
| Blob soft delete enabled | — | CC9.1 | 164.308(a)(7) | 3.8 | ✅ |

### 3.3 Networking

| Check | ID | SOC2 | HIPAA | CIS | Status |
|---|---|---|---|---|---|
| No NSG rules allow RDP from Internet | `az_nsg_rdp` | CC6.6 | 164.312(e)(2)(i) | 6.1 | ✅ |
| No NSG rules allow SSH from Internet | `az_nsg_ssh` | CC6.6 | 164.312(e)(2)(i) | 6.2 | ✅ |
| NSG flow logs enabled (90-day retention) | — | CC7.2 | 164.312(b) | 6.4 | ✅ |
| Network Watcher enabled in all regions | — | CC7.2 | 164.312(b) | 6.5 | ✅ |

### 3.4 Compute & Encryption

| Check | ID | SOC2 | HIPAA | CIS | Status |
|---|---|---|---|---|---|
| VM managed disk encryption enabled | `az_disk_encryption` | CC6.7 | 164.312(a)(2)(iv) | 7.2 | ✅ |
| Azure Backup enabled on VMs | — | CC9.1 | 164.308(a)(7) | 7.4 | ✅ |
| Trusted launch / Secure boot enabled | — | CC6.6 | — | 7.5 | ✅ |

### 3.5 Logging & Monitoring

| Check | ID | SOC2 | HIPAA | CIS | Status |
|---|---|---|---|---|---|
| Activity log diagnostic settings configured | `az_activity_logs` | CC7.2 | 164.312(b) | 5.1.1 | ✅ |
| Activity log retention ≥ 1 year | — | CC7.2 | 164.312(b) | 5.1.2 | ✅ |
| Log alert: Create/update policy assignment | — | CC7.2 | — | 5.2.1 | ✅ |
| Log alert: Create/update/delete NSG | — | CC7.2 | — | 5.2.5 | ✅ |
| Log alert: Create/update SQL server firewall | — | CC7.2 | — | 5.2.8 | ✅ |

### 3.6 SQL Database

| Check | ID | SOC2 | HIPAA | CIS | Status |
|---|---|---|---|---|---|
| SQL Server auditing enabled | `az_sql_auditing` | CC7.2 | 164.312(b) | 4.1.1 | ✅ |
| SQL Database TDE enabled | `az_sql_tde` | CC6.7 | 164.312(a)(2)(iv) | 4.1.2 | ✅ |
| SQL Server threat detection / Advanced Threat Protection | — | CC6.8 | 164.308(a)(1)(ii)(D) | 4.2.1 | ✅ |
| SQL Server audit retention ≥ 90 days | — | CC7.2 | 164.312(b) | 4.1.3 | ✅ |
| SQL Vulnerability assessment enabled | — | CC7.1 | 164.308(a)(5) | 4.2.2 | ✅ |
| No SQL Server firewall rule allows all IPs (0.0.0.0) | — | CC6.6 | 164.312(e)(2)(i) | 4.3 | ✅ |

### 3.7 AKS

| Check | ID | SOC2 | HIPAA | CIS | Status |
|---|---|---|---|---|---|
| RBAC enabled | `az_aks_rbac` | CC6.1 | 164.308(a)(3)(i) | 5.1.1 | ✅ |
| Azure AD integration | `az_aks_aad` | CC6.1 | 164.308(a)(3)(i) | 5.2.1 | ✅ |
| Network policy configured | `az_aks_network_policy` | CC6.6 | 164.312(e)(2)(i) | 5.3.2 | ✅ |
| Private cluster / authorized IP ranges | `az_aks_private_cluster` | CC6.6 | 164.312(e)(2)(i) | 5.4.1 | ✅ |
| Node OS auto-upgrade enabled | — | CC7.1 | 164.308(a)(5) | 5.4.2 | ✅ |
| Defender for Containers on AKS | — | CC6.8 | 164.308(a)(1)(ii)(D) | 5.4.3 | ✅ |
| Secrets Store CSI Driver (not env-var secrets) | — | CC6.7 | 164.312(a)(2)(iv) | 5.1.2 | ✅ |

---

## 4. Kubernetes Workloads (all providers)

### 4.1 Pod & Container Security

| Check | ID | SOC2 | HIPAA | CIS | Status |
|---|---|---|---|---|---|
| No privileged containers | `k8s_privileged` | CC6.6 | 164.312(a)(1) | 5.2.1 | ✅ |
| No containers running as root | `k8s_root_user` | CC6.6 | 164.312(a)(1) | 5.2.6 | ✅ |
| No hostNetwork sharing | `k8s_host_network` | CC6.6 | 164.312(a)(1) | 5.2.4 | ✅ |
| No hostPID sharing | `k8s_host_pid` | CC6.6 | 164.312(a)(1) | 5.2.2 | ✅ |
| No hostIPC sharing | `k8s_host_ipc` | CC6.6 | 164.312(a)(1) | 5.2.3 | ✅ |
| All containers have resource limits | `k8s_resource_limits` | CC6.6 | — | 5.2.12 | ✅ |
| Read-only root filesystem | `k8s_readonly_rootfs` | CC6.6 | 164.312(a)(1) | 5.2.8 | ✅ |
| No privilege escalation allowed | — | CC6.6 | 164.312(a)(1) | 5.2.5 | ✅ |
| Containers drop all Linux capabilities | — | CC6.6 | 164.312(a)(1) | 5.2.7 | ✅ |
| No writable hostPath mounts | — | CC6.6 | 164.312(a)(1) | 5.2.9 | ✅ |
| Seccomp profile set | — | CC6.6 | — | 5.7.2 | ✅ |
| AppArmor / SELinux profile set | — | CC6.6 | — | 5.7.3 | ✅ |

### 4.2 RBAC

| Check | ID | SOC2 | HIPAA | CIS | Status |
|---|---|---|---|---|---|
| No unexpected cluster-admin bindings | `k8s_cluster_admin` | CC6.3 | 164.308(a)(3)(i) | 5.1.1 | ✅ |
| No wildcard verbs in roles/clusterroles | — | CC6.3 | 164.308(a)(3) | 5.1.3 | ✅ |
| Service accounts do not auto-mount tokens | — | CC6.3 | 164.308(a)(3) | 5.1.6 | ✅ |
| No bind/escalate/impersonate in roles | — | CC6.3 | 164.308(a)(3) | 5.1.5 | ✅ |

### 4.3 Networking

| Check | ID | SOC2 | HIPAA | CIS | Status |
|---|---|---|---|---|---|
| All workload namespaces have network policies | `k8s_network_policies` | CC6.6 | 164.312(e)(2)(i) | 5.3.2 | ✅ |
| Network policies enforce default-deny | — | CC6.6 | 164.312(e)(2)(i) | 5.3.1 | ✅ |

### 4.4 Secrets Management

| Check | ID | SOC2 | HIPAA | CIS | Status |
|---|---|---|---|---|---|
| No secrets stored in pod environment variables | — | CC6.7 | 164.312(a)(2)(iv) | 5.4.1 | ✅ |
| Etcd secrets encrypted at rest | — | CC6.7 | 164.312(a)(2)(iv) | 5.4.2 | ✅ |
| External secrets / CSI driver in use | — | CC6.7 | 164.312(a)(2)(iv) | — | ✅ |

### 4.5 Admission Control

| Check | ID | SOC2 | HIPAA | CIS | Status |
|---|---|---|---|---|---|
| Pod Security Admission enforced (baseline/restricted) | — | CC6.6 | 164.312(a)(1) | 5.2.1 | ✅ |
| OPA/Gatekeeper or Kyverno policy engine active | — | CC6.6 | — | — | ✅ |

---

## 5. GitHub

### 5.1 Repository Security

| Check | ID | SOC2 | HIPAA | CIS | Status |
|---|---|---|---|---|---|
| Branch protection with required reviews | `github_branch_protection` | CC8.1 | 164.308(a)(3)(i) | — | ✅ |
| Required status checks before merge | `github_required_status_checks` | CC8.1 | — | — | ✅ |
| No unexpected public repositories | `github_public_repos` | CC6.6 | 164.308(a)(4)(i) | — | ✅ |
| Secret scanning enabled on public repos | `github_secret_scanning` | CC6.8 | 164.308(a)(1)(ii)(D) | — | ✅ |
| Dependabot configured | `github_dependabot` | CC7.1 | — | — | ✅ |
| Secret scanning on private repos (Advanced Security) | — | CC6.8 | 164.308(a)(1)(ii)(D) | — | ✅ |
| Push protection blocks committing secrets | — | CC6.8 | — | — | ✅ |
| Dependabot security alerts enabled | — | CC7.1 | 164.308(a)(5) | — | ✅ |
| Code scanning (SAST / CodeQL) enabled | — | CC7.1 | 164.308(a)(5) | — | ✅ |

### 5.2 CI/CD Pipeline

| Check | ID | SOC2 | HIPAA | CIS | Status |
|---|---|---|---|---|---|
| Actions pinned to full commit SHA | `github_actions_pinned` | CC8.1/CC7.1 | — | — | ✅ |
| No unsafe pull_request_target + head checkout | `github_actions_prt` | CC8.1 | — | — | ✅ |
| Production environments require reviewer approval | `github_env_protection` | CC8.1/CC6.3 | — | — | ✅ |
| GITHUB_TOKEN permissions default to read-only | — | CC6.3 | — | — | ✅ |
| No self-hosted runners on public repos | — | CC6.6 | — | — | ✅ |
| OIDC used for cloud auth (no long-lived secrets) | — | CC6.1 | 164.308(a)(3) | — | ✅ |

### 5.3 Organization Security

| Check | ID | SOC2 | HIPAA | CIS | Status |
|---|---|---|---|---|---|
| 2FA required for all org members | — | CC6.1 | 164.312(d) | — | ✅ |
| SSO enforced for org members | — | CC6.1 | 164.308(a)(5) | — | ✅ |
| No outside collaborators with admin access | — | CC6.3 | 164.308(a)(3) | — | ✅ |
| Verified/approved domains configured | — | CC6.1 | — | — | ✅ |

---

## Summary

| Source | ✅ Done | 🔲 Todo | Total |
|---|---|---|---|
| AWS IAM | 6 | 7 | 13 |
| AWS S3 | 2 | 4 | 6 |
| AWS CloudTrail | 3 | 6 | 9 |
| AWS Networking | 3 | 3 | 6 |
| AWS Encryption/KMS | 2 | 4 | 6 |
| AWS Monitoring | 2 | 3 | 5 |
| AWS EKS | 4 | 3 | 7 |
| AWS ECR | 2 | 3 | 5 |
| GCP IAM | 2 | 4 | 6 |
| GCP Audit/Logging | 1 | 4 | 5 |
| GCP Networking | 3 | 2 | 5 |
| GCP Storage | 2 | 3 | 5 |
| GCP Compute/SQL | 2 | 6 | 8 |
| GCP GKE | 6 | 4 | 10 |
| Azure IAM | 1 | 5 | 6 |
| Azure Storage | 2 | 4 | 6 |
| Azure Networking | 2 | 2 | 4 |
| Azure Compute | 1 | 2 | 3 |
| Azure Logging | 1 | 4 | 5 |
| Azure SQL | 2 | 4 | 6 |
| Azure AKS | 4 | 3 | 7 |
| Kubernetes Pods | 7 | 5 | 12 |
| Kubernetes RBAC | 1 | 3 | 4 |
| Kubernetes Networking | 1 | 1 | 2 |
| Kubernetes Secrets | 0 | 3 | 3 |
| Kubernetes Admission | 0 | 2 | 2 |
| GitHub Repos | 5 | 4 | 9 |
| GitHub CI/CD | 3 | 3 | 6 |
| GitHub Org | 0 | 4 | 4 |
| **TOTAL** | **74** | **116** | **190** |
