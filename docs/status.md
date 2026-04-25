# ComplyKit — Check Status

**Frameworks:** SOC2 (Trust Services Criteria) · HIPAA (Security Rule) · CIS (Benchmarks)

---

## Part 1 — Implemented Checks

### AWS / IAM

| # | Check ID | Title | SOC2 | HIPAA | CIS |
|---|---|---|---|---|---|
| 1 | `aws_iam_root_mfa` | Root account MFA enabled | CC6.1 | 164.312(d) | 1.5 |
| 2 | `aws_iam_root_access_keys` | No root account access keys | CC6.1 | — | 1.4 |
| 3 | `aws_iam_root_hardware_mfa` | Root hardware MFA (verify manually) | CC6.1 | 164.312(d) | 1.6 |
| 4 | `aws_iam_password_policy` | IAM password policy strength + reuse prevention | CC6.1 | 164.308(a)(5)(ii)(D) | 1.8/1.9 |
| 5 | `aws_iam_unused_credentials` | Unused credentials > 90 days | CC6.2 | 164.308(a)(5)(ii)(C) | 1.12 |
| 6 | `aws_iam_access_key_rotation` | Access key rotation < 90 days | CC6.1 | 164.308(a)(5)(ii)(D) | 1.14 |
| 7 | `aws_iam_one_key_per_user` | One active access key per user | CC6.1 | — | 1.13 |
| 8 | `aws_iam_console_mfa` | All console users have MFA | CC6.1 | 164.312(d) | 1.10 |
| 9 | `aws_iam_no_direct_admin` | No AdministratorAccess attached directly to users | CC6.3 | 164.308(a)(3) | 1.16 |
| 10 | `aws_iam_users_in_groups` | IAM users receive permissions via groups | CC6.3 | 164.308(a)(3) | 1.15 |
| 11 | `aws_iam_support_role` | Support role with AWSSupportAccess exists | CC6.3 | — | 1.17 |
| 12 | `aws_iam_access_analyzer` | IAM Access Analyzer enabled | CC6.3 | — | 1.20 |

### AWS / S3

| # | Check ID | Title | SOC2 | HIPAA | CIS |
|---|---|---|---|---|---|
| 13 | `aws_s3_public_access_block` | Public access block enabled per bucket | CC6.6 | 164.312(e)(1) | 2.1.2 |
| 14 | `aws_s3_encryption` | Server-side encryption enabled | CC6.7 | 164.312(e)(1) | 2.1.1 |
| 15 | `aws_s3_versioning` | Versioning enabled | CC7.2 | 164.312(c)(1) | 2.1.5 |
| 16 | `aws_s3_logging` | Access logging enabled | CC7.2 | 164.312(b) | 3.6 |
| 17 | `aws_s3_mfa_delete` | MFA delete enabled | CC6.7 | 164.312(c)(1) | 2.1.3 |

### AWS / CloudTrail

| # | Check ID | Title | SOC2 | HIPAA | CIS |
|---|---|---|---|---|---|
| 18 | `aws_cloudtrail_enabled` | Trail exists | CC7.2 | 164.312(b) | 3.1 |
| 19 | `aws_cloudtrail_logging` | Trail logging enabled | CC7.2 | 164.312(b) | 3.1 |
| 20 | `aws_cloudtrail_multiregion` | Multi-region trail | CC7.2 | 164.312(b) | 3.1 |
| 21 | `aws_cloudtrail_log_validation` | Log file validation enabled | CC7.2 | 164.312(b) | 3.2 |
| 22 | `aws_ct_cloudwatch` | CloudTrail integrated with CloudWatch Logs | CC7.2 | 164.312(b) | 3.4 |
| 23 | `aws_ct_s3_public` | CloudTrail S3 bucket not publicly accessible | CC7.2 | 164.312(b) | 3.3 |
| 24 | `aws_ct_kms` | CloudTrail logs encrypted with KMS CMK | CC6.7 | 164.312(a)(2)(iv) | 3.7 |

### AWS / CloudWatch Alarms

| # | Check ID | Title | SOC2 | HIPAA | CIS |
|---|---|---|---|---|---|
| 25 | `aws_cw_alarm_root_login` | Alarm: root account login | CC7.2 | 164.312(b) | 3.3 |
| 26 | `aws_cw_alarm_unauth_api` | Alarm: unauthorized API calls | CC7.2 | 164.312(b) | 3.1 |
| 27 | `aws_cw_alarm_no_mfa_console` | Alarm: console sign-in without MFA | CC6.1 | 164.312(d) | 3.2 |
| 28 | `aws_cw_alarm_iam_policy_change` | Alarm: IAM policy changes | CC7.2 | 164.312(b) | 3.4 |

### AWS / Networking

| # | Check ID | Title | SOC2 | HIPAA | CIS |
|---|---|---|---|---|---|
| 29 | `aws_sg_open_ssh` | No SG open SSH to 0.0.0.0/0 | CC6.6 | 164.312(e)(2)(i) | 4.1 |
| 30 | `aws_sg_open_rdp` | No SG open RDP to 0.0.0.0/0 | CC6.6 | 164.312(e)(2)(i) | 4.2 |
| 31 | `aws_sg_unrestricted_ports` | No SG exposes high-risk ports to 0.0.0.0/0 | CC6.6 | 164.312(e)(2)(i) | 4.3 |
| 32 | `aws_sg_default_restricted` | Default security groups restrict all traffic | CC6.6 | 164.312(e)(2)(i) | 5.4 |
| 33 | `aws_vpc_flow_logs` | VPC flow logs enabled | CC6.6 | 164.312(b) | 3.9 |

### AWS / Encryption & KMS

| # | Check ID | Title | SOC2 | HIPAA | CIS |
|---|---|---|---|---|---|
| 34 | `aws_ebs_encryption` | EBS default encryption enabled | CC6.7 | 164.312(a)(2)(iv) | 2.2.1 |
| 35 | `aws_rds_encryption` | RDS encryption at rest | CC6.7 | 164.312(a)(2)(iv) | 2.3.1 |
| 36 | `aws_kms_rotation` | KMS CMK annual rotation enabled | CC6.7 | 164.312(a)(2)(iv) | 3.8 |
| 37 | `aws_efs_encryption` | EFS encryption at rest | CC6.7 | 164.312(a)(2)(iv) | 2.4.1 |
| 38 | `aws_rds_public_snapshot` | No public RDS snapshots | CC6.6 | 164.312(e)(1) | 2.3.2 |
| 39 | `aws_secrets_manager` | Secrets Manager in use | CC6.7 | 164.312(a)(2)(iv) | — |

### AWS / Monitoring & Config

| # | Check ID | Title | SOC2 | HIPAA | CIS |
|---|---|---|---|---|---|
| 40 | `aws_config_enabled` | AWS Config enabled and recording | CC7.2 | — | 3.5 |
| 41 | `aws_guardduty_enabled` | GuardDuty enabled | CC6.8 | 164.308(a)(1)(ii)(D) | 3.10 |
| 42 | `aws_securityhub_enabled` | Security Hub enabled | CC6.8 | 164.308(a)(1)(ii)(D) | — |
| 43 | `aws_inspector_enabled` | Inspector v2 enabled | CC7.1 | 164.308(a)(5)(ii)(B) | — |
| 44 | `aws_sns_topics` | SNS topics exist for alarm notifications | CC7.2 | 164.312(b) | — |

### AWS / EKS

| # | Check ID | Title | SOC2 | HIPAA | CIS |
|---|---|---|---|---|---|
| 45 | `aws_eks_endpoint_public` | API endpoint not open to 0.0.0.0/0 | CC6.6 | 164.312(e)(2)(i) | 5.4.1 |
| 46 | `aws_eks_secrets_encryption` | Secrets envelope encryption (KMS) | CC6.7 | 164.312(a)(2)(iv) | 5.3.1 |
| 47 | `aws_eks_logging` | Control plane logging (api/audit/auth) | CC7.2 | 164.312(b) | 5.1.1 |
| 48 | `aws_eks_imdsv2` | Node groups use custom launch templates (IMDSv2) | CC6.6 | — | 5.4.2 |

### AWS / ECR

| # | Check ID | Title | SOC2 | HIPAA | CIS |
|---|---|---|---|---|---|
| 49 | `aws_ecr_scan_on_push` | Scan-on-push enabled on all repos | CC7.1 | 164.308(a)(5)(ii)(B) | 5.1 |
| 50 | `aws_ecr_vulnerabilities` | No CRITICAL/HIGH CVEs in latest images | CC7.1 | 164.308(a)(5)(ii)(B) | 5.2 |

---

### GCP / IAM

| # | Check ID | Title | SOC2 | HIPAA | CIS |
|---|---|---|---|---|---|
| 51 | `gcp_iam_sa_keys` | No service accounts with user-managed keys | CC6.1/6.2 | 164.308(a)(3)(ii)(A) | 1.4 |
| 52 | `gcp_org_domain_restrict` | Domain-restricted sharing policy enforced | CC6.1/6.6 | 164.308(a)(4)(i) | 1.8 |
| 53 | `gcp_iam_primitive_roles` | No users with primitive Owner/Editor roles | CC6.3 | 164.308(a)(3) | 1.1 |
| 54 | `gcp_iam_gmail` | No gmail.com accounts in project IAM | CC6.1 | 164.308(a)(3) | 1.2 |
| 55 | `gcp_iam_sa_owner` | No service account has project Owner role | CC6.3 | 164.308(a)(3) | 1.5 |
| 56 | `gcp_iam_sa_key_age` | Service account keys rotated < 90 days | CC6.1 | 164.308(a)(5) | 1.7 |

### GCP / Audit & Logging

| # | Check ID | Title | SOC2 | HIPAA | CIS |
|---|---|---|---|---|---|
| 57 | `gcp_audit_logs` | Cloud Audit Logs DATA_READ+WRITE for allServices | CC7.2 | 164.312(b) | 2.1 |
| 58 | `gcp_log_sink` | Log sink configured (export to GCS/BigQuery) | CC7.2 | 164.312(b) | 2.2 |
| 59 | `gcp_log_metric_ownership` | Log metric: project ownership changes | CC7.2 | 164.312(b) | 2.4 |
| 60 | `gcp_log_metric_audit_config` | Log metric: audit config changes | CC7.2 | 164.312(b) | 2.5 |
| 61 | `gcp_log_metric_custom_role` | Log metric: custom role changes | CC7.2 | 164.312(b) | 2.6 |

### GCP / Networking

| # | Check ID | Title | SOC2 | HIPAA | CIS |
|---|---|---|---|---|---|
| 62 | `gcp_firewall_ssh` | No firewall rules allow SSH from 0.0.0.0/0 | CC6.6 | 164.312(e)(2)(i) | 3.1 |
| 63 | `gcp_firewall_rdp` | No firewall rules allow RDP from 0.0.0.0/0 | CC6.6 | 164.312(e)(2)(i) | 3.2 |
| 64 | `gcp_vpc_flow_logs` | VPC flow logs on all subnets | CC6.6 | 164.312(b) | 3.8 |
| 65 | `gcp_no_default_network` | Default VPC network does not exist | CC6.6 | 164.312(e)(2)(i) | 3.1 |

### GCP / Storage (GCS)

| # | Check ID | Title | SOC2 | HIPAA | CIS |
|---|---|---|---|---|---|
| 66 | `gcp_gcs_public_access` | No GCS buckets publicly accessible | CC6.6 | 164.312(e)(1) | 5.1 |
| 67 | `gcp_gcs_uniform_iam` | GCS uniform bucket-level access enabled | CC6.6/6.7 | 164.312(e)(1) | 5.2 |
| 68 | `gcp_gcs_versioning` | GCS bucket versioning enabled | CC7.2 | 164.312(c)(1) | 5.3 |
| 69 | `gcp_gcs_logging` | GCS bucket access logging enabled | CC7.2 | 164.312(b) | 5.4 |
| 70 | `gcp_gcs_cmek` | GCS bucket encryption with CMEK | CC6.7 | 164.312(a)(2)(iv) | 5.5 |

### GCP / Compute & Cloud SQL

| # | Check ID | Title | SOC2 | HIPAA | CIS |
|---|---|---|---|---|---|
| 71 | `gcp_cloudsql_ssl` | Cloud SQL requires SSL | CC6.7 | 164.312(a)(2)(iv) | 6.3.7 |
| 72 | `gcp_cloudsql_public_ip` | Cloud SQL no public IP | CC6.6 | 164.312(e)(2)(i) | 6.4 |
| 73 | `gcp_cloudsql_backup` | Cloud SQL automated backups enabled | CC9.1 | 164.308(a)(7) | 6.7 |
| 74 | `gcp_vm_os_login` | OS Login enabled at project level | CC6.1 | 164.308(a)(3) | 4.4 |
| 75 | `gcp_vm_project_ssh_keys` | No project-wide SSH keys configured | CC6.1 | 164.308(a)(3) | 4.3 |
| 76 | `gcp_vm_serial_port` | VM serial port access disabled | CC6.6 | 164.312(e)(2)(i) | 4.5 |
| 77 | `gcp_vm_shielded` | Shielded VM (Secure Boot) enabled | CC6.6 | — | 4.8 |

### GCP / GKE

| # | Check ID | Title | SOC2 | HIPAA | CIS |
|---|---|---|---|---|---|
| 78 | `gcp_gke_private_cluster` | Private nodes enabled | CC6.6 | 164.312(e)(2)(i) | 6.6.1 |
| 79 | `gcp_gke_workload_identity` | Workload Identity enabled | CC6.1 | 164.308(a)(3)(ii)(A) | 6.2.1 |
| 80 | `gcp_gke_network_policy` | Network policy enabled | CC6.6 | 164.312(e)(2)(i) | 6.6.7 |
| 81 | `gcp_gke_master_auth_networks` | Master authorized networks restricted | CC6.6 | 164.312(e)(2)(i) | 6.6.2 |
| 82 | `gcp_gke_shielded_nodes` | Shielded nodes enabled | CC6.6 | — | 6.5.3 |
| 83 | `gcp_gke_legacy_metadata` | Legacy metadata endpoints disabled | CC6.6 | — | 6.4.1 |
| 84 | `gcp_gke_auto_upgrade` | Node auto-upgrade enabled | CC7.1 | 164.308(a)(5) | 6.5.2 |
| 85 | `gcp_gke_binary_auth` | Binary Authorization enabled | CC7.1 | — | 6.10.1 |
| 86 | `gcp_gke_intranode_visibility` | Intranode visibility enabled | CC6.6 | — | 6.6.5 |
| 87 | `gcp_gke_release_channel` | Release channel configured | CC7.1 | — | 6.5.1 |

---

### Azure / Storage

| # | Check ID | Title | SOC2 | HIPAA | CIS |
|---|---|---|---|---|---|
| 88 | `az_storage_https` | Storage accounts enforce HTTPS-only | CC6.7 | 164.312(e)(2)(ii) | 3.1 |
| 89 | `az_storage_public` | No public blob access on storage accounts | CC6.6 | 164.312(e)(1) | 3.7 |
| 90 | `az_storage_tls` | Minimum TLS 1.2 enforced | CC6.7 | 164.312(e)(2)(ii) | 3.4 |
| 91 | `az_storage_soft_delete` | Blob soft delete enabled | CC9.1 | 164.308(a)(7) | 3.8 |

### Azure / Networking

| # | Check ID | Title | SOC2 | HIPAA | CIS |
|---|---|---|---|---|---|
| 92 | `az_nsg_rdp` | No NSG rules allow RDP from Internet | CC6.6 | 164.312(e)(2)(i) | 6.1 |
| 93 | `az_nsg_ssh` | No NSG rules allow SSH from Internet | CC6.6 | 164.312(e)(2)(i) | 6.2 |
| 94 | `az_nsg_flow_logs` | Network Watcher / NSG flow logs configured | CC7.2 | 164.312(b) | 6.4 |

### Azure / Compute & Encryption

| # | Check ID | Title | SOC2 | HIPAA | CIS |
|---|---|---|---|---|---|
| 95 | `az_disk_encryption` | VM managed disk encryption enabled | CC6.7 | 164.312(a)(2)(iv) | 7.2 |
| 96 | `az_vm_backup` | VM backup configured (tag-based check) | CC9.1 | 164.308(a)(7) | 7.4 |

### Azure / Monitoring & Logging

| # | Check ID | Title | SOC2 | HIPAA | CIS |
|---|---|---|---|---|---|
| 97 | `az_defender` | Defender for Cloud (Standard tier) on key services | CC6.8 | 164.308(a)(1)(ii)(D) | 2.1 |
| 98 | `az_aks_defender_containers` | Defender for Containers enabled | CC6.8 | 164.308(a)(1)(ii)(D) | 5.4.3 |
| 99 | `az_activity_logs` | Activity log diagnostic settings configured | CC7.2 | 164.312(b) | 5.1.1 |
| 100 | `az_activity_log_retention` | Activity log retention ≥ 365 days | CC7.2 | 164.312(b) | 5.1.2 |
| 101 | `az_log_alerts` | Activity log alerts configured | CC7.2 | 164.312(b) | 5.2.1 |

### Azure / SQL Database

| # | Check ID | Title | SOC2 | HIPAA | CIS |
|---|---|---|---|---|---|
| 102 | `az_sql_auditing` | SQL Server auditing enabled | CC7.2 | 164.312(b) | 4.1.1 |
| 103 | `az_sql_tde` | SQL Database Transparent Data Encryption | CC6.7 | 164.312(a)(2)(iv) | 4.1.2 |
| 104 | `az_sql_threat` | SQL Advanced Threat Protection enabled | CC6.8 | 164.308(a)(1)(ii)(D) | 4.2.1 |
| 105 | `az_sql_firewall` | No SQL Server firewall rule allows all IPs | CC6.6 | 164.312(e)(2)(i) | 4.3 |
| 106 | `az_sql_audit_retention` | SQL audit retention ≥ 90 days | CC7.2 | 164.312(b) | 4.1.3 |

### Azure / AKS

| # | Check ID | Title | SOC2 | HIPAA | CIS |
|---|---|---|---|---|---|
| 107 | `az_aks_rbac` | RBAC enabled | CC6.1 | 164.308(a)(3)(i) | 5.1.1 |
| 108 | `az_aks_aad` | Azure AD integration enabled | CC6.1 | 164.308(a)(3)(i) | 5.2.1 |
| 109 | `az_aks_network_policy` | Network policy configured | CC6.6 | 164.312(e)(2)(i) | 5.3.2 |
| 110 | `az_aks_private_cluster` | Private cluster / authorized IP ranges | CC6.6 | 164.312(e)(2)(i) | 5.4.1 |

---

### Kubernetes / Pod & Container Security

| # | Check ID | Title | SOC2 | HIPAA | CIS |
|---|---|---|---|---|---|
| 111 | `k8s_privileged` | No privileged containers | CC6.6 | 164.312(a)(1) | 5.2.1 |
| 112 | `k8s_root_user` | No containers running as root | CC6.6 | 164.312(a)(1) | 5.2.6 |
| 113 | `k8s_host_network` | No hostNetwork sharing | CC6.6 | 164.312(a)(1) | 5.2.4 |
| 114 | `k8s_host_pid` | No hostPID sharing | CC6.6 | 164.312(a)(1) | 5.2.2 |
| 115 | `k8s_host_ipc` | No hostIPC sharing | CC6.6 | 164.312(a)(1) | 5.2.3 |
| 116 | `k8s_resource_limits` | All containers have resource limits | CC6.6 | — | 5.2.12 |
| 117 | `k8s_readonly_rootfs` | Read-only root filesystem | CC6.6 | 164.312(a)(1) | 5.2.8 |
| 118 | `k8s_privilege_escalation` | No privilege escalation allowed | CC6.6 | 164.312(a)(1) | 5.2.5 |
| 119 | `k8s_capability_drop` | Containers drop all capabilities | CC6.6 | 164.312(a)(1) | 5.2.7 |
| 120 | `k8s_hostpath_mounts` | No writable hostPath volume mounts | CC6.6 | 164.312(a)(1) | 5.2.9 |
| 121 | `k8s_seccomp` | Seccomp profile set on pods | CC6.6 | — | 5.7.2 |
| 122 | `k8s_secrets_env_vars` | No plaintext secrets in env variables | CC6.7 | 164.312(a)(2)(iv) | 5.4.1 |

### Kubernetes / RBAC

| # | Check ID | Title | SOC2 | HIPAA | CIS |
|---|---|---|---|---|---|
| 123 | `k8s_cluster_admin` | No unexpected cluster-admin bindings | CC6.3 | 164.308(a)(3)(i) | 5.1.1 |
| 124 | `k8s_wildcard_roles` | No wildcard verbs or resources in roles | CC6.3 | 164.308(a)(3) | 5.1.3 |
| 125 | `k8s_sa_token_automount` | Service accounts disable token automounting | CC6.3 | 164.308(a)(3) | 5.1.6 |
| 126 | `k8s_bind_escalate` | No bind/escalate/impersonate verbs in roles | CC6.3 | 164.308(a)(3) | 5.1.5 |

### Kubernetes / Networking & Admission

| # | Check ID | Title | SOC2 | HIPAA | CIS |
|---|---|---|---|---|---|
| 127 | `k8s_network_policies` | All workload namespaces have network policies | CC6.6 | 164.312(e)(2)(i) | 5.3.2 |
| 128 | `k8s_default_deny` | Namespaces have default-deny network policies | CC6.6 | 164.312(e)(2)(i) | 5.3.1 |
| 129 | `k8s_psa` | Pod Security Admission labels on all namespaces | CC6.6 | 164.312(a)(1) | 5.2.1 |

---

### GitHub / Repository Security

| # | Check ID | Title | SOC2 | HIPAA | CIS |
|---|---|---|---|---|---|
| 130 | `github_branch_protection` | Branch protection with required reviews | CC8.1 | 164.308(a)(3)(i) | — |
| 131 | `github_required_status_checks` | Required status checks before merge | CC8.1 | — | — |
| 132 | `github_public_repos` | No unexpected public repositories | CC6.6 | 164.308(a)(4)(i) | — |
| 133 | `github_secret_scanning` | Secret scanning enabled on public repos | CC6.8 | 164.308(a)(1)(ii)(D) | — |
| 134 | `github_dependabot` | Dependabot configured | CC7.1 | — | — |
| 135 | `github_push_protection` | Secret scanning push protection enabled | CC6.8 | 164.308(a)(1)(ii)(D) | — |
| 136 | `github_code_scanning` | Code scanning (SAST/CodeQL) on private repos | CC7.1 | 164.308(a)(5) | — |

### GitHub / CI/CD Pipeline

| # | Check ID | Title | SOC2 | HIPAA | CIS |
|---|---|---|---|---|---|
| 137 | `github_actions_pinned` | Actions pinned to full SHA (not floating tag) | CC8.1/CC7.1 | — | — |
| 138 | `github_actions_prt` | No unsafe pull_request_target + head checkout | CC8.1 | — | — |
| 139 | `github_env_protection` | Production environments require reviewer approval | CC8.1/CC6.3 | — | — |
| 140 | `github_token_permissions` | GITHUB_TOKEN permissions verified | CC6.3 | — | — |
| 141 | `github_no_self_hosted_public` | No self-hosted runners on public repos | CC6.6 | — | — |

### GitHub / Organization

| # | Check ID | Title | SOC2 | HIPAA | CIS |
|---|---|---|---|---|---|
| 142 | `github_org_2fa` | Organization requires 2FA for all members | CC6.1 | 164.312(d) | — |
| 143 | `github_org_sso` | SAML SSO enabled for org | CC6.1 | 164.308(a)(5) | — |
| 144 | `github_org_outside_collab` | Outside collaborators reviewed | CC6.3 | 164.308(a)(3) | — |

**Total implemented: 144 checks**

---

## Part 2 — Near Future

Prioritized by impact. P1 = high value, straightforward API. P2 = medium complexity. P3 = complex or needs external service.

### AWS

| Priority | Check ID (proposed) | Title | SOC2 | HIPAA | CIS | Notes |
|---|---|---|---|---|---|---|
| P1 ✅ | `aws_ecr_immutable_tags` | ECR image tags are immutable | CC7.1 | — | 5.3 | `ecr.GetRepositoryPolicy`, `PutImageTagMutability` |
| P1 ✅ | `aws_ecr_lifecycle_policy` | ECR lifecycle policy configured | CC7.1 | — | 5.4 | Prevents stale image accumulation |
| P1 ✅ | `aws_ecr_repo_not_public` | ECR repository policy not public | CC6.6 | 164.312(e)(1) | 5.5 | Check `GetRepositoryPolicy` for `*` principal |
| P1 ✅ | `aws_iam_password_max_age` | IAM password max age ≤ 90 days | CC6.1 | 164.308(a)(5) | 1.11 | Add to existing password policy check |
| P1 ✅ | `aws_s3_account_public_block` | Account-level S3 public access block | CC6.6 | 164.312(e)(1) | 2.1.4 | `s3control.GetPublicAccessBlock` |
| P1 ✅ | `aws_waf_enabled` | WAF associated with ALB/CloudFront | CC6.6 | 164.312(e)(2)(i) | — | `wafv2.ListWebACLs` + check associations |
| P1 ✅ | `aws_alb_https_only` | ALB listeners redirect HTTP to HTTPS | CC6.7 | 164.312(e)(2)(ii) | — | `elasticloadbalancingv2.DescribeListeners` |
| P2 ✅ | `aws_eks_pod_security` | EKS pod security admission enforced | CC6.6 | 164.312(a)(1) | 5.2.1 | Check namespace labels via k8s API |
| P2 ✅ | `aws_eks_anonymous_auth` | EKS no anonymous API access | CC6.3 | 164.308(a)(3) | 5.1.1 | Check `system:anonymous` bindings |
| P2 ✅ | `aws_lambda_public_url` | Lambda function URLs are not publicly open | CC6.6 | 164.312(e)(2)(i) | — | `lambda.GetFunctionUrlConfig` |
| P2 ✅ | `aws_backup_vault` | AWS Backup vault configured for key resources | CC9.1 | 164.308(a)(7) | — | `backup.ListBackupVaults` |
| P2 ✅ | `aws_route53_dnssec` | Route53 DNSSEC enabled on hosted zones | CC6.7 | — | — | `route53.ListHostedZones` + DNSSEC status |
| P3 ✅ | `aws_org_scp` | AWS Organizations SCP baseline policies active | CC6.3 | — | — | `organizations.ListPolicies` |
| P3 ✅ | `aws_cw_log_metric_filters` | CloudWatch metric filters verified via Logs API | CC7.2 | 164.312(b) | 3.x | Cross-reference log groups with alarm metrics |

### GCP

| Priority | Check ID (proposed) | Title | SOC2 | HIPAA | CIS | Notes |
|---|---|---|---|---|---|---|
| P1 ✅ | `gcp_dns_logging` | DNS logging enabled on all VPC networks | CC7.2 | 164.312(b) | 3.7 | `dns.ManagedZones` + private zones check |
| P1 ✅ | `gcp_bigquery_public` | BigQuery datasets not publicly accessible | CC6.6 | 164.312(e)(1) | — | `bigquery.Datasets.GetIamPolicy` |
| P1 ✅ | `gcp_artifact_registry_scan` | Artifact Registry container scanning enabled | CC7.1 | 164.308(a)(5)(ii)(B) | — | Container Analysis API |
| P2 ✅ | `gcp_cloudsql_cmek` | Cloud SQL encryption with CMEK | CC6.7 | 164.312(a)(2)(iv) | 6.1 | Check `diskEncryptionConfiguration.kmsKeyName` |
| P2 ✅ | `gcp_gke_database_encryption` | GKE application-layer secrets encryption | CC6.7 | 164.312(a)(2)(iv) | 6.3.1 | `cluster.DatabaseEncryption.State` |
| P2 ✅ | `gcp_kms_key_rotation` | Cloud KMS key rotation enabled | CC6.7 | 164.312(a)(2)(iv) | — | `cloudkms.CryptoKeys` rotationPeriod |
| P2 ✅ | `gcp_vm_disk_cmek` | VM disk encryption with CMEK | CC6.7 | 164.312(a)(2)(iv) | 4.7 | Check `disk.diskEncryptionKey.kmsKeyName` |
| P3 ✅ | `gcp_scc_enabled` | Security Command Center enabled | CC6.8 | 164.308(a)(1)(ii)(D) | — | SCC API activation check |

### Azure

| Priority | Check ID (proposed) | Title | SOC2 | HIPAA | CIS | Notes |
|---|---|---|---|---|---|---|
| P1 ✅ | `az_storage_infra_encryption` | Storage infrastructure encryption enabled | CC6.7 | 164.312(a)(2)(iv) | 3.2 | `requireInfrastructureEncryption` property |
| P1 ✅ | `az_keyvault_soft_delete` | Key Vault soft delete and purge protection enabled | CC6.7 | 164.312(a)(2)(iv) | 8.4 | `armkeyvault` SDK |
| P1 ✅ | `az_keyvault_key_expiry` | Key Vault keys have expiration dates set | CC6.7 | — | 8.1 | `armkeyvault.KeysClient` |
| P1 ✅ | `az_sql_vuln_assessment` | SQL Vulnerability Assessment enabled | CC7.1 | 164.308(a)(5) | 4.2.2 | `armsql.VulnerabilityAssessmentsClient` |
| P1 ✅ | `az_aks_node_auto_upgrade` | AKS node OS auto-upgrade enabled | CC7.1 | 164.308(a)(5) | 5.4.2 | `NodeOSUpgradeChannel` property |
| P2 ✅ | `az_mfa_conditional_access` | Azure AD Conditional Access requires MFA | CC6.1 | 164.312(d) | 1.2.1 | Microsoft Graph API (`beta/identity/conditionalAccess`) |
| P2 ✅ | `az_no_guest_admin` | No guest users with administrative roles | CC6.3 | 164.308(a)(3) | 1.3 | Graph API `directoryRoles` membership |
| P2 ✅ | `az_pim_enabled` | Privileged Identity Management in use | CC6.3 | 164.308(a)(3) | 1.14 | Graph API PIM role assignments |
| P2 ✅ | `az_aks_csi_secrets` | AKS uses Secrets Store CSI Driver | CC6.7 | 164.312(a)(2)(iv) | 5.1.2 | Check addon profile `azureKeyvaultSecretsProvider` |
| P2 ✅ | `az_network_watcher_all_regions` | Network Watcher enabled in all active regions | CC7.2 | 164.312(b) | 6.5 | Compare NW regions vs VM regions |
| P3 ✅ | `az_vm_trusted_launch` | VM Trusted Launch / Secure Boot enabled | CC6.6 | — | 7.5 | `armcompute` `SecurityProfile.SecurityType` |

### Kubernetes

| Priority | Check ID (proposed) | Title | SOC2 | HIPAA | CIS | Notes |
|---|---|---|---|---|---|---|
| P1 ✅ | `k8s_image_pull_always` | Containers use specific image tags (not `:latest`) | CC7.1 | — | 5.5.1 | Check image tag in pod specs |
| P1 ✅ | `k8s_non_root_uid` | Containers run as UID > 0 (numeric user) | CC6.6 | 164.312(a)(1) | 5.2.6 | Check `runAsUser` > 0 |
| P1 ✅ | `k8s_resource_requests` | All containers have resource requests set | CC6.6 | — | — | Prevents noisy-neighbour DoS |
| P1 ✅ | `k8s_image_registry` | Container images pulled from approved registries only | CC7.1 | — | — | Check image registry prefix allowlist |
| P2 ✅ | `k8s_etcd_encryption` | etcd secrets encrypted at rest | CC6.7 | 164.312(a)(2)(iv) | 5.4.2 | Check kube-apiserver `--encryption-provider-config` |
| P2 ✅ | `k8s_opa_gatekeeper` | OPA Gatekeeper or Kyverno admission controller active | CC6.6 | — | — | Check for `ConstraintTemplate` CRDs or Kyverno `ClusterPolicy` |
| P2 ✅ | `k8s_apparmor` | AppArmor profiles applied to containers | CC6.6 | — | 5.7.3 | Check `container.apparmor.security.beta.kubernetes.io` annotations |
| P2 ✅ | `k8s_external_secrets` | External Secrets Operator or CSI driver in use | CC6.7 | 164.312(a)(2)(iv) | — | Check for `SecretStore` CRDs or CSI driver daemonset |
| P3 ✅ | `k8s_audit_logging` | Kubernetes audit logging enabled and retained | CC7.2 | 164.312(b) | 3.2.1 | Check `kube-apiserver --audit-log-path` |
| P3 ✅ | `k8s_falco` | Runtime threat detection (Falco) running | CC6.8 | 164.308(a)(1)(ii)(D) | — | Check Falco daemonset in cluster |

### GitHub

| Priority | Check ID (proposed) | Title | SOC2 | HIPAA | CIS | Notes |
|---|---|---|---|---|---|---|
| P1 ✅ | `github_codeowners` | CODEOWNERS file exists in all repos | CC8.1 | — | — | `GET /repos/{owner}/{repo}/contents/CODEOWNERS` |
| P1 ✅ | `github_dependabot_alerts` | Dependabot security alerts enabled | CC7.1 | 164.308(a)(5) | — | `GET /repos/{owner}/{repo}/vulnerability-alerts` |
| P1 ✅ | `github_branch_dismiss_stale` | Branch protection dismisses stale reviews | CC8.1 | — | — | Check `dismiss_stale_reviews` in protection config |
| P1 ✅ | `github_signed_commits` | Signed commits required on protected branches | CC8.1 | — | — | Check `required_signatures` in branch protection |
| P2 ✅ | `github_oidc_cloud_auth` | OIDC used for cloud auth (no long-lived secrets) | CC6.1 | 164.308(a)(3) | — | Check workflows for `aws-actions/configure-aws-credentials` with OIDC |
| P2 ✅ | `github_verified_domains` | Verified and approved domains configured | CC6.1 | — | — | `GET /orgs/{org}` — `verified_domains` field |
| P2 ✅ | `github_org_ip_allowlist` | Organization IP allowlist enabled | CC6.6 | — | — | `GET /orgs/{org}/settings/billing` (Enterprise only) |
| P3 ✅ | `github_secret_rotation` | Secrets in repository have expiry / rotation policy | CC6.1 | — | — | Cross-reference Secrets Manager / rotation cadence |

### Cross-Cutting (all providers)

| Priority | Check ID (proposed) | Title | SOC2 | HIPAA | Notes |
|---|---|---|---|---|---|
| P1 ✅ | `cross_backup_restore_test` | Backup restore testing evidence exists | CC9.1 | 164.308(a)(7)(ii)(D) | Manual / policy check |
| P1 ✅ | `cross_incident_response` | Incident response runbook documented | CC7.3 | 164.308(a)(6) | Manual / policy check |
| P2 ✅ | `cross_pen_test` | Annual penetration test evidence | CC4.1 | 164.308(a)(8) | Manual / upload evidence |
| P2 ✅ | `cross_data_classification` | PII/PHI data stores tagged and encrypted | CC6.7 | 164.312(a)(2)(iv) | Requires data catalog integration |
| P3 ✅ | `cross_vendor_risk` | Third-party SaaS integrations inventoried | CC9.2 | 164.308(b) | Requires vendor management integration |

---

## Summary

| Source | Implemented | Near Future (P1) | Near Future (P2/P3) |
|---|---|---|---|
| AWS IAM | 12 | 1 | 2 |
| AWS S3 | 5 | 1 | — |
| AWS CloudTrail | 7 | 1 | — |
| AWS CloudWatch | 4 | — | — |
| AWS Networking | 5 | 2 | 1 |
| AWS Encryption/KMS | 6 | — | — |
| AWS Monitoring | 5 | — | — |
| AWS EKS | 4 | — | 2 |
| AWS ECR | 2 | 3 | — |
| AWS Other | — | 2 | 3 |
| GCP IAM | 6 | — | — |
| GCP Logging | 5 | 1 | — |
| GCP Networking | 4 | — | — |
| GCP Storage | 5 | 1 | — |
| GCP Compute/SQL | 7 | — | 3 |
| GCP GKE | 10 | — | 2 |
| GCP Other | — | 1 | 2 |
| Azure Storage | 4 | 1 | — |
| Azure Networking | 3 | — | 1 |
| Azure Compute | 2 | — | 1 |
| Azure Monitoring | 5 | — | — |
| Azure SQL | 5 | 1 | — |
| Azure AKS | 4 | 1 | 2 |
| Azure IAM | — | — | 3 |
| Kubernetes Pods | 12 | 4 | 2 |
| Kubernetes RBAC | 4 | — | — |
| Kubernetes Networking | 3 | — | — |
| Kubernetes Admission | 1 | — | 2 |
| Kubernetes Other | — | — | 3 |
| GitHub Repos | 7 | 4 | — |
| GitHub CI/CD | 5 | — | 2 |
| GitHub Org | 3 | — | 2 |
| Cross-Cutting | — | 2 | 3 |
| **TOTAL** | **144** | **26** | **36** |
