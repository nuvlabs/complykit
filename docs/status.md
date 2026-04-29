# ComplyKit — Check Status

**Frameworks:** SOC2 (Trust Services Criteria) · HIPAA (Security Rule) · CIS (Benchmarks) · ISO 27001 · PCI DSS

---

## Summary

**267 checks registered** across 14 integrations. All checks are registered in `internal/engine/registry.go` and mapped in `internal/engine/controls.go`.

| Integration | Checks |
|---|---|
| AWS/IAM | 12 |
| AWS/S3 | 6 |
| AWS/CloudTrail | 7 |
| AWS/CloudWatch | 5 |
| AWS/EC2 | 5 |
| AWS/EKS | 6 |
| AWS/ECR | 5 |
| AWS/RDS | 9 |
| AWS/Other (KMS, EFS, WAF, ALB, Lambda, Backup, Route53, Org, Macie, Config, GuardDuty, SecurityHub, Inspector, SNS) | 18 |
| GCP (IAM, Logging, Network, Storage, Compute, GKE, BigQuery, KMS, SCC, DLP) | 42 |
| Azure (Storage, Network, Compute, Monitor, SQL, KeyVault, AKS, AAD, Defender) | 28 |
| Kubernetes (Pods, RBAC, Network, Secrets, Admission) | 26 |
| GitHub (Repos, CI/CD, Org) | 20 |
| Terraform (S3, SG, RDS, EC2, Secrets) | 12 |
| Database (comply db scan) | 7 |
| Policy (Cross-cutting) | 5 |

---

## Implemented (267 total)

All checks listed in `internal/engine/registry.go`. Key check IDs by category:

### AWS IAM
`aws_iam_root_mfa` · `aws_iam_root_access_keys` · `aws_iam_root_hardware_mfa` · `aws_iam_console_mfa` · `aws_iam_password_policy` · `aws_iam_unused_credentials` · `aws_iam_access_key_rotation` · `aws_iam_no_direct_admin` · `aws_iam_users_in_groups` · `aws_iam_support_role` · `aws_iam_one_key_per_user` · `aws_iam_access_analyzer`

### AWS S3
`aws_s3_account_public_block` · `aws_s3_public_access_block` · `aws_s3_encryption` · `aws_s3_versioning` · `aws_s3_logging` · `aws_s3_mfa_delete`

### AWS CloudTrail / CloudWatch
`aws_cloudtrail_enabled` · `aws_cloudtrail_logging` · `aws_cloudtrail_multiregion` · `aws_cloudtrail_log_validation` · `aws_ct_cloudwatch` · `aws_ct_s3_public` · `aws_ct_kms` · `aws_cw_alarm_root_login` · `aws_cw_alarm_unauth_api` · `aws_cw_alarm_no_mfa_console` · `aws_cw_alarm_iam_policy_change` · `aws_cw_log_metric_filters`

### AWS Networking & Encryption
`aws_sg_open_ssh` · `aws_sg_open_rdp` · `aws_sg_unrestricted_ports` · `aws_sg_default_restricted` · `aws_vpc_flow_logs` · `aws_ebs_encryption` · `aws_efs_encryption` · `aws_kms_rotation`

### AWS EKS / ECR
`aws_eks_endpoint_public` · `aws_eks_secrets_encryption` · `aws_eks_logging` · `aws_eks_imdsv2` · `aws_eks_pod_security` · `aws_eks_anonymous_auth` · `aws_ecr_scan_on_push` · `aws_ecr_vulnerabilities` · `aws_ecr_immutable_tags` · `aws_ecr_lifecycle_policy` · `aws_ecr_repo_not_public`

### AWS Other Services
`aws_rds_*` (9 checks) · `aws_waf_enabled` · `aws_alb_https_only` · `aws_lambda_public_url` · `aws_backup_vault` · `aws_route53_dnssec` · `aws_org_scp` · `aws_macie_enabled` · `aws_macie_findings` · `aws_guardduty_enabled` · `aws_config_enabled` · `aws_securityhub_enabled` · `aws_inspector_enabled`

### GCP
`gcp_iam_*` (6) · `gcp_audit_logs` · `gcp_log_*` (4) · `gcp_firewall_*` (2) · `gcp_vpc_flow_logs` · `gcp_no_default_network` · `gcp_dns_logging` · `gcp_gcs_*` (5) · `gcp_cloudsql_*` (4) · `gcp_vm_*` (5) · `gcp_gke_*` (10) · `gcp_bigquery_public` · `gcp_artifact_registry_scan` · `gcp_kms_key_rotation` · `gcp_scc_enabled` · `gcp_dlp_job_active`

### Azure
`az_storage_*` (5) · `az_nsg_*` (3) · `az_disk_encryption` · `az_vm_*` (2) · `az_defender` · `az_aks_defender_containers` · `az_activity_*` (2) · `az_log_alerts` · `az_sql_*` (6) · `az_keyvault_*` (3) · `az_aks_*` (6) · `az_mfa_conditional_access` · `az_no_guest_admin` · `az_pim_enabled` · `az_network_watcher_all_regions`

### Kubernetes
`k8s_privileged` · `k8s_root_user` · `k8s_host_*` (4) · `k8s_resource_limits` · `k8s_readonly_rootfs` · `k8s_privilege_escalation` · `k8s_capability_drop` · `k8s_hostpath_mounts` · `k8s_seccomp` · `k8s_psa` · `k8s_secrets_env_vars` · `k8s_cluster_admin` · `k8s_wildcard_roles` · `k8s_sa_token_automount` · `k8s_bind_escalate` · `k8s_network_policies` · `k8s_default_deny` · `k8s_image_pull_always` · `k8s_non_root_uid` · `k8s_resource_requests` · `k8s_image_registry` · `k8s_etcd_encryption` · `k8s_opa_gatekeeper` · `k8s_apparmor` · `k8s_external_secrets` · `k8s_audit_logging` · `k8s_falco`

### GitHub
`github_branch_protection` · `github_required_status_checks` · `github_public_repos` · `github_secret_scanning` · `github_dependabot` · `github_push_protection` · `github_code_scanning` · `github_dependabot_alerts` · `github_codeowners` · `github_branch_dismiss_stale` · `github_signed_commits` · `github_actions_pinned` · `github_actions_prt` · `github_env_protection` · `github_token_permissions` · `github_no_self_hosted_public` · `github_org_2fa` · `github_org_sso` · `github_org_outside_collab` · `github_oidc_cloud_auth` · `github_verified_domains` · `github_org_ip_allowlist` · `github_secret_rotation` · `github_db_credentials`

### Database (comply db scan)
`db_pii_column_detection` · `db_pii_data_sampling` · `db_tls_connection_test` · `db_rls_on_pii_tables` · `db_schema_audit_table` · `db_default_accounts` · `db_unused_accounts`

### Policy / Cross-cutting
`cross_backup_restore_test` · `cross_incident_response` · `cross_pen_test` · `cross_data_classification` · `cross_vendor_risk`

---

## Near Future (next priorities)

All planned checks from the original plan have been implemented and registered. Consider:

- **Deeper cloud scanning**: Azure Entra ID custom role detection, GCP KMS HSM enforcement
- **CI/CD hardening**: GitLab CI/CD security checks, Jenkins pipeline scanning
- **Network controls**: Azure DDoS protection, GCP Cloud Armor WAF
- **Secrets management**: HashiCorp Vault integration, AWS Parameter Store rotation
- **Compliance evidence**: SOC 2 Type II report upload, HIPAA BAA tracking
