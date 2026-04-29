package engine

// CheckInfo describes a single compliance check for the admin UI.
type CheckInfo struct {
	ID          string       `json:"id"`
	Title       string       `json:"title"`
	Severity    string       `json:"severity"`
	Integration string       `json:"integration"`
	Frameworks  []string     `json:"frameworks"` // which frameworks this check belongs to
	Controls    []ControlRef `json:"controls"`
}

// Registry is the canonical list of all checks, used by the admin checks browser.
var Registry = []CheckInfo{
	// ── AWS IAM ──────────────────────────────────────────────────────────────
	{ID: "aws_iam_root_mfa", Title: "Root account MFA enabled", Severity: "critical", Integration: "AWS/IAM",
		Frameworks: []string{"soc2", "hipaa", "cis", "iso27001", "pcidss"},
		Controls:   []ControlRef{{FrameworkSOC2, "CC6.1"}, {FrameworkCIS, "1.5"}, ISO27001("A.9.4.2"), PCIDSS("8.4.2")}},
	{ID: "aws_iam_root_access_keys", Title: "No root account access keys", Severity: "critical", Integration: "AWS/IAM",
		Frameworks: []string{"soc2", "cis", "iso27001", "pcidss"},
		Controls:   []ControlRef{{FrameworkSOC2, "CC6.1"}, {FrameworkCIS, "1.4"}, ISO27001("A.9.2.3"), PCIDSS("7.2.1")}},
	{ID: "aws_iam_console_mfa", Title: "MFA enabled for all IAM users", Severity: "critical", Integration: "AWS/IAM",
		Frameworks: []string{"soc2", "hipaa", "cis", "iso27001", "pcidss"},
		Controls:   []ControlRef{{FrameworkSOC2, "CC6.1"}, ISO27001("A.9.4.2"), PCIDSS("8.4.2")}},
	{ID: "aws_iam_password_policy", Title: "IAM password policy configured", Severity: "high", Integration: "AWS/IAM",
		Frameworks: []string{"soc2", "cis", "iso27001", "pcidss"},
		Controls:   []ControlRef{{FrameworkSOC2, "CC6.1"}, ISO27001("A.9.4.1"), PCIDSS("8.3.6")}},
	{ID: "aws_iam_unused_credentials", Title: "No unused IAM credentials (90+ days)", Severity: "high", Integration: "AWS/IAM",
		Frameworks: []string{"soc2", "cis", "iso27001", "pcidss"},
		Controls:   []ControlRef{{FrameworkSOC2, "CC6.2"}, ISO27001("A.9.2.5"), PCIDSS("8.2.6")}},
	{ID: "aws_iam_access_key_rotation", Title: "Access keys rotated within 90 days", Severity: "high", Integration: "AWS/IAM",
		Frameworks: []string{"soc2", "cis", "iso27001", "pcidss"},
		Controls:   []ControlRef{{FrameworkSOC2, "CC6.1"}, ISO27001("A.9.4.3"), PCIDSS("8.2.9")}},
	{ID: "aws_iam_no_direct_admin", Title: "No direct AdministratorAccess policies", Severity: "high", Integration: "AWS/IAM",
		Frameworks: []string{"soc2", "cis", "iso27001", "pcidss"},
		Controls:   []ControlRef{{FrameworkSOC2, "CC6.3"}, ISO27001("A.9.2.3"), PCIDSS("7.2.1")}},
	{ID: "aws_iam_access_analyzer", Title: "IAM Access Analyzer enabled", Severity: "medium", Integration: "AWS/IAM",
		Frameworks: []string{"soc2", "iso27001", "pcidss"},
		Controls:   []ControlRef{{FrameworkSOC2, "CC6.1"}, ISO27001("A.9.1.2"), PCIDSS("7.2.3")}},

	// ── AWS S3 ───────────────────────────────────────────────────────────────
	{ID: "aws_s3_account_public_block", Title: "S3 account-level public access block", Severity: "critical", Integration: "AWS/S3",
		Frameworks: []string{"soc2", "cis", "iso27001", "pcidss"},
		Controls:   []ControlRef{{FrameworkSOC2, "CC6.1"}, ISO27001("A.13.1.3"), PCIDSS("1.3.2")}},
	{ID: "aws_s3_encryption", Title: "S3 bucket server-side encryption", Severity: "high", Integration: "AWS/S3",
		Frameworks: []string{"soc2", "hipaa", "cis", "iso27001", "pcidss"},
		Controls:   []ControlRef{{FrameworkSOC2, "CC6.1"}, {FrameworkHIPAA, "164.312(a)(2)(iv)"}, ISO27001("A.10.1.1"), PCIDSS("3.5.1")}},
	{ID: "aws_s3_versioning", Title: "S3 bucket versioning enabled", Severity: "medium", Integration: "AWS/S3",
		Frameworks: []string{"soc2", "iso27001", "pcidss"},
		Controls:   []ControlRef{{FrameworkSOC2, "CC7.2"}, ISO27001("A.12.3.1"), PCIDSS("12.3.4")}},
	{ID: "aws_s3_logging", Title: "S3 access logging enabled", Severity: "medium", Integration: "AWS/S3",
		Frameworks: []string{"soc2", "iso27001", "pcidss"},
		Controls:   []ControlRef{{FrameworkSOC2, "CC7.2"}, ISO27001("A.12.4.1"), PCIDSS("10.2.1")}},

	// ── AWS CloudTrail ────────────────────────────────────────────────────────
	{ID: "aws_cloudtrail_enabled", Title: "CloudTrail enabled in all regions", Severity: "critical", Integration: "AWS/CloudTrail",
		Frameworks: []string{"soc2", "hipaa", "cis", "iso27001", "pcidss"},
		Controls:   []ControlRef{{FrameworkSOC2, "CC7.2"}, ISO27001("A.12.4.1"), PCIDSS("10.2.1")}},
	{ID: "aws_ct_log_validation", Title: "CloudTrail log file validation enabled", Severity: "medium", Integration: "AWS/CloudTrail",
		Frameworks: []string{"soc2", "cis", "iso27001", "pcidss"},
		Controls:   []ControlRef{{FrameworkSOC2, "CC7.2"}, ISO27001("A.12.4.2"), PCIDSS("10.5.2")}},

	// ── AWS Security Groups ───────────────────────────────────────────────────
	{ID: "aws_sg_no_open_ssh", Title: "SSH not open to 0.0.0.0/0", Severity: "critical", Integration: "AWS/EC2",
		Frameworks: []string{"soc2", "cis", "iso27001", "pcidss"},
		Controls:   []ControlRef{{FrameworkSOC2, "CC6.6"}, {FrameworkCIS, "5.2"}, ISO27001("A.13.1.1"), PCIDSS("1.2.1")}},
	{ID: "aws_sg_no_open_rdp", Title: "RDP not open to 0.0.0.0/0", Severity: "critical", Integration: "AWS/EC2",
		Frameworks: []string{"soc2", "cis", "iso27001", "pcidss"},
		Controls:   []ControlRef{{FrameworkSOC2, "CC6.6"}, ISO27001("A.13.1.1"), PCIDSS("1.2.1")}},

	// ── AWS KMS ───────────────────────────────────────────────────────────────
	{ID: "aws_kms_key_rotation", Title: "KMS customer keys auto-rotate annually", Severity: "medium", Integration: "AWS/KMS",
		Frameworks: []string{"soc2", "iso27001", "pcidss"},
		Controls:   []ControlRef{{FrameworkSOC2, "CC6.1"}, ISO27001("A.10.1.2"), PCIDSS("3.7.4")}},

	// ── AWS RDS ───────────────────────────────────────────────────────────────
	{ID: "aws_rds_encryption", Title: "RDS storage encryption enabled", Severity: "high", Integration: "AWS/RDS",
		Frameworks: []string{"soc2", "hipaa", "cis", "iso27001", "pcidss"},
		Controls:   []ControlRef{{FrameworkSOC2, "CC6.1"}, {FrameworkHIPAA, "164.312(a)(2)(iv)"}, ISO27001("A.10.1.1"), PCIDSS("3.5.1")}},
	{ID: "aws_rds_not_public", Title: "RDS instances not publicly accessible", Severity: "critical", Integration: "AWS/RDS",
		Frameworks: []string{"soc2", "cis", "iso27001", "pcidss"},
		Controls:   []ControlRef{{FrameworkSOC2, "CC6.1"}, ISO27001("A.13.1.3"), PCIDSS("1.3.2")}},
	{ID: "aws_rds_ssl_enforcement", Title: "RDS instances enforce SSL/TLS in transit", Severity: "high", Integration: "AWS/RDS",
		Frameworks: []string{"soc2", "hipaa", "iso27001", "pcidss"},
		Controls:   []ControlRef{{FrameworkSOC2, "CC6.7"}, {FrameworkHIPAA, "164.312(e)(1)"}, ISO27001("A.10.1.1"), PCIDSS("4.2.1")}},
	{ID: "aws_rds_deletion_protection", Title: "RDS instances have deletion protection enabled", Severity: "medium", Integration: "AWS/RDS",
		Frameworks: []string{"soc2", "iso27001", "pcidss"},
		Controls:   []ControlRef{{FrameworkSOC2, "CC9.1"}, ISO27001("A.12.3.1"), PCIDSS("12.3.4")}},
	{ID: "aws_rds_backup", Title: "RDS automated backups retain ≥ 7 days", Severity: "high", Integration: "AWS/RDS",
		Frameworks: []string{"soc2", "hipaa", "iso27001", "pcidss"},
		Controls:   []ControlRef{{FrameworkSOC2, "CC9.1"}, {FrameworkHIPAA, "164.310(d)(2)(iv)"}, ISO27001("A.12.3.1"), PCIDSS("12.3.4")}},
	{ID: "aws_rds_iam_auth", Title: "RDS IAM database authentication enabled", Severity: "medium", Integration: "AWS/RDS",
		Frameworks: []string{"soc2", "hipaa", "iso27001", "pcidss"},
		Controls:   []ControlRef{{FrameworkSOC2, "CC6.1"}, {FrameworkHIPAA, "164.312(a)(1)"}, ISO27001("A.9.2.3"), PCIDSS("8.2.1")}},
	{ID: "aws_rds_multi_az", Title: "RDS instances have Multi-AZ enabled", Severity: "medium", Integration: "AWS/RDS",
		Frameworks: []string{"soc2", "iso27001", "pcidss"},
		Controls:   []ControlRef{{FrameworkSOC2, "A1.2"}, ISO27001("A.17.2.1"), PCIDSS("12.3.4")}},
	{ID: "aws_rds_minor_upgrade", Title: "RDS auto minor version upgrade enabled", Severity: "low", Integration: "AWS/RDS",
		Frameworks: []string{"cis", "iso27001", "pcidss"},
		Controls:   []ControlRef{{FrameworkCIS, "2.3.2"}, ISO27001("A.12.6.1"), PCIDSS("6.3.3")}},

	// ── AWS EC2 Database ──────────────────────────────────────────────────────
	{ID: "aws_ec2_db_ebs_encrypted", Title: "EC2 database instance EBS volumes are encrypted", Severity: "high", Integration: "AWS/EC2-Database",
		Frameworks: []string{"soc2", "hipaa", "iso27001", "pcidss"},
		Controls:   []ControlRef{{FrameworkSOC2, "CC6.7"}, {FrameworkHIPAA, "164.312(a)(2)(iv)"}, ISO27001("A.10.1.1"), PCIDSS("3.5.1")}},
	{ID: "aws_ec2_db_no_public_ip", Title: "EC2 database instances have no public IP address", Severity: "critical", Integration: "AWS/EC2-Database",
		Frameworks: []string{"soc2", "hipaa", "iso27001", "pcidss"},
		Controls:   []ControlRef{{FrameworkSOC2, "CC6.1"}, {FrameworkHIPAA, "164.312(a)(1)"}, ISO27001("A.13.1.3"), PCIDSS("1.3.2")}},
	{ID: "aws_ec2_db_sg_exposure", Title: "EC2 database security groups do not expose DB ports to internet", Severity: "critical", Integration: "AWS/EC2-Database",
		Frameworks: []string{"soc2", "hipaa", "iso27001", "pcidss"},
		Controls:   []ControlRef{{FrameworkSOC2, "CC6.6"}, {FrameworkHIPAA, "164.312(a)(1)"}, ISO27001("A.13.1.1"), PCIDSS("1.2.1")}},

	// ── Kubernetes Database ───────────────────────────────────────────────────
	{ID: "k8s_db_pvc_encrypted", Title: "Database pod PVCs use encrypted StorageClass", Severity: "high", Integration: "Kubernetes",
		Frameworks: []string{"soc2", "hipaa", "iso27001", "pcidss"},
		Controls:   []ControlRef{{FrameworkSOC2, "CC6.7"}, {FrameworkHIPAA, "164.312(a)(2)(iv)"}, ISO27001("A.10.1.1"), PCIDSS("3.5.1")}},
	{ID: "k8s_db_no_public_service", Title: "No database ports exposed via LoadBalancer or NodePort", Severity: "critical", Integration: "Kubernetes",
		Frameworks: []string{"soc2", "hipaa", "iso27001", "pcidss"},
		Controls:   []ControlRef{{FrameworkSOC2, "CC6.1"}, {FrameworkHIPAA, "164.312(a)(1)"}, ISO27001("A.13.1.3"), PCIDSS("1.3.2")}},

	// ── Terraform Database ────────────────────────────────────────────────────
	{ID: "tf_rds_ssl_mode", Title: "RDS parameter group enforces SSL/TLS", Severity: "high", Integration: "Terraform",
		Frameworks: []string{"soc2", "hipaa", "iso27001", "pcidss"},
		Controls:   []ControlRef{{FrameworkSOC2, "CC6.7"}, {FrameworkHIPAA, "164.312(e)(1)"}, ISO27001("A.10.1.1"), PCIDSS("4.2.1")}},
	{ID: "tf_db_hardcoded_password", Title: "No hardcoded passwords in Terraform RDS resources", Severity: "critical", Integration: "Terraform",
		Frameworks: []string{"soc2", "hipaa", "iso27001", "pcidss"},
		Controls:   []ControlRef{{FrameworkSOC2, "CC6.1"}, {FrameworkHIPAA, "164.312(a)(2)(iv)"}, ISO27001("A.9.4.3"), PCIDSS("8.3.1")}},

	// ── AWS RDS Access ────────────────────────────────────────────────────────
	{ID: "aws_rds_overprivileged_iam", Title: "No IAM principals with broad RDS access", Severity: "high", Integration: "AWS/DB-Access",
		Frameworks: []string{"soc2", "hipaa", "iso27001", "pcidss"},
		Controls:   []ControlRef{{FrameworkSOC2, "CC6.3"}, {FrameworkHIPAA, "164.312(a)(1)"}, ISO27001("A.9.2.3"), PCIDSS("7.2.1")}},
	{ID: "aws_rds_no_master_user_exposed", Title: "RDS instances do not use default master usernames", Severity: "medium", Integration: "AWS/RDS",
		Frameworks: []string{"soc2", "iso27001", "pcidss"},
		Controls:   []ControlRef{{FrameworkSOC2, "CC6.1"}, ISO27001("A.9.2.3"), PCIDSS("8.2.1")}},
	{ID: "aws_secrets_manager_rotation", Title: "DB secrets in Secrets Manager have rotation enabled", Severity: "high", Integration: "AWS/DB-Access",
		Frameworks: []string{"soc2", "hipaa", "iso27001", "pcidss"},
		Controls:   []ControlRef{{FrameworkSOC2, "CC6.1"}, {FrameworkHIPAA, "164.312(a)(2)(iv)"}, ISO27001("A.9.4.3"), PCIDSS("8.3.9")}},

	// ── Kubernetes DB Access ──────────────────────────────────────────────────
	{ID: "k8s_db_not_root", Title: "Database containers do not run as root", Severity: "high", Integration: "Kubernetes",
		Frameworks: []string{"soc2", "hipaa", "iso27001", "pcidss"},
		Controls:   []ControlRef{{FrameworkSOC2, "CC6.1"}, {FrameworkHIPAA, "164.312(a)(1)"}, ISO27001("A.9.2.3"), PCIDSS("7.2.1")}},
	{ID: "k8s_db_secret_not_configmap", Title: "No database credentials stored in ConfigMaps", Severity: "critical", Integration: "Kubernetes",
		Frameworks: []string{"soc2", "hipaa", "iso27001", "pcidss"},
		Controls:   []ControlRef{{FrameworkSOC2, "CC6.1"}, {FrameworkHIPAA, "164.312(a)(2)(iv)"}, ISO27001("A.9.4.3"), PCIDSS("8.3.1")}},

	// ── AWS GuardDuty ─────────────────────────────────────────────────────────
	{ID: "aws_guardduty_enabled", Title: "GuardDuty threat detection enabled", Severity: "high", Integration: "AWS/GuardDuty",
		Frameworks: []string{"soc2", "iso27001", "pcidss"},
		Controls:   []ControlRef{{FrameworkSOC2, "CC7.1"}, ISO27001("A.16.1.2"), PCIDSS("10.7.1")}},

	// ── ISO 27001 specific ────────────────────────────────────────────────────
	{ID: "iso27001_asset_tagging", Title: "EC2 instances tagged with Owner and Environment", Severity: "medium", Integration: "AWS/ISO27001",
		Frameworks: []string{"iso27001"},
		Controls:   []ControlRef{ISO27001("A.8.1"), ISO27001("A.8.2")}},
	{ID: "iso27001_rds_multi_az", Title: "RDS instances have Multi-AZ enabled", Severity: "high", Integration: "AWS/ISO27001",
		Frameworks: []string{"iso27001"},
		Controls:   []ControlRef{ISO27001("A.17.1.2"), ISO27001("A.17.2.1")}},
	{ID: "iso27001_rds_backup_retention", Title: "RDS backup retention ≥ 7 days", Severity: "high", Integration: "AWS/ISO27001",
		Frameworks: []string{"iso27001"},
		Controls:   []ControlRef{ISO27001("A.12.3.1"), ISO27001("A.17.1.2")}},
	{ID: "iso27001_alb_https_redirect", Title: "ALB HTTP redirects to HTTPS", Severity: "high", Integration: "AWS/ISO27001",
		Frameworks: []string{"iso27001"},
		Controls:   []ControlRef{ISO27001("A.10.1.1"), ISO27001("A.13.2.3")}},
	{ID: "iso27001_cloudwatch_alarms", Title: "CloudWatch alarms for incident detection", Severity: "medium", Integration: "AWS/ISO27001",
		Frameworks: []string{"iso27001"},
		Controls:   []ControlRef{ISO27001("A.16.1.2"), ISO27001("A.12.4.1")}},

	// ── PCI DSS specific ──────────────────────────────────────────────────────
	{ID: "pcidss_inspector_enabled", Title: "AWS Inspector v2 enabled", Severity: "high", Integration: "AWS/PCIDSS",
		Frameworks: []string{"pcidss"},
		Controls:   []ControlRef{PCIDSS("6.3.2"), PCIDSS("11.3.1")}},
	{ID: "pcidss_guardduty_malware", Title: "GuardDuty malware protection enabled", Severity: "critical", Integration: "AWS/PCIDSS",
		Frameworks: []string{"pcidss"},
		Controls:   []ControlRef{PCIDSS("5.2.1"), PCIDSS("5.3.2")}},
	{ID: "pcidss_ebs_encrypted", Title: "All EBS volumes encrypted", Severity: "high", Integration: "AWS/PCIDSS",
		Frameworks: []string{"pcidss"},
		Controls:   []ControlRef{PCIDSS("3.5.1"), PCIDSS("3.7.1")}},
	{ID: "pcidss_vpc_flow_logs", Title: "VPC Flow Logs enabled on all VPCs", Severity: "high", Integration: "AWS/PCIDSS",
		Frameworks: []string{"pcidss"},
		Controls:   []ControlRef{PCIDSS("10.2.1"), PCIDSS("10.3.2")}},
	{ID: "pcidss_ecr_scan_on_push", Title: "ECR repositories scan images on push", Severity: "high", Integration: "AWS/PCIDSS",
		Frameworks: []string{"pcidss"},
		Controls:   []ControlRef{PCIDSS("6.3.2"), PCIDSS("11.3.1")}},

	// ── GitHub ────────────────────────────────────────────────────────────────
	{ID: "github_2fa_required", Title: "2FA required for all org members", Severity: "critical", Integration: "GitHub",
		Frameworks: []string{"soc2", "iso27001", "pcidss"},
		Controls:   []ControlRef{{FrameworkSOC2, "CC6.1"}, ISO27001("A.9.4.2"), PCIDSS("8.4.2")}},
	{ID: "github_branch_protection", Title: "Default branch protection enabled", Severity: "high", Integration: "GitHub",
		Frameworks: []string{"soc2", "iso27001", "pcidss"},
		Controls:   []ControlRef{{FrameworkSOC2, "CC8.1"}, ISO27001("A.12.1.4"), PCIDSS("6.2.4")}},
	{ID: "github_secret_scanning", Title: "Secret scanning enabled", Severity: "critical", Integration: "GitHub",
		Frameworks: []string{"soc2", "iso27001", "pcidss"},
		Controls:   []ControlRef{{FrameworkSOC2, "CC6.1"}, ISO27001("A.9.4.1"), PCIDSS("6.3.2")}},
	{ID: "github_db_credentials", Title: "No database credentials committed to source code", Severity: "critical", Integration: "GitHub",
		Frameworks: []string{"soc2", "hipaa", "iso27001", "pcidss"},
		Controls:   []ControlRef{{FrameworkSOC2, "CC6.1"}, {FrameworkHIPAA, "164.312(a)(2)(iv)"}, ISO27001("A.9.4.3"), PCIDSS("8.3.1")}},

	// ── GCP ───────────────────────────────────────────────────────────────────
	{ID: "gcp_logging_enabled", Title: "Cloud Audit Logging enabled", Severity: "high", Integration: "GCP",
		Frameworks: []string{"soc2", "iso27001", "pcidss"},
		Controls:   []ControlRef{{FrameworkSOC2, "CC7.2"}, ISO27001("A.12.4.1"), PCIDSS("10.2.1")}},
	{ID: "gcp_storage_not_public", Title: "GCS buckets not publicly accessible", Severity: "critical", Integration: "GCP",
		Frameworks: []string{"soc2", "iso27001", "pcidss"},
		Controls:   []ControlRef{{FrameworkSOC2, "CC6.1"}, ISO27001("A.13.1.3"), PCIDSS("1.3.2")}},
	{ID: "gcp_sql_require_ssl", Title: "Cloud SQL requires SSL connections", Severity: "high", Integration: "GCP",
		Frameworks: []string{"soc2", "hipaa", "iso27001", "pcidss"},
		Controls:   []ControlRef{{FrameworkSOC2, "CC6.1"}, ISO27001("A.10.1.1"), PCIDSS("4.2.1")}},

	// ── Kubernetes ────────────────────────────────────────────────────────────
	{ID: "k8s_no_privileged_containers", Title: "No privileged containers running", Severity: "critical", Integration: "Kubernetes",
		Frameworks: []string{"soc2", "iso27001", "pcidss"},
		Controls:   []ControlRef{{FrameworkSOC2, "CC6.1"}, ISO27001("A.13.1.3"), PCIDSS("6.3.1")}},
	{ID: "k8s_rbac_enabled", Title: "RBAC enabled on cluster", Severity: "high", Integration: "Kubernetes",
		Frameworks: []string{"soc2", "iso27001", "pcidss"},
		Controls:   []ControlRef{{FrameworkSOC2, "CC6.3"}, ISO27001("A.9.2.3"), PCIDSS("7.2.1")}},
	{ID: "k8s_network_policies", Title: "Network policies defined", Severity: "high", Integration: "Kubernetes",
		Frameworks: []string{"soc2", "iso27001", "pcidss"},
		Controls:   []ControlRef{{FrameworkSOC2, "CC6.6"}, ISO27001("A.13.1.1"), PCIDSS("1.2.7")}},

	// ── Terraform ─────────────────────────────────────────────────────────────
	{ID: "tf_sg_ssh_restricted", Title: "SSH not open to 0.0.0.0/0 in Terraform", Severity: "critical", Integration: "Terraform",
		Frameworks: []string{"soc2", "cis", "iso27001", "pcidss"},
		Controls:   []ControlRef{{FrameworkSOC2, "CC6.6"}, ISO27001("A.13.1.1"), PCIDSS("1.2.1")}},
	{ID: "tf_rds_encrypted", Title: "RDS storage_encrypted = true in Terraform", Severity: "high", Integration: "Terraform",
		Frameworks: []string{"soc2", "hipaa", "iso27001", "pcidss"},
		Controls:   []ControlRef{{FrameworkSOC2, "CC6.1"}, ISO27001("A.10.1.1"), PCIDSS("3.5.1")}},
	{ID: "tf_remote_backend", Title: "Terraform remote backend configured", Severity: "high", Integration: "Terraform",
		Frameworks: []string{"soc2", "iso27001", "pcidss"},
		Controls:   []ControlRef{{FrameworkSOC2, "CC6.1"}, ISO27001("A.10.1.1"), PCIDSS("3.5.1")}},
	{ID: "tf_no_hardcoded_secrets", Title: "No hardcoded secrets in Terraform", Severity: "critical", Integration: "Terraform",
		Frameworks: []string{"soc2", "hipaa", "iso27001", "pcidss"},
		Controls:   []ControlRef{{FrameworkSOC2, "CC6.1"}, ISO27001("A.9.4.3"), PCIDSS("8.2.1")}},

	// ── Database (comply db scan) ─────────────────────────────────────────────
	{ID: "db_pii_column_detection", Title: "No PII-named columns without documented controls", Severity: "high", Integration: "Database",
		Frameworks: []string{"soc2", "hipaa", "iso27001", "pcidss"},
		Controls:   []ControlRef{{FrameworkSOC2, "CC6.1"}, {FrameworkHIPAA, "164.312(a)(1)"}, ISO27001("A.18.1.4"), PCIDSS("3.3.1")}},
	{ID: "db_pii_data_sampling", Title: "No unencrypted PII in sampled database rows", Severity: "critical", Integration: "Database",
		Frameworks: []string{"soc2", "hipaa", "iso27001", "pcidss"},
		Controls:   []ControlRef{{FrameworkSOC2, "CC6.1"}, {FrameworkHIPAA, "164.312(e)(2)(ii)"}, ISO27001("A.18.1.4"), PCIDSS("3.3.1")}},
	{ID: "db_tls_connection_test", Title: "Database server enforces TLS — no plaintext connections", Severity: "critical", Integration: "Database",
		Frameworks: []string{"soc2", "hipaa", "iso27001", "pcidss"},
		Controls:   []ControlRef{{FrameworkSOC2, "CC6.7"}, {FrameworkHIPAA, "164.312(e)(1)"}, ISO27001("A.10.1.1"), PCIDSS("4.2.1")}},
	{ID: "db_rls_on_pii_tables", Title: "Row Level Security enabled on PII tables", Severity: "high", Integration: "Database",
		Frameworks: []string{"soc2", "hipaa", "iso27001", "pcidss"},
		Controls:   []ControlRef{{FrameworkSOC2, "CC6.3"}, {FrameworkHIPAA, "164.312(a)(1)"}, ISO27001("A.9.1.2"), PCIDSS("7.2.2")}},
	{ID: "db_schema_audit_table", Title: "Audit log table exists in database schema", Severity: "medium", Integration: "Database",
		Frameworks: []string{"soc2", "hipaa", "iso27001", "pcidss"},
		Controls:   []ControlRef{{FrameworkSOC2, "CC7.2"}, {FrameworkHIPAA, "164.312(b)"}, ISO27001("A.12.4.1"), PCIDSS("10.2.1")}}}
