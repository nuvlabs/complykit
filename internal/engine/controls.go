package engine

// ISO27001 returns a ControlRef for ISO/IEC 27001:2022.
func ISO27001(id string) ControlRef {
	return ControlRef{Framework: FrameworkISO27001, ID: id}
}

// PCIDSS returns a ControlRef for PCI DSS v4.0.
func PCIDSS(id string) ControlRef {
	return ControlRef{Framework: FrameworkPCIDSS, ID: id}
}

// ControlMap maps a check ID to its ISO 27001 and PCI DSS control references.
// All existing checks are enriched here without touching individual checker files.
var ControlMap = map[string][]ControlRef{
	// ── AWS IAM ──────────────────────────────────────────────────────────────
	"aws_iam_root_mfa":              {ISO27001("A.9.4.2"), PCIDSS("8.4.2")},
	"aws_iam_root_access_keys":      {ISO27001("A.9.2.3"), PCIDSS("7.2.1")},
	"aws_iam_root_hardware_mfa":     {ISO27001("A.9.4.2"), PCIDSS("8.4.2")},
	"aws_iam_password_policy":       {ISO27001("A.9.4.1"), PCIDSS("8.3.6")},
	"aws_iam_unused_credentials":    {ISO27001("A.9.2.5"), PCIDSS("8.2.6")},
	"aws_iam_access_key_rotation":   {ISO27001("A.9.4.3"), PCIDSS("8.2.9")},
	"aws_iam_console_mfa":           {ISO27001("A.9.4.2"), PCIDSS("8.4.2")},
	"aws_iam_no_direct_admin":       {ISO27001("A.9.2.3"), PCIDSS("7.2.1")},
	"aws_iam_users_in_groups":       {ISO27001("A.9.2.2"), PCIDSS("7.2.1")},
	"aws_iam_support_role":          {ISO27001("A.6.1.2"), PCIDSS("12.5.1")},
	"aws_iam_access_analyzer":       {ISO27001("A.9.1.2"), PCIDSS("7.2.3")},
	"aws_iam_one_key_per_user":      {ISO27001("A.9.2.3"), PCIDSS("8.2.1")},

	// ── AWS S3 ───────────────────────────────────────────────────────────────
	"aws_s3_account_public_block":   {ISO27001("A.13.1.3"), PCIDSS("1.3.2")},
	"aws_s3_public_access_block":    {ISO27001("A.13.1.3"), PCIDSS("1.3.2")},
	"aws_s3_encryption":             {ISO27001("A.10.1.1"), PCIDSS("3.5.1")},
	"aws_s3_versioning":             {ISO27001("A.12.3.1"), PCIDSS("12.3.4")},
	"aws_s3_logging":                {ISO27001("A.12.4.1"), PCIDSS("10.2.1")},
	"aws_s3_mfa_delete":             {ISO27001("A.12.3.1"), PCIDSS("10.5.2")},

	// ── AWS CloudTrail ────────────────────────────────────────────────────────
	"aws_cloudtrail_enabled":        {ISO27001("A.12.4.1"), PCIDSS("10.2.1")},
	"aws_ct_cloudwatch":             {ISO27001("A.12.4.1"), PCIDSS("10.4.1")},
	"aws_ct_s3_public":              {ISO27001("A.12.4.2"), PCIDSS("10.5.1")},
	"aws_ct_s3_encrypted":           {ISO27001("A.10.1.1"), PCIDSS("10.5.1")},
	"aws_ct_log_validation":         {ISO27001("A.12.4.2"), PCIDSS("10.5.2")},
	"aws_ct_all_regions":            {ISO27001("A.12.4.1"), PCIDSS("10.2.1")},

	// ── AWS Security Groups ───────────────────────────────────────────────────
	"aws_sg_no_open_ssh":            {ISO27001("A.13.1.1"), PCIDSS("1.2.1")},
	"aws_sg_no_open_rdp":            {ISO27001("A.13.1.1"), PCIDSS("1.2.1")},
	"aws_sg_no_open_all":            {ISO27001("A.13.1.1"), PCIDSS("1.2.2")},
	"aws_sg_default_restrict":       {ISO27001("A.13.1.1"), PCIDSS("1.2.7")},

	// ── AWS KMS ───────────────────────────────────────────────────────────────
	"aws_kms_key_rotation":          {ISO27001("A.10.1.2"), PCIDSS("3.7.4")},
	"aws_kms_no_public_key":         {ISO27001("A.10.1.1"), PCIDSS("3.7.1")},

	// ── AWS RDS ───────────────────────────────────────────────────────────────
	"aws_rds_encryption":            {ISO27001("A.10.1.1"), PCIDSS("3.5.1")},
	"aws_rds_not_public":            {ISO27001("A.13.1.3"), PCIDSS("1.3.2")},
	"aws_rds_ssl_enforcement":       {ISO27001("A.10.1.1"), PCIDSS("4.2.1")},
	"aws_rds_backup":                {ISO27001("A.12.3.1"), PCIDSS("12.3.4")},
	"aws_rds_multi_az":              {ISO27001("A.17.2.1"), PCIDSS("12.3.4")},
	"aws_rds_deletion_protection":   {ISO27001("A.12.3.1"), PCIDSS("12.3.4")},
	"aws_rds_minor_upgrade":         {ISO27001("A.12.6.1"), PCIDSS("6.3.3")},
	"aws_rds_iam_auth":              {ISO27001("A.9.2.3"),  PCIDSS("8.2.1")},

	// ── AWS EC2 Database ──────────────────────────────────────────────────────
	"aws_ec2_db_ebs_encrypted":      {ISO27001("A.10.1.1"), PCIDSS("3.5.1")},
	"aws_ec2_db_no_public_ip":       {ISO27001("A.13.1.3"), PCIDSS("1.3.2")},
	"aws_ec2_db_sg_exposure":        {ISO27001("A.13.1.1"), PCIDSS("1.2.1")},
	"aws_ec2_db_cloudwatch_logs":    {ISO27001("A.12.4.1"), PCIDSS("10.2.1")},

	// ── AWS RDS Audit ─────────────────────────────────────────────────────────
	"aws_rds_audit_logging":         {ISO27001("A.12.4.1"), PCIDSS("10.2.1")},
	"aws_cloudtrail_rds_events":     {ISO27001("A.12.4.1"), PCIDSS("10.2.1")},

	// ── Kubernetes DB Audit ───────────────────────────────────────────────────
	"k8s_db_audit_logging":          {ISO27001("A.12.4.1"), PCIDSS("10.2.1")},

	// ── AWS DB Access ─────────────────────────────────────────────────────────
	"aws_rds_overprivileged_iam":    {ISO27001("A.9.2.3"),  PCIDSS("7.2.1")},
	"aws_rds_no_master_user_exposed":{ISO27001("A.9.2.3"),  PCIDSS("8.2.1")},

	// ── AWS ECR ───────────────────────────────────────────────────────────────
	"aws_ecr_scan_on_push":          {ISO27001("A.12.6.1"), PCIDSS("6.3.2")},
	"aws_ecr_immutable_tags":        {ISO27001("A.12.5.1"), PCIDSS("6.3.2")},
	"aws_ecr_not_public":            {ISO27001("A.13.1.3"), PCIDSS("1.3.2")},

	// ── AWS EKS ───────────────────────────────────────────────────────────────
	"aws_eks_secrets_encrypted":     {ISO27001("A.10.1.1"), PCIDSS("3.5.1")},
	"aws_eks_public_endpoint":       {ISO27001("A.13.1.3"), PCIDSS("1.3.2")},
	"aws_eks_logging":               {ISO27001("A.12.4.1"), PCIDSS("10.2.1")},

	// ── AWS GuardDuty ─────────────────────────────────────────────────────────
	"aws_guardduty_enabled":         {ISO27001("A.16.1.2"), PCIDSS("10.7.1")},

	// ── AWS Config ────────────────────────────────────────────────────────────
	"aws_config_enabled":            {ISO27001("A.12.4.1"), PCIDSS("10.2.1")},

	// ── AWS CloudWatch ────────────────────────────────────────────────────────
	"aws_cloudwatch_root_usage":     {ISO27001("A.9.2.3"), PCIDSS("10.2.1.1")},
	"aws_cloudwatch_unauth_api":     {ISO27001("A.12.4.1"), PCIDSS("10.2.1.3")},
	"aws_cloudwatch_console_nfa":    {ISO27001("A.9.4.2"), PCIDSS("10.2.1.2")},

	// ── AWS WAF ───────────────────────────────────────────────────────────────
	"aws_waf_enabled":               {ISO27001("A.13.1.1"), PCIDSS("6.4.1")},

	// ── GCP ───────────────────────────────────────────────────────────────────
	"gcp_iam_service_account_keys":  {ISO27001("A.9.4.3"), PCIDSS("8.2.9")},
	"gcp_iam_no_user_managed_keys":  {ISO27001("A.9.2.3"), PCIDSS("8.2.1")},
	"gcp_logging_enabled":           {ISO27001("A.12.4.1"), PCIDSS("10.2.1")},
	"gcp_storage_not_public":        {ISO27001("A.13.1.3"), PCIDSS("1.3.2")},
	"gcp_compute_serial_port":       {ISO27001("A.13.1.1"), PCIDSS("1.2.1")},
	"gcp_sql_require_ssl":           {ISO27001("A.10.1.1"), PCIDSS("4.2.1")},
	"gcp_sql_no_public_ip":          {ISO27001("A.13.1.3"), PCIDSS("1.3.2")},
	"gcp_gke_private_nodes":         {ISO27001("A.13.1.3"), PCIDSS("1.3.2")},
	"gcp_gke_network_policy":        {ISO27001("A.13.1.1"), PCIDSS("1.2.7")},

	// ── GitHub ────────────────────────────────────────────────────────────────
	"github_2fa_required":           {ISO27001("A.9.4.2"), PCIDSS("8.4.2")},
	"github_branch_protection":      {ISO27001("A.12.1.4"), PCIDSS("6.2.4")},
	"github_secret_scanning":        {ISO27001("A.9.4.1"), PCIDSS("6.3.2")},
	"github_code_scanning":          {ISO27001("A.12.6.1"), PCIDSS("6.3.2")},
	"github_private_repos":          {ISO27001("A.13.1.3"), PCIDSS("1.3.2")},
	"github_signed_commits":         {ISO27001("A.12.4.3"), PCIDSS("10.5.2")},
	"github_db_credentials":         {ISO27001("A.9.4.3"), PCIDSS("8.3.1")},

	// ── Terraform ─────────────────────────────────────────────────────────────
	"tf_s3_no_public_acl":           {ISO27001("A.13.1.3"), PCIDSS("1.3.2")},
	"tf_s3_public_access_block":     {ISO27001("A.13.1.3"), PCIDSS("1.3.2")},
	"tf_s3_encryption":              {ISO27001("A.10.1.1"), PCIDSS("3.5.1")},
	"tf_s3_versioning":              {ISO27001("A.12.3.1"), PCIDSS("12.3.4")},
	"tf_sg_ssh_restricted":          {ISO27001("A.13.1.1"), PCIDSS("1.2.1")},
	"tf_sg_rdp_restricted":          {ISO27001("A.13.1.1"), PCIDSS("1.2.1")},
	"tf_sg_no_open_all":             {ISO27001("A.13.1.1"), PCIDSS("1.2.2")},
	"tf_rds_not_public":             {ISO27001("A.13.1.3"), PCIDSS("1.3.2")},
	"tf_rds_encrypted":              {ISO27001("A.10.1.1"), PCIDSS("3.5.1")},
	"tf_rds_deletion_protection":    {ISO27001("A.12.3.1"), PCIDSS("12.3.4")},
	"tf_ec2_imdsv2":                 {ISO27001("A.13.1.3"), PCIDSS("6.3.3")},
	"tf_remote_backend":             {ISO27001("A.10.1.1"), PCIDSS("3.5.1")},
	"tf_no_hardcoded_secrets":       {ISO27001("A.9.4.3"), PCIDSS("8.2.1")},

	// ── Kubernetes ────────────────────────────────────────────────────────────
	"k8s_no_privileged_containers":  {ISO27001("A.13.1.3"), PCIDSS("6.3.1")},
	"k8s_network_policies":          {ISO27001("A.13.1.1"), PCIDSS("1.2.7")},
	"k8s_rbac_enabled":              {ISO27001("A.9.2.3"),  PCIDSS("7.2.1")},
	"k8s_no_host_network":           {ISO27001("A.13.1.3"), PCIDSS("1.3.2")},
	"k8s_image_policy":              {ISO27001("A.12.5.1"), PCIDSS("6.3.2")},
	"k8s_db_pvc_encrypted":          {ISO27001("A.10.1.1"), PCIDSS("3.5.1")},
	"k8s_db_no_public_service":      {ISO27001("A.13.1.3"), PCIDSS("1.3.2")},
	"k8s_db_not_root":               {ISO27001("A.9.2.3"),  PCIDSS("7.2.1")},
	"k8s_db_secret_not_configmap":   {ISO27001("A.9.4.3"),  PCIDSS("8.3.1")},

	// ── Terraform Database ────────────────────────────────────────────────────
	"tf_rds_ssl_mode":               {ISO27001("A.10.1.1"), PCIDSS("4.2.1")},
	"tf_db_hardcoded_password":      {ISO27001("A.9.4.3"), PCIDSS("8.3.1")},

	// ── AWS Secrets Manager ───────────────────────────────────────────────────
	"aws_secrets_manager_rotation":  {ISO27001("A.9.4.3"), PCIDSS("8.3.9")},

	// ── Database (comply db scan) ─────────────────────────────────────────────
	"db_pii_column_detection": {ISO27001("A.18.1.4"), PCIDSS("3.3.1")},
	"db_pii_data_sampling":    {ISO27001("A.18.1.4"), PCIDSS("3.3.1")},
	"db_tls_connection_test":  {ISO27001("A.10.1.1"), PCIDSS("4.2.1")},
	"db_rls_on_pii_tables":    {ISO27001("A.9.1.2"),  PCIDSS("7.2.2")},
	"db_schema_audit_table":   {ISO27001("A.12.4.1"), PCIDSS("10.2.1")},
	"db_default_accounts":     {ISO27001("A.9.2.3"),  PCIDSS("8.2.1")},
	"db_unused_accounts":      {ISO27001("A.9.2.5"),  PCIDSS("8.2.6")},

	// ── AWS Macie ─────────────────────────────────────────────────────────────
	"aws_macie_enabled":   {ISO27001("A.18.1.4"), PCIDSS("3.3.1")},
	"aws_macie_findings":  {ISO27001("A.18.1.4"), PCIDSS("3.3.1")},

	// ── GCP DLP ───────────────────────────────────────────────────────────────
	"gcp_dlp_job_active":  {ISO27001("A.18.1.4"), PCIDSS("3.3.1")},
}

// EnrichWithFrameworks adds ISO 27001 and PCI DSS controls to a finding
// based on ControlMap, without modifying existing controls.
func EnrichWithFrameworks(f *Finding) {
	extra, ok := ControlMap[f.CheckID]
	if !ok {
		return
	}
	existing := map[string]bool{}
	for _, c := range f.Controls {
		existing[string(c.Framework)+":"+c.ID] = true
	}
	for _, c := range extra {
		key := string(c.Framework) + ":" + c.ID
		if !existing[key] {
			f.Controls = append(f.Controls, c)
		}
	}
}
