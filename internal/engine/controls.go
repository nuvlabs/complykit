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

	// ── AWS ECR (additional) ──────────────────────────────────────────────────
	"aws_ecr_lifecycle_policy": {ISO27001("A.12.3.1"), PCIDSS("6.3.2")},
	"aws_ecr_repo_not_public":  {ISO27001("A.13.1.3"), PCIDSS("1.3.2")},

	// ── AWS ALB / WAF ─────────────────────────────────────────────────────────
	"aws_alb_https_only": {ISO27001("A.10.1.1"), PCIDSS("4.2.1")},

	// ── AWS Backup / Lambda / Route53 / Org ──────────────────────────────────
	"aws_backup_vault":          {ISO27001("A.12.3.1"), PCIDSS("12.3.4")},
	"aws_lambda_public_url":     {ISO27001("A.13.1.3"), PCIDSS("1.3.2")},
	"aws_route53_dnssec":        {ISO27001("A.10.1.1"), PCIDSS("4.2.1")},
	"aws_org_scp":               {ISO27001("A.9.2.3"),  PCIDSS("7.2.1")},
	"aws_cw_log_metric_filters": {ISO27001("A.12.4.1"), PCIDSS("10.2.1")},

	// ── AWS EKS (additional) ──────────────────────────────────────────────────
	"aws_eks_pod_security":   {ISO27001("A.13.1.3"), PCIDSS("6.3.1")},
	"aws_eks_anonymous_auth": {ISO27001("A.9.2.3"),  PCIDSS("7.2.1")},

	// ── GCP (main check IDs used by checkers) ────────────────────────────────
	"gcp_audit_logs":           {ISO27001("A.12.4.1"), PCIDSS("10.2.1")},
	"gcp_iam_sa_keys":          {ISO27001("A.9.2.3"),  PCIDSS("8.2.9")},
	"gcp_org_domain_restrict":  {ISO27001("A.9.1.2"),  PCIDSS("7.2.3")},
	"gcp_gcs_public_access":    {ISO27001("A.13.1.3"), PCIDSS("1.3.2")},
	"gcp_gcs_uniform_iam":      {ISO27001("A.13.1.3"), PCIDSS("1.3.2")},
	"gcp_gcs_versioning":       {ISO27001("A.12.3.1"), PCIDSS("12.3.4")},
	"gcp_gcs_logging":          {ISO27001("A.12.4.1"), PCIDSS("10.2.1")},
	"gcp_gcs_cmek":             {ISO27001("A.10.1.1"), PCIDSS("3.5.1")},
	"gcp_cloudsql_ssl":         {ISO27001("A.10.1.1"), PCIDSS("4.2.1")},
	"gcp_cloudsql_public_ip":   {ISO27001("A.13.1.3"), PCIDSS("1.3.2")},
	"gcp_cloudsql_backup":      {ISO27001("A.12.3.1"), PCIDSS("12.3.4")},
	"gcp_firewall_ssh":         {ISO27001("A.13.1.1"), PCIDSS("1.2.1")},
	"gcp_firewall_rdp":         {ISO27001("A.13.1.1"), PCIDSS("1.2.1")},
	"gcp_vpc_flow_logs":        {ISO27001("A.12.4.1"), PCIDSS("10.2.1")},
	"gcp_no_default_network":   {ISO27001("A.13.1.1"), PCIDSS("1.2.7")},
	"gcp_vm_os_login":          {ISO27001("A.9.2.3"),  PCIDSS("8.2.1")},
	"gcp_vm_project_ssh_keys":  {ISO27001("A.9.2.3"),  PCIDSS("8.2.1")},
	"gcp_vm_serial_port":       {ISO27001("A.13.1.1"), PCIDSS("1.2.1")},
	"gcp_vm_shielded":          {ISO27001("A.13.1.3"), PCIDSS("6.3.1")},
	"gcp_gke_private_cluster":  {ISO27001("A.13.1.3"), PCIDSS("1.3.2")},
	"gcp_gke_workload_identity":{ISO27001("A.9.2.3"),  PCIDSS("8.2.1")},
	"gcp_gke_shielded_nodes":   {ISO27001("A.13.1.3"), PCIDSS("6.3.1")},
	"gcp_gke_legacy_metadata":  {ISO27001("A.13.1.3"), PCIDSS("1.3.2")},
	"gcp_gke_auto_upgrade":     {ISO27001("A.12.6.1"), PCIDSS("6.3.3")},
	"gcp_gke_binary_auth":      {ISO27001("A.12.5.1"), PCIDSS("6.3.2")},
	"gcp_gke_intranode_visibility":{ISO27001("A.13.1.1"), PCIDSS("1.2.7")},
	"gcp_gke_release_channel":  {ISO27001("A.12.6.1"), PCIDSS("6.3.3")},
	"gcp_gke_master_auth_networks":{ISO27001("A.13.1.3"), PCIDSS("1.3.2")},
	"gcp_iam_primitive_roles":  {ISO27001("A.9.2.3"),  PCIDSS("7.2.1")},
	"gcp_iam_gmail":            {ISO27001("A.9.2.2"),  PCIDSS("8.2.1")},
	"gcp_iam_sa_owner":         {ISO27001("A.9.2.3"),  PCIDSS("7.2.1")},
	"gcp_iam_sa_key_age":       {ISO27001("A.9.4.3"),  PCIDSS("8.2.9")},
	"gcp_log_sink":             {ISO27001("A.12.4.1"), PCIDSS("10.2.1")},
	"gcp_log_metric_ownership": {ISO27001("A.12.4.1"), PCIDSS("10.2.1")},
	"gcp_log_metric_audit_config":{ISO27001("A.12.4.1"), PCIDSS("10.2.1")},
	"gcp_log_metric_custom_role":{ISO27001("A.12.4.1"), PCIDSS("10.2.1")},

	// ── GCP P2/P3 ─────────────────────────────────────────────────────────────
	"gcp_dns_logging":           {ISO27001("A.12.4.1"), PCIDSS("10.2.1")},
	"gcp_bigquery_public":       {ISO27001("A.13.1.3"), PCIDSS("1.3.2")},
	"gcp_artifact_registry_scan":{ISO27001("A.12.6.1"), PCIDSS("6.3.2")},
	"gcp_cloudsql_cmek":         {ISO27001("A.10.1.1"), PCIDSS("3.5.1")},
	"gcp_gke_database_encryption":{ISO27001("A.10.1.1"), PCIDSS("3.5.1")},
	"gcp_kms_key_rotation":      {ISO27001("A.10.1.2"), PCIDSS("3.7.4")},
	"gcp_vm_disk_cmek":          {ISO27001("A.10.1.1"), PCIDSS("3.5.1")},
	"gcp_scc_enabled":           {ISO27001("A.16.1.2"), PCIDSS("10.7.1")},

	// ── Azure (all check IDs used by checkers) ────────────────────────────────
	"az_storage_https":           {ISO27001("A.10.1.1"), PCIDSS("4.2.1")},
	"az_storage_public":          {ISO27001("A.13.1.3"), PCIDSS("1.3.2")},
	"az_storage_tls":             {ISO27001("A.10.1.1"), PCIDSS("4.2.1")},
	"az_storage_soft_delete":     {ISO27001("A.12.3.1"), PCIDSS("12.3.4")},
	"az_storage_infra_encryption":{ISO27001("A.10.1.1"), PCIDSS("3.5.1")},
	"az_nsg_rdp":                 {ISO27001("A.13.1.1"), PCIDSS("1.2.1")},
	"az_nsg_ssh":                 {ISO27001("A.13.1.1"), PCIDSS("1.2.1")},
	"az_nsg_flow_logs":           {ISO27001("A.12.4.1"), PCIDSS("10.2.1")},
	"az_disk_encryption":         {ISO27001("A.10.1.1"), PCIDSS("3.5.1")},
	"az_vm_backup":               {ISO27001("A.12.3.1"), PCIDSS("12.3.4")},
	"az_vm_trusted_launch":       {ISO27001("A.13.1.3"), PCIDSS("6.3.1")},
	"az_defender":                {ISO27001("A.16.1.2"), PCIDSS("10.7.1")},
	"az_aks_defender_containers": {ISO27001("A.16.1.2"), PCIDSS("10.7.1")},
	"az_activity_logs":           {ISO27001("A.12.4.1"), PCIDSS("10.2.1")},
	"az_activity_log_retention":  {ISO27001("A.12.4.1"), PCIDSS("10.2.1")},
	"az_log_alerts":              {ISO27001("A.16.1.2"), PCIDSS("10.7.1")},
	"az_sql_auditing":            {ISO27001("A.12.4.1"), PCIDSS("10.2.1")},
	"az_sql_tde":                 {ISO27001("A.10.1.1"), PCIDSS("3.5.1")},
	"az_sql_threat":              {ISO27001("A.16.1.2"), PCIDSS("10.7.1")},
	"az_sql_firewall":            {ISO27001("A.13.1.1"), PCIDSS("1.2.1")},
	"az_sql_audit_retention":     {ISO27001("A.12.4.1"), PCIDSS("10.2.1")},
	"az_sql_vuln_assessment":     {ISO27001("A.12.6.1"), PCIDSS("11.3.1")},
	"az_keyvault_soft_delete":    {ISO27001("A.12.3.1"), PCIDSS("12.3.4")},
	"az_keyvault_purge_protection":{ISO27001("A.12.3.1"), PCIDSS("12.3.4")},
	"az_keyvault_key_expiry":     {ISO27001("A.10.1.2"), PCIDSS("3.7.4")},
	"az_aks_rbac":                {ISO27001("A.9.2.3"),  PCIDSS("7.2.1")},
	"az_aks_aad":                 {ISO27001("A.9.2.3"),  PCIDSS("8.2.1")},
	"az_aks_network_policy":      {ISO27001("A.13.1.1"), PCIDSS("1.2.7")},
	"az_aks_private_cluster":     {ISO27001("A.13.1.3"), PCIDSS("1.3.2")},
	"az_aks_node_auto_upgrade":   {ISO27001("A.12.6.1"), PCIDSS("6.3.3")},
	"az_aks_csi_secrets":         {ISO27001("A.9.4.3"),  PCIDSS("8.3.1")},
	"az_mfa_conditional_access":  {ISO27001("A.9.4.2"),  PCIDSS("8.4.2")},
	"az_no_guest_admin":          {ISO27001("A.9.2.3"),  PCIDSS("7.2.1")},
	"az_pim_enabled":             {ISO27001("A.9.2.5"),  PCIDSS("7.2.1")},
	"az_network_watcher_all_regions":{ISO27001("A.12.4.1"), PCIDSS("10.2.1")},

	// ── Kubernetes (all check IDs used by checkers) ───────────────────────────
	"k8s_privileged":           {ISO27001("A.13.1.3"), PCIDSS("6.3.1")},
	"k8s_root_user":            {ISO27001("A.9.2.3"),  PCIDSS("7.2.1")},
	"k8s_host_network":         {ISO27001("A.13.1.3"), PCIDSS("1.3.2")},
	"k8s_host_pid":             {ISO27001("A.13.1.3"), PCIDSS("6.3.1")},
	"k8s_host_ipc":             {ISO27001("A.13.1.3"), PCIDSS("6.3.1")},
	"k8s_host_namespace":       {ISO27001("A.13.1.3"), PCIDSS("6.3.1")},
	"k8s_resource_limits":      {ISO27001("A.13.1.3"), PCIDSS("6.3.1")},
	"k8s_readonly_rootfs":      {ISO27001("A.13.1.3"), PCIDSS("6.3.1")},
	"k8s_cluster_admin":        {ISO27001("A.9.2.3"),  PCIDSS("7.2.1")},
	"k8s_wildcard_roles":       {ISO27001("A.9.2.3"),  PCIDSS("7.2.1")},
	"k8s_sa_token_automount":   {ISO27001("A.9.2.3"),  PCIDSS("7.2.1")},
	"k8s_bind_escalate":        {ISO27001("A.9.2.3"),  PCIDSS("7.2.1")},
	"k8s_default_deny":         {ISO27001("A.13.1.1"), PCIDSS("1.2.7")},
	"k8s_privilege_escalation": {ISO27001("A.13.1.3"), PCIDSS("6.3.1")},
	"k8s_capability_drop":      {ISO27001("A.13.1.3"), PCIDSS("6.3.1")},
	"k8s_hostpath_mounts":      {ISO27001("A.13.1.3"), PCIDSS("6.3.1")},
	"k8s_seccomp":              {ISO27001("A.13.1.3"), PCIDSS("6.3.1")},
	"k8s_psa":                  {ISO27001("A.13.1.3"), PCIDSS("6.3.1")},
	"k8s_secrets_env_vars":     {ISO27001("A.9.4.3"),  PCIDSS("8.3.1")},
	"k8s_image_pull_always":    {ISO27001("A.12.5.1"), PCIDSS("6.3.2")},
	"k8s_non_root_uid":         {ISO27001("A.9.2.3"),  PCIDSS("7.2.1")},
	"k8s_resource_requests":    {ISO27001("A.13.1.3"), PCIDSS("6.3.1")},
	"k8s_image_registry":       {ISO27001("A.12.5.1"), PCIDSS("6.3.2")},
	"k8s_etcd_encryption":      {ISO27001("A.10.1.1"), PCIDSS("3.5.1")},
	"k8s_opa_gatekeeper":       {ISO27001("A.13.1.3"), PCIDSS("6.3.1")},
	"k8s_apparmor":             {ISO27001("A.13.1.3"), PCIDSS("6.3.1")},
	"k8s_external_secrets":     {ISO27001("A.9.4.3"),  PCIDSS("8.3.1")},
	"k8s_audit_logging":        {ISO27001("A.12.4.1"), PCIDSS("10.2.1")},
	"k8s_falco":                {ISO27001("A.16.1.2"), PCIDSS("10.7.1")},

	// ── GitHub (all check IDs used by checkers) ───────────────────────────────
	"github_public_repos":          {ISO27001("A.13.1.3"), PCIDSS("1.3.2")},
	"github_dependabot":            {ISO27001("A.12.6.1"), PCIDSS("6.3.2")},
	"github_org_2fa":               {ISO27001("A.9.4.2"),  PCIDSS("8.4.2")},
	"github_org_sso":               {ISO27001("A.9.4.2"),  PCIDSS("8.4.2")},
	"github_org_outside_collab":    {ISO27001("A.9.2.2"),  PCIDSS("7.2.1")},
	"github_push_protection":       {ISO27001("A.9.4.1"),  PCIDSS("6.3.2")},
	"github_token_permissions":     {ISO27001("A.9.2.3"),  PCIDSS("7.2.1")},
	"github_no_self_hosted_public": {ISO27001("A.13.1.3"), PCIDSS("1.3.2")},
	"github_actions_pinned":        {ISO27001("A.12.5.1"), PCIDSS("6.3.2")},
	"github_actions_prt":           {ISO27001("A.12.1.4"), PCIDSS("6.2.4")},
	"github_env_protection":        {ISO27001("A.12.1.4"), PCIDSS("6.2.4")},
	"github_codeowners":            {ISO27001("A.9.2.2"),  PCIDSS("6.2.4")},
	"github_dependabot_alerts":     {ISO27001("A.12.6.1"), PCIDSS("6.3.2")},
	"github_branch_dismiss_stale":  {ISO27001("A.12.1.4"), PCIDSS("6.2.4")},
	"github_oidc_cloud_auth":       {ISO27001("A.9.4.3"),  PCIDSS("8.3.1")},
	"github_verified_domains":      {ISO27001("A.9.1.2"),  PCIDSS("7.2.3")},
	"github_org_ip_allowlist":      {ISO27001("A.9.1.2"),  PCIDSS("1.3.2")},
	"github_secret_rotation":       {ISO27001("A.9.4.3"),  PCIDSS("8.3.9")},
	"github_required_status_checks":{ISO27001("A.12.1.4"), PCIDSS("6.2.4")},

	// ── Aliases (actual checker IDs → same controls as canonical entries) ────
	"aws_kms_rotation":            {ISO27001("A.10.1.2"), PCIDSS("3.7.4")},
	"aws_sg_open_ssh":             {ISO27001("A.13.1.1"), PCIDSS("1.2.1")},
	"aws_sg_open_rdp":             {ISO27001("A.13.1.1"), PCIDSS("1.2.1")},
	"aws_sg_unrestricted_ports":   {ISO27001("A.13.1.1"), PCIDSS("1.2.2")},
	"aws_sg_default_restricted":   {ISO27001("A.13.1.1"), PCIDSS("1.2.7")},
	"aws_vpc_flow_logs":           {ISO27001("A.12.4.1"), PCIDSS("10.2.1")},
	"aws_ebs_encryption":          {ISO27001("A.10.1.1"), PCIDSS("3.5.1")},
	"aws_efs_encryption":          {ISO27001("A.10.1.1"), PCIDSS("3.5.1")},
	"aws_cloudtrail_log_validation":{ISO27001("A.12.4.2"), PCIDSS("10.5.2")},
	"aws_eks_endpoint_public":     {ISO27001("A.13.1.3"), PCIDSS("1.3.2")},
	"aws_eks_secrets_encryption":  {ISO27001("A.10.1.1"), PCIDSS("3.5.1")},
	"aws_eks_imdsv2":              {ISO27001("A.13.1.3"), PCIDSS("6.3.3")},
	"aws_ecr_vulnerabilities":     {ISO27001("A.12.6.1"), PCIDSS("6.3.2")},
	"aws_rds_public_snapshot":     {ISO27001("A.13.1.3"), PCIDSS("1.3.2")},
	"aws_secrets_manager":         {ISO27001("A.9.4.3"),  PCIDSS("8.3.1")},
	"aws_securityhub_enabled":     {ISO27001("A.16.1.2"), PCIDSS("10.7.1")},
	"aws_inspector_enabled":       {ISO27001("A.12.6.1"), PCIDSS("6.3.2")},
	"aws_sns_topics":              {ISO27001("A.12.4.1"), PCIDSS("10.2.1")},
	"aws_cw_alarm_root_login":     {ISO27001("A.12.4.1"), PCIDSS("10.2.1.1")},
	"aws_cw_alarm_unauth_api":     {ISO27001("A.12.4.1"), PCIDSS("10.2.1.3")},
	"aws_cw_alarm_no_mfa_console": {ISO27001("A.9.4.2"),  PCIDSS("10.2.1.2")},
	"aws_cw_alarm_iam_policy_change":{ISO27001("A.12.4.1"), PCIDSS("10.2.1")},

	// ── Policy / Cross-cutting ────────────────────────────────────────────────
	"cross_backup_restore_test": {ISO27001("A.12.3.1"), PCIDSS("12.3.4")},
	"cross_incident_response":   {ISO27001("A.16.1.5"), PCIDSS("12.10.1")},
	"cross_pen_test":            {ISO27001("A.18.2.3"), PCIDSS("11.4.1")},
	"cross_data_classification": {ISO27001("A.8.2.1"),  PCIDSS("3.3.1")},
	"cross_vendor_risk":         {ISO27001("A.15.1.1"), PCIDSS("12.8.1")},
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
