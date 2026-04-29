package aws

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/complykit/complykit/internal/engine"
)

type RDSChecker struct {
	client *rds.Client
}

func NewRDSChecker(cfg aws.Config) *RDSChecker {
	return &RDSChecker{
		client: rds.NewFromConfig(cfg),
	}
}

func (c *RDSChecker) Integration() string { return "AWS/RDS" }

func (c *RDSChecker) Run() ([]engine.Finding, error) {
	var findings []engine.Finding
	findings = append(findings, c.checkEncryption()...)
	findings = append(findings, c.checkNoPublicAccess()...)
	findings = append(findings, c.checkSSLEnforcement()...)
	findings = append(findings, c.checkDeletionProtection()...)
	findings = append(findings, c.checkAutomatedBackups()...)
	findings = append(findings, c.checkIAMAuth()...)
	findings = append(findings, c.checkMultiAZ()...)
	findings = append(findings, c.checkMinorVersionUpgrade()...)
	findings = append(findings, c.checkMasterUsername()...)
	findings = append(findings, c.checkAuditLogging()...)
	return findings, nil
}

func (c *RDSChecker) checkEncryption() []engine.Finding {
	paginator := rds.NewDescribeDBInstancesPaginator(c.client, &rds.DescribeDBInstancesInput{})
	var unencrypted []string
	hasInstances := false

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.Background())
		if err != nil {
			return []engine.Finding{skip("aws_rds_encryption", "RDS Encryption at Rest", err.Error())}
		}
		for _, db := range page.DBInstances {
			hasInstances = true
			if !aws.ToBool(db.StorageEncrypted) {
				unencrypted = append(unencrypted, aws.ToString(db.DBInstanceIdentifier))
			}
		}
	}

	if !hasInstances {
		return []engine.Finding{pass("aws_rds_encryption", "No RDS instances found", "AWS/RDS", "account",
			soc2("CC6.7"), hipaa("164.312(a)(2)(iv)"), cis("2.3.1"))}
	}
	if len(unencrypted) == 0 {
		return []engine.Finding{pass("aws_rds_encryption", "All RDS instances have encryption at rest enabled", "AWS/RDS", "instances",
			soc2("CC6.7"), hipaa("164.312(a)(2)(iv)"), cis("2.3.1"))}
	}
	return []engine.Finding{fail(
		"aws_rds_encryption",
		fmt.Sprintf("%d RDS instance(s) without encryption at rest: %v", len(unencrypted), truncateList(unencrypted, 5)),
		"AWS/RDS", fmt.Sprintf("%d instances", len(unencrypted)), SeverityHigh,
		"RDS encryption must be enabled at creation time. To remediate:\n  1. Take a snapshot of the unencrypted instance\n  2. Copy the snapshot with encryption enabled\n  3. Restore from the encrypted snapshot\n  4. Switch traffic and delete old instance",
		soc2("CC6.7"), hipaa("164.312(a)(2)(iv)"), cis("2.3.1"),
	)}
}

func (c *RDSChecker) checkNoPublicAccess() []engine.Finding {
	paginator := rds.NewDescribeDBInstancesPaginator(c.client, &rds.DescribeDBInstancesInput{})
	var public []string
	hasInstances := false

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.Background())
		if err != nil {
			return []engine.Finding{skip("aws_rds_not_public", "RDS Public Access", err.Error())}
		}
		for _, db := range page.DBInstances {
			hasInstances = true
			if aws.ToBool(db.PubliclyAccessible) {
				public = append(public, aws.ToString(db.DBInstanceIdentifier))
			}
		}
	}

	if !hasInstances {
		return nil
	}
	if len(public) == 0 {
		return []engine.Finding{pass("aws_rds_not_public", "No RDS instances are publicly accessible", "AWS/RDS", "instances",
			soc2("CC6.1"), cis("2.3.3"))}
	}
	return []engine.Finding{fail(
		"aws_rds_not_public",
		fmt.Sprintf("%d RDS instance(s) publicly accessible: %v", len(public), truncateList(public, 5)),
		"AWS/RDS", fmt.Sprintf("%d instances", len(public)), SeverityCritical,
		"Disable public accessibility:\n  aws rds modify-db-instance --db-instance-identifier <id> --no-publicly-accessible\n  Place RDS instances in private subnets with no route to an internet gateway.",
		soc2("CC6.1"), cis("2.3.3"),
	)}
}

func (c *RDSChecker) checkSSLEnforcement() []engine.Finding {
	paginator := rds.NewDescribeDBInstancesPaginator(c.client, &rds.DescribeDBInstancesInput{})
	var noSSL []string
	hasInstances := false

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.Background())
		if err != nil {
			return []engine.Finding{skip("aws_rds_ssl_enforcement", "RDS SSL/TLS Enforcement", err.Error())}
		}
		for _, db := range page.DBInstances {
			hasInstances = true
			pgName := ""
			if len(db.DBParameterGroups) > 0 {
				pgName = aws.ToString(db.DBParameterGroups[0].DBParameterGroupName)
			}
			// Default parameter groups cannot have SSL enforced (read-only)
			if strings.HasPrefix(pgName, "default.") || pgName == "" {
				noSSL = append(noSSL, aws.ToString(db.DBInstanceIdentifier))
				continue
			}
			if !c.isSSLEnforced(pgName, aws.ToString(db.Engine)) {
				noSSL = append(noSSL, aws.ToString(db.DBInstanceIdentifier))
			}
		}
	}

	if !hasInstances {
		return nil
	}
	if len(noSSL) == 0 {
		return []engine.Finding{pass("aws_rds_ssl_enforcement", "All RDS instances enforce SSL/TLS in transit", "AWS/RDS", "instances",
			soc2("CC6.7"), hipaa("164.312(e)(1)"))}
	}
	return []engine.Finding{fail(
		"aws_rds_ssl_enforcement",
		fmt.Sprintf("%d RDS instance(s) not enforcing SSL/TLS: %v", len(noSSL), truncateList(noSSL, 5)),
		"AWS/RDS", fmt.Sprintf("%d instances", len(noSSL)), SeverityHigh,
		"Create a custom parameter group and set:\n  PostgreSQL: rds.force_ssl = 1\n  MySQL/MariaDB: require_secure_transport = ON\nThen associate it with your DB instance:\n  aws rds modify-db-instance --db-instance-identifier <id> --db-parameter-group-name <custom-pg>",
		soc2("CC6.7"), hipaa("164.312(e)(1)"),
	)}
}

func (c *RDSChecker) isSSLEnforced(pgName, dbEngine string) bool {
	var paramName, onValue string
	switch {
	case strings.Contains(dbEngine, "postgres"):
		paramName, onValue = "rds.force_ssl", "1"
	case strings.Contains(dbEngine, "mysql"), strings.Contains(dbEngine, "mariadb"):
		paramName, onValue = "require_secure_transport", "ON"
	default:
		return true // SQL Server, Oracle — SSL is handled differently
	}

	var marker *string
	for {
		out, err := c.client.DescribeDBParameters(context.Background(), &rds.DescribeDBParametersInput{
			DBParameterGroupName: aws.String(pgName),
			Marker:               marker,
		})
		if err != nil {
			return false
		}
		for _, p := range out.Parameters {
			if aws.ToString(p.ParameterName) == paramName {
				return strings.EqualFold(aws.ToString(p.ParameterValue), onValue)
			}
		}
		if out.Marker == nil {
			break
		}
		marker = out.Marker
	}
	return false
}

func (c *RDSChecker) checkDeletionProtection() []engine.Finding {
	paginator := rds.NewDescribeDBInstancesPaginator(c.client, &rds.DescribeDBInstancesInput{})
	var noProtection []string
	hasInstances := false

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.Background())
		if err != nil {
			return []engine.Finding{skip("aws_rds_deletion_protection", "RDS Deletion Protection", err.Error())}
		}
		for _, db := range page.DBInstances {
			hasInstances = true
			if !aws.ToBool(db.DeletionProtection) {
				noProtection = append(noProtection, aws.ToString(db.DBInstanceIdentifier))
			}
		}
	}

	if !hasInstances {
		return nil
	}
	if len(noProtection) == 0 {
		return []engine.Finding{pass("aws_rds_deletion_protection", "All RDS instances have deletion protection enabled", "AWS/RDS", "instances",
			soc2("CC9.1"))}
	}
	return []engine.Finding{fail(
		"aws_rds_deletion_protection",
		fmt.Sprintf("%d RDS instance(s) without deletion protection: %v", len(noProtection), truncateList(noProtection, 5)),
		"AWS/RDS", fmt.Sprintf("%d instances", len(noProtection)), SeverityMedium,
		"Enable deletion protection:\n  aws rds modify-db-instance --db-instance-identifier <id> --deletion-protection",
		soc2("CC9.1"),
	)}
}

func (c *RDSChecker) checkAutomatedBackups() []engine.Finding {
	paginator := rds.NewDescribeDBInstancesPaginator(c.client, &rds.DescribeDBInstancesInput{})
	var insufficient []string
	hasInstances := false

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.Background())
		if err != nil {
			return []engine.Finding{skip("aws_rds_backup", "RDS Automated Backups", err.Error())}
		}
		for _, db := range page.DBInstances {
			hasInstances = true
			if aws.ToInt32(db.BackupRetentionPeriod) < 7 {
				insufficient = append(insufficient, aws.ToString(db.DBInstanceIdentifier))
			}
		}
	}

	if !hasInstances {
		return nil
	}
	if len(insufficient) == 0 {
		return []engine.Finding{pass("aws_rds_backup", "All RDS instances have automated backups ≥ 7 days", "AWS/RDS", "instances",
			soc2("CC9.1"), hipaa("164.310(d)(2)(iv)"))}
	}
	return []engine.Finding{fail(
		"aws_rds_backup",
		fmt.Sprintf("%d RDS instance(s) with backup retention < 7 days: %v", len(insufficient), truncateList(insufficient, 5)),
		"AWS/RDS", fmt.Sprintf("%d instances", len(insufficient)), SeverityHigh,
		"Increase backup retention to at least 7 days:\n  aws rds modify-db-instance --db-instance-identifier <id> --backup-retention-period 7",
		soc2("CC9.1"), hipaa("164.310(d)(2)(iv)"),
	)}
}

func (c *RDSChecker) checkIAMAuth() []engine.Finding {
	paginator := rds.NewDescribeDBInstancesPaginator(c.client, &rds.DescribeDBInstancesInput{})
	var noIAM []string
	hasInstances := false

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.Background())
		if err != nil {
			return []engine.Finding{skip("aws_rds_iam_auth", "RDS IAM Authentication", err.Error())}
		}
		for _, db := range page.DBInstances {
			hasInstances = true
			// IAM auth only supported for MySQL, PostgreSQL, MariaDB, Aurora
			engine := aws.ToString(db.Engine)
			if !supportsIAMAuth(engine) {
				continue
			}
			if !aws.ToBool(db.IAMDatabaseAuthenticationEnabled) {
				noIAM = append(noIAM, aws.ToString(db.DBInstanceIdentifier))
			}
		}
	}

	if !hasInstances {
		return nil
	}
	if len(noIAM) == 0 {
		return []engine.Finding{pass("aws_rds_iam_auth", "All RDS instances have IAM database authentication enabled", "AWS/RDS", "instances",
			soc2("CC6.1"), hipaa("164.312(a)(1)"))}
	}
	return []engine.Finding{fail(
		"aws_rds_iam_auth",
		fmt.Sprintf("%d RDS instance(s) without IAM authentication: %v", len(noIAM), truncateList(noIAM, 5)),
		"AWS/RDS", fmt.Sprintf("%d instances", len(noIAM)), SeverityMedium,
		"Enable IAM database authentication to eliminate long-lived DB passwords:\n  aws rds modify-db-instance --db-instance-identifier <id> --enable-iam-database-authentication\n  Then grant rds-db:connect to IAM roles instead of using static credentials.",
		soc2("CC6.1"), hipaa("164.312(a)(1)"),
	)}
}

// checkMasterUsername flags RDS instances whose master username is a well-known default
// (admin, root, sa, administrator) — a common misconfiguration that simplifies brute-force attacks.
func (c *RDSChecker) checkMasterUsername() []engine.Finding {
	defaultUsernames := map[string]bool{
		"admin": true, "root": true, "sa": true, "administrator": true,
	}

	paginator := rds.NewDescribeDBInstancesPaginator(c.client, &rds.DescribeDBInstancesInput{})
	var flagged []string
	hasInstances := false

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.Background())
		if err != nil {
			return []engine.Finding{skip("aws_rds_no_master_user_exposed", "RDS Master Username", err.Error())}
		}
		for _, db := range page.DBInstances {
			hasInstances = true
			if defaultUsernames[strings.ToLower(aws.ToString(db.MasterUsername))] {
				flagged = append(flagged, fmt.Sprintf("%s (user: %s)",
					aws.ToString(db.DBInstanceIdentifier), aws.ToString(db.MasterUsername)))
			}
		}
	}

	if !hasInstances {
		return nil
	}
	if len(flagged) == 0 {
		return []engine.Finding{pass("aws_rds_no_master_user_exposed",
			"No RDS instances use default master usernames", "AWS/RDS", "instances",
			soc2("CC6.1"))}
	}
	return []engine.Finding{fail(
		"aws_rds_no_master_user_exposed",
		fmt.Sprintf("%d RDS instance(s) use default master username: %v", len(flagged), truncateList(flagged, 5)),
		"AWS/RDS", fmt.Sprintf("%d instances", len(flagged)), SeverityMedium,
		"Use a non-obvious master username. RDS does not allow changing the master username after creation;\n"+
			"  you must snapshot → restore with a new username, or create a new application DB user and revoke master privileges.",
		soc2("CC6.1"),
	)}
}

func supportsIAMAuth(engine string) bool {
	for _, e := range []string{"mysql", "postgres", "mariadb", "aurora"} {
		if strings.Contains(engine, e) {
			return true
		}
	}
	return false
}

func (c *RDSChecker) checkMultiAZ() []engine.Finding {
	paginator := rds.NewDescribeDBInstancesPaginator(c.client, &rds.DescribeDBInstancesInput{})
	var noMultiAZ []string
	hasInstances := false

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.Background())
		if err != nil {
			return []engine.Finding{skip("aws_rds_multi_az", "RDS Multi-AZ", err.Error())}
		}
		for _, db := range page.DBInstances {
			hasInstances = true
			if db.MultiAZ == nil || !*db.MultiAZ {
				noMultiAZ = append(noMultiAZ, aws.ToString(db.DBInstanceIdentifier))
			}
		}
	}

	if !hasInstances {
		return nil
	}
	if len(noMultiAZ) == 0 {
		return []engine.Finding{pass("aws_rds_multi_az", "All RDS instances have Multi-AZ enabled", "AWS/RDS", "instances",
			soc2("A1.2"))}
	}
	return []engine.Finding{fail(
		"aws_rds_multi_az",
		fmt.Sprintf("%d RDS instance(s) without Multi-AZ: %v", len(noMultiAZ), truncateList(noMultiAZ, 5)),
		"AWS/RDS", fmt.Sprintf("%d instances", len(noMultiAZ)), SeverityMedium,
		"Enable Multi-AZ for production databases:\n  aws rds modify-db-instance --db-instance-identifier <id> --multi-az",
		soc2("A1.2"),
	)}
}

func (c *RDSChecker) checkMinorVersionUpgrade() []engine.Finding {
	paginator := rds.NewDescribeDBInstancesPaginator(c.client, &rds.DescribeDBInstancesInput{})
	var noUpgrade []string
	hasInstances := false

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.Background())
		if err != nil {
			return []engine.Finding{skip("aws_rds_minor_upgrade", "RDS Auto Minor Version Upgrade", err.Error())}
		}
		for _, db := range page.DBInstances {
			hasInstances = true
			if !aws.ToBool(db.AutoMinorVersionUpgrade) {
				noUpgrade = append(noUpgrade, aws.ToString(db.DBInstanceIdentifier))
			}
		}
	}

	if !hasInstances {
		return nil
	}
	if len(noUpgrade) == 0 {
		return []engine.Finding{pass("aws_rds_minor_upgrade", "All RDS instances have auto minor version upgrade enabled", "AWS/RDS", "instances",
			cis("2.3.2"))}
	}
	return []engine.Finding{fail(
		"aws_rds_minor_upgrade",
		fmt.Sprintf("%d RDS instance(s) with auto minor version upgrade disabled: %v", len(noUpgrade), truncateList(noUpgrade, 5)),
		"AWS/RDS", fmt.Sprintf("%d instances", len(noUpgrade)), SeverityLow,
		"Enable auto minor version upgrade:\n  aws rds modify-db-instance --db-instance-identifier <id> --auto-minor-version-upgrade",
		cis("2.3.2"),
	)}
}

// checkAuditLogging verifies that RDS instances export audit/error/general logs to CloudWatch Logs.
func (c *RDSChecker) checkAuditLogging() []engine.Finding {
	// Required log types per engine — any of these must be present.
	wantedLogs := map[string][]string{
		"mysql":     {"audit", "error", "general"},
		"mariadb":   {"audit", "error"},
		"postgres":  {"postgresql"},
		"aurora":    {"audit"},
		"oracle":    {"audit"},
		"sqlserver": {"error"},
	}
	defaultWanted := []string{"audit", "error"}

	paginator := rds.NewDescribeDBInstancesPaginator(c.client, &rds.DescribeDBInstancesInput{})
	var noLogs []string
	hasInstances := false

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.Background())
		if err != nil {
			return []engine.Finding{skip("aws_rds_audit_logging", "RDS Audit Logging", err.Error())}
		}
		for _, db := range page.DBInstances {
			hasInstances = true
			id := aws.ToString(db.DBInstanceIdentifier)
			engine := strings.ToLower(aws.ToString(db.Engine))

			wanted := defaultWanted
			for prefix, logs := range wantedLogs {
				if strings.HasPrefix(engine, prefix) {
					wanted = logs
					break
				}
			}

			exported := map[string]bool{}
			for _, lg := range db.EnabledCloudwatchLogsExports {
				exported[strings.ToLower(lg)] = true
			}

			hasAny := false
			for _, w := range wanted {
				if exported[w] {
					hasAny = true
					break
				}
			}
			if !hasAny {
				noLogs = append(noLogs, id)
			}
		}
	}

	if !hasInstances {
		return nil
	}
	if len(noLogs) == 0 {
		return []engine.Finding{pass("aws_rds_audit_logging",
			"All RDS instances export audit/error logs to CloudWatch Logs",
			"AWS/RDS", "instances",
			soc2("CC7.2"), hipaa("164.312(b)"), cis("2.3.4"),
		)}
	}
	return []engine.Finding{fail(
		"aws_rds_audit_logging",
		fmt.Sprintf("%d RDS instance(s) not exporting audit logs to CloudWatch Logs: %v", len(noLogs), truncateList(noLogs, 5)),
		"AWS/RDS", fmt.Sprintf("%d instances", len(noLogs)), SeverityHigh,
		"Enable CloudWatch log exports:\n"+
			"  aws rds modify-db-instance --db-instance-identifier <id>\\\n"+
			"    --cloudwatch-logs-export-configuration '{\"EnableLogTypes\":[\"audit\",\"error\",\"general\"]}'\n"+
			"For PostgreSQL use: \"postgresql\" instead of \"audit\".",
		soc2("CC7.2"), hipaa("164.312(b)"), cis("2.3.4"),
	)}
}
