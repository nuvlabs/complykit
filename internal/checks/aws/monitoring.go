package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/inspector2"
	i2types "github.com/aws/aws-sdk-go-v2/service/inspector2/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/complykit/complykit/internal/engine"
)

type MonitoringChecker struct {
	hub  *securityhub.Client
	ins  *inspector2.Client
	sns  *sns.Client
	rds  *rds.Client
	sm   *secretsmanager.Client
}

func NewMonitoringChecker(cfg aws.Config) *MonitoringChecker {
	return &MonitoringChecker{
		hub: securityhub.NewFromConfig(cfg),
		ins: inspector2.NewFromConfig(cfg),
		sns: sns.NewFromConfig(cfg),
		rds: rds.NewFromConfig(cfg),
		sm:  secretsmanager.NewFromConfig(cfg),
	}
}

func (c *MonitoringChecker) Integration() string { return "AWS/Monitoring" }

func (c *MonitoringChecker) Run() ([]engine.Finding, error) {
	var findings []engine.Finding
	findings = append(findings, c.checkSecurityHub()...)
	findings = append(findings, c.checkInspector()...)
	findings = append(findings, c.checkSNSTopics()...)
	findings = append(findings, c.checkRDSPublicSnapshots()...)
	findings = append(findings, c.checkSecretsManager()...)
	return findings, nil
}

func (c *MonitoringChecker) checkSecurityHub() []engine.Finding {
	_, err := c.hub.GetEnabledStandards(context.Background(), &securityhub.GetEnabledStandardsInput{})
	if err != nil {
		// Not enabled returns an error
		return []engine.Finding{fail(
			"aws_securityhub_enabled", "AWS Security Hub is not enabled",
			"AWS/Monitoring", "account", SeverityHigh,
			"Enable Security Hub:\n  aws securityhub enable-security-hub --enable-default-standards",
			soc2("CC6.8"), hipaa("164.308(a)(1)(ii)(D)"),
		)}
	}
	return []engine.Finding{pass("aws_securityhub_enabled", "AWS Security Hub is enabled", "AWS/Monitoring", "account",
		soc2("CC6.8"), hipaa("164.308(a)(1)(ii)(D)"))}
}

func (c *MonitoringChecker) checkInspector() []engine.Finding {
	out, err := c.ins.BatchGetAccountStatus(context.Background(), &inspector2.BatchGetAccountStatusInput{
		AccountIds: []string{}, // empty = current account
	})
	if err != nil {
		return []engine.Finding{skip("aws_inspector_enabled", "AWS Inspector v2", err.Error())}
	}
	for _, acct := range out.Accounts {
		if acct.State != nil && acct.State.Status == i2types.StatusEnabled {
			return []engine.Finding{pass("aws_inspector_enabled", "AWS Inspector v2 is enabled", "AWS/Monitoring", "account",
				soc2("CC7.1"), hipaa("164.308(a)(5)(ii)(B)"))}
		}
	}
	return []engine.Finding{fail(
		"aws_inspector_enabled", "AWS Inspector v2 is not enabled",
		"AWS/Monitoring", "account", SeverityMedium,
		"Enable Inspector v2:\n  aws inspector2 enable --resource-types EC2 ECR LAMBDA",
		soc2("CC7.1"), hipaa("164.308(a)(5)(ii)(B)"),
	)}
}

func (c *MonitoringChecker) checkSNSTopics() []engine.Finding {
	out, err := c.sns.ListTopics(context.Background(), &sns.ListTopicsInput{})
	if err != nil {
		return []engine.Finding{skip("aws_sns_topics", "SNS Topics for Alarms", err.Error())}
	}
	if len(out.Topics) > 0 {
		return []engine.Finding{pass("aws_sns_topics", "SNS topics exist for CloudWatch alarm notifications", "AWS/Monitoring", "account",
			soc2("CC7.2"), hipaa("164.312(b)"))}
	}
	return []engine.Finding{fail(
		"aws_sns_topics", "No SNS topics found — CloudWatch alarms cannot notify anyone",
		"AWS/Monitoring", "account", SeverityMedium,
		"Create an SNS topic and subscribe your security team:\n  aws sns create-topic --name SecurityAlerts\n  aws sns subscribe --topic-arn ARN --protocol email --notification-endpoint security@company.com",
		soc2("CC7.2"), hipaa("164.312(b)"),
	)}
}

func (c *MonitoringChecker) checkRDSPublicSnapshots() []engine.Finding {
	paginator := rds.NewDescribeDBSnapshotsPaginator(c.rds, &rds.DescribeDBSnapshotsInput{
		SnapshotType: aws.String("public"),
	})
	var publicSnaps []string
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.Background())
		if err != nil {
			return []engine.Finding{skip("aws_rds_public_snapshot", "RDS Public Snapshots", err.Error())}
		}
		for _, snap := range page.DBSnapshots {
			publicSnaps = append(publicSnaps, aws.ToString(snap.DBSnapshotIdentifier))
		}
	}
	if len(publicSnaps) == 0 {
		return []engine.Finding{pass("aws_rds_public_snapshot", "No public RDS snapshots found", "AWS/Monitoring", "rds",
			soc2("CC6.6"), hipaa("164.312(e)(1)"), cis("2.3.2"))}
	}
	return []engine.Finding{fail(
		"aws_rds_public_snapshot",
		fmt.Sprintf("%d public RDS snapshot(s) found: %v", len(publicSnaps), truncateList(publicSnaps, 5)),
		"AWS/Monitoring", fmt.Sprintf("%d snapshots", len(publicSnaps)), SeverityCritical,
		"Make snapshots private:\n  aws rds modify-db-snapshot-attribute --db-snapshot-identifier SNAP --attribute-name restore --values-to-remove all",
		soc2("CC6.6"), hipaa("164.312(e)(1)"), cis("2.3.2"),
	)}
}

func (c *MonitoringChecker) checkSecretsManager() []engine.Finding {
	out, err := c.sm.ListSecrets(context.Background(), &secretsmanager.ListSecretsInput{MaxResults: aws.Int32(1)})
	if err != nil {
		return []engine.Finding{skip("aws_secrets_manager", "AWS Secrets Manager", err.Error())}
	}
	if len(out.SecretList) > 0 {
		return []engine.Finding{pass("aws_secrets_manager", "AWS Secrets Manager is in use (at least one secret found)", "AWS/Monitoring", "account",
			soc2("CC6.7"), hipaa("164.312(a)(2)(iv)"))}
	}
	return []engine.Finding{fail(
		"aws_secrets_manager", "No secrets found in AWS Secrets Manager — credentials may be stored insecurely",
		"AWS/Monitoring", "account", SeverityMedium,
		"Migrate hardcoded credentials and DB passwords to Secrets Manager:\n  aws secretsmanager create-secret --name MySecret --secret-string file://secret.json",
		soc2("CC6.7"), hipaa("164.312(a)(2)(iv)"),
	)}
}
