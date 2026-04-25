package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/complykit/complykit/internal/engine"
)

type RDSChecker struct {
	client *rds.Client
}

func NewRDSChecker(cfg aws.Config) *RDSChecker {
	return &RDSChecker{client: rds.NewFromConfig(cfg)}
}

func (c *RDSChecker) Integration() string { return "AWS/RDS" }

func (c *RDSChecker) Run() ([]engine.Finding, error) {
	return c.checkEncryption(), nil
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
