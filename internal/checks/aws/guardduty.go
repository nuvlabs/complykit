package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	gdtypes "github.com/aws/aws-sdk-go-v2/service/guardduty/types"
	"github.com/complykit/complykit/internal/engine"
)

type GuardDutyChecker struct {
	client *guardduty.Client
}

func NewGuardDutyChecker(cfg aws.Config) *GuardDutyChecker {
	return &GuardDutyChecker{client: guardduty.NewFromConfig(cfg)}
}

func (c *GuardDutyChecker) Integration() string { return "AWS/GuardDuty" }

func (c *GuardDutyChecker) Run() ([]engine.Finding, error) {
	out, err := c.client.ListDetectors(context.Background(), &guardduty.ListDetectorsInput{})
	if err != nil {
		return []engine.Finding{skip("aws_guardduty_enabled", "GuardDuty Enabled", err.Error())}, nil
	}

	if len(out.DetectorIds) == 0 {
		return []engine.Finding{fail(
			"aws_guardduty_enabled", "GuardDuty is not enabled in this region",
			"AWS/GuardDuty", "account", SeverityHigh,
			"Enable GuardDuty:\n  aws guardduty create-detector --enable",
			soc2("CC6.8"), hipaa("164.308(a)(1)(ii)(D)"), cis("3.10"),
		)}, nil
	}

	for _, id := range out.DetectorIds {
		det, err := c.client.GetDetector(context.Background(), &guardduty.GetDetectorInput{
			DetectorId: aws.String(id),
		})
		if err != nil {
			continue
		}
		if det.Status != gdtypes.DetectorStatusEnabled {
			return []engine.Finding{fail(
				"aws_guardduty_enabled", "GuardDuty detector is disabled",
				"AWS/GuardDuty", "account", SeverityHigh,
				"Enable the GuardDuty detector:\n  aws guardduty update-detector --detector-id "+id+" --enable",
				soc2("CC6.8"), hipaa("164.308(a)(1)(ii)(D)"), cis("3.10"),
			)}, nil
		}
	}

	return []engine.Finding{pass("aws_guardduty_enabled", "GuardDuty is enabled and active", "AWS/GuardDuty", "account",
		soc2("CC6.8"), hipaa("164.308(a)(1)(ii)(D)"), cis("3.10"))}, nil
}
