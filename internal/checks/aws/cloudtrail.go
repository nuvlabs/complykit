package aws

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/complykit/complykit/internal/engine"
)

type CloudTrailChecker struct {
	client *cloudtrail.Client
}

func NewCloudTrailChecker(cfg aws.Config) *CloudTrailChecker {
	return &CloudTrailChecker{client: cloudtrail.NewFromConfig(cfg)}
}

func (c *CloudTrailChecker) Integration() string { return "AWS/CloudTrail" }

func (c *CloudTrailChecker) Run() ([]engine.Finding, error) {
	var findings []engine.Finding
	findings = append(findings, c.checkTrails()...)
	findings = append(findings, c.checkRDSDataEvents()...)
	return findings, nil
}

// checkRDSDataEvents verifies that at least one CloudTrail trail records RDS data events.
func (c *CloudTrailChecker) checkRDSDataEvents() []engine.Finding {
	out, err := c.client.DescribeTrails(context.Background(), &cloudtrail.DescribeTrailsInput{
		IncludeShadowTrails: aws.Bool(false),
	})
	if err != nil {
		return []engine.Finding{skip("aws_cloudtrail_rds_events", "CloudTrail RDS Data Events", err.Error())}
	}

	for _, trail := range out.TrailList {
		selOut, serr := c.client.GetEventSelectors(context.Background(), &cloudtrail.GetEventSelectorsInput{
			TrailName: trail.TrailARN,
		})
		if serr != nil {
			continue
		}
		// Advanced event selectors
		for _, sel := range selOut.AdvancedEventSelectors {
			for _, f := range sel.FieldSelectors {
				if aws.ToString(f.Field) == "resources.type" {
					for _, v := range f.Equals {
						if strings.Contains(strings.ToLower(v), "rds") {
							return []engine.Finding{pass("aws_cloudtrail_rds_events",
								"CloudTrail records RDS data events",
								"AWS/CloudTrail", "trails",
								soc2("CC7.2"), hipaa("164.312(b)"),
							)}
						}
					}
				}
			}
		}
	}

	return []engine.Finding{fail(
		"aws_cloudtrail_rds_events",
		"No CloudTrail trail records RDS data events",
		"AWS/CloudTrail", "account", SeverityMedium,
		"Enable RDS data events on a trail:\n"+
			"  aws cloudtrail put-event-selectors --trail-name <trail> \\\n"+
			"    --advanced-event-selectors '[{\"Name\":\"RDS\",\"FieldSelectors\":["+
			"{\"Field\":\"eventCategory\",\"Equals\":[\"Data\"]},"+
			"{\"Field\":\"resources.type\",\"Equals\":[\"AWS::RDS::DBInstance\"]}"+
			"]}]'",
		soc2("CC7.2"), hipaa("164.312(b)"),
	)}
}

func (c *CloudTrailChecker) checkTrails() []engine.Finding {
	out, err := c.client.DescribeTrails(context.Background(), &cloudtrail.DescribeTrailsInput{
		IncludeShadowTrails: aws.Bool(false),
	})
	if err != nil {
		return []engine.Finding{skip("aws_cloudtrail_enabled", "CloudTrail Enabled", err.Error())}
	}

	if len(out.TrailList) == 0 {
		return []engine.Finding{fail(
			"aws_cloudtrail_enabled", "No CloudTrail trails configured",
			"AWS/CloudTrail", "account", SeverityCritical,
			"Create a trail:\n  aws cloudtrail create-trail --name my-trail --s3-bucket-name my-bucket --is-multi-region-trail\n  aws cloudtrail start-logging --name my-trail",
			soc2("CC7.2"), hipaa("164.312(b)"), cis("3.1"),
		)}
	}

	var findings []engine.Finding
	var activeMultiRegion, loggingDisabled, noValidation, singleRegion []string

	for _, trail := range out.TrailList {
		name := aws.ToString(trail.Name)
		status, err := c.client.GetTrailStatus(context.Background(), &cloudtrail.GetTrailStatusInput{
			Name: trail.TrailARN,
		})
		if err != nil || !aws.ToBool(status.IsLogging) {
			loggingDisabled = append(loggingDisabled, name)
			continue
		}
		if !aws.ToBool(trail.LogFileValidationEnabled) {
			noValidation = append(noValidation, name)
		}
		if aws.ToBool(trail.IsMultiRegionTrail) {
			activeMultiRegion = append(activeMultiRegion, name)
		} else {
			singleRegion = append(singleRegion, name)
		}
	}

	if len(loggingDisabled) > 0 {
		findings = append(findings, fail(
			"aws_cloudtrail_logging",
			fmt.Sprintf("CloudTrail logging disabled for: %v", loggingDisabled),
			"AWS/CloudTrail", fmt.Sprintf("%d trails", len(loggingDisabled)), SeverityCritical,
			"Enable logging: aws cloudtrail start-logging --name TRAIL_NAME",
			soc2("CC7.2"), hipaa("164.312(b)"), cis("3.1"),
		))
	}

	if len(activeMultiRegion) > 0 {
		findings = append(findings, pass("aws_cloudtrail_multiregion",
			fmt.Sprintf("Multi-region CloudTrail active: %v", activeMultiRegion),
			"AWS/CloudTrail", "account", soc2("CC7.2"), hipaa("164.312(b)"), cis("3.1")))
	} else if len(singleRegion) > 0 {
		findings = append(findings, fail(
			"aws_cloudtrail_multiregion", fmt.Sprintf("No multi-region trail (single-region only: %v)", singleRegion),
			"AWS/CloudTrail", "account", SeverityHigh,
			"Enable multi-region trail:\n  aws cloudtrail update-trail --name TRAIL_NAME --is-multi-region-trail",
			soc2("CC7.2"), hipaa("164.312(b)"), cis("3.1"),
		))
	}

	if len(noValidation) > 0 {
		findings = append(findings, fail(
			"aws_cloudtrail_log_validation",
			fmt.Sprintf("%d trail(s) without log file validation: %v", len(noValidation), noValidation),
			"AWS/CloudTrail", fmt.Sprintf("%d trails", len(noValidation)), SeverityMedium,
			"Enable log file validation:\n  aws cloudtrail update-trail --name TRAIL_NAME --enable-log-file-validation",
			soc2("CC7.2"), hipaa("164.312(b)"), cis("3.2"),
		))
	} else if len(activeMultiRegion)+len(singleRegion) > 0 {
		findings = append(findings, pass("aws_cloudtrail_log_validation",
			"All active trails have log file validation enabled",
			"AWS/CloudTrail", "trails", soc2("CC7.2"), hipaa("164.312(b)"), cis("3.2")))
	}

	return findings
}
