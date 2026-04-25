package aws

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/complykit/complykit/internal/engine"
)

type CloudWatchChecker struct {
	cw  *cloudwatch.Client
	ct  *cloudtrail.Client
	s3c *s3.Client
}

func NewCloudWatchChecker(cfg aws.Config) *CloudWatchChecker {
	return &CloudWatchChecker{
		cw:  cloudwatch.NewFromConfig(cfg),
		ct:  cloudtrail.NewFromConfig(cfg),
		s3c: s3.NewFromConfig(cfg),
	}
}

func (c *CloudWatchChecker) Integration() string { return "AWS/CloudWatch" }

func (c *CloudWatchChecker) Run() ([]engine.Finding, error) {
	var findings []engine.Finding
	findings = append(findings, c.checkCTCloudWatchIntegration()...)
	findings = append(findings, c.checkCTBucketNotPublic()...)
	findings = append(findings, c.checkCTKMSEncryption()...)
	findings = append(findings, c.checkCWAlarms()...)
	return findings, nil
}

// ── CloudTrail → CloudWatch Logs integration ──────────────────────────────────

func (c *CloudWatchChecker) checkCTCloudWatchIntegration() []engine.Finding {
	out, err := c.ct.DescribeTrails(context.Background(), &cloudtrail.DescribeTrailsInput{IncludeShadowTrails: aws.Bool(false)})
	if err != nil {
		return []engine.Finding{skip("aws_ct_cloudwatch", "CloudTrail CloudWatch Integration", err.Error())}
	}
	var noIntegration []string
	for _, trail := range out.TrailList {
		if aws.ToString(trail.CloudWatchLogsLogGroupArn) == "" {
			noIntegration = append(noIntegration, aws.ToString(trail.Name))
		}
	}
	if len(noIntegration) == 0 {
		return []engine.Finding{pass("aws_ct_cloudwatch", "All CloudTrail trails are integrated with CloudWatch Logs", "AWS/CloudWatch", "trails",
			soc2("CC7.2"), hipaa("164.312(b)"), cis("3.4"))}
	}
	return []engine.Finding{fail(
		"aws_ct_cloudwatch",
		fmt.Sprintf("%d trail(s) not sending logs to CloudWatch: %v", len(noIntegration), noIntegration),
		"AWS/CloudWatch", fmt.Sprintf("%d trails", len(noIntegration)), SeverityHigh,
		"Enable CloudWatch Logs integration:\n  aws cloudtrail update-trail --name TRAIL --cloud-watch-logs-log-group-arn LOG_GROUP_ARN --cloud-watch-logs-role-arn ROLE_ARN",
		soc2("CC7.2"), hipaa("164.312(b)"), cis("3.4"),
	)}
}

// ── CloudTrail S3 bucket not public ──────────────────────────────────────────

func (c *CloudWatchChecker) checkCTBucketNotPublic() []engine.Finding {
	out, err := c.ct.DescribeTrails(context.Background(), &cloudtrail.DescribeTrailsInput{IncludeShadowTrails: aws.Bool(false)})
	if err != nil {
		return []engine.Finding{skip("aws_ct_s3_public", "CloudTrail S3 Bucket Not Public", err.Error())}
	}
	var publicBuckets []string
	seen := map[string]bool{}
	for _, trail := range out.TrailList {
		bucket := aws.ToString(trail.S3BucketName)
		if bucket == "" || seen[bucket] {
			continue
		}
		seen[bucket] = true
		pab, err := c.s3c.GetPublicAccessBlock(context.Background(), &s3.GetPublicAccessBlockInput{Bucket: aws.String(bucket)})
		if err != nil || pab.PublicAccessBlockConfiguration == nil ||
			!aws.ToBool(pab.PublicAccessBlockConfiguration.BlockPublicAcls) ||
			!aws.ToBool(pab.PublicAccessBlockConfiguration.RestrictPublicBuckets) {
			publicBuckets = append(publicBuckets, bucket)
		}
	}
	if len(publicBuckets) == 0 {
		return []engine.Finding{pass("aws_ct_s3_public", "CloudTrail S3 buckets have public access blocked", "AWS/CloudWatch", "ct-buckets",
			soc2("CC7.2"), hipaa("164.312(b)"), cis("3.3"))}
	}
	return []engine.Finding{fail(
		"aws_ct_s3_public",
		fmt.Sprintf("CloudTrail S3 bucket(s) may be publicly accessible: %v", publicBuckets),
		"AWS/CloudWatch", "ct-buckets", SeverityCritical,
		"Enable public access block on CloudTrail bucket:\n  aws s3api put-public-access-block --bucket BUCKET --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
		soc2("CC7.2"), hipaa("164.312(b)"), cis("3.3"),
	)}
}

// ── CloudTrail KMS encryption ─────────────────────────────────────────────────

func (c *CloudWatchChecker) checkCTKMSEncryption() []engine.Finding {
	out, err := c.ct.DescribeTrails(context.Background(), &cloudtrail.DescribeTrailsInput{IncludeShadowTrails: aws.Bool(false)})
	if err != nil {
		return []engine.Finding{skip("aws_ct_kms", "CloudTrail KMS Encryption", err.Error())}
	}
	var noKMS []string
	for _, trail := range out.TrailList {
		if aws.ToString(trail.KmsKeyId) == "" {
			noKMS = append(noKMS, aws.ToString(trail.Name))
		}
	}
	if len(noKMS) == 0 {
		return []engine.Finding{pass("aws_ct_kms", "All CloudTrail trails are encrypted with KMS CMK", "AWS/CloudWatch", "trails",
			soc2("CC6.7"), hipaa("164.312(a)(2)(iv)"), cis("3.7"))}
	}
	return []engine.Finding{fail(
		"aws_ct_kms",
		fmt.Sprintf("%d trail(s) not encrypted with KMS: %v", len(noKMS), noKMS),
		"AWS/CloudWatch", fmt.Sprintf("%d trails", len(noKMS)), SeverityMedium,
		"Enable KMS encryption on trail:\n  aws cloudtrail update-trail --name TRAIL --kms-key-id arn:aws:kms:REGION:ACCOUNT:key/KEY_ID",
		soc2("CC6.7"), hipaa("164.312(a)(2)(iv)"), cis("3.7"),
	)}
}

// ── CloudWatch metric alarms ──────────────────────────────────────────────────

// Each entry: (alarm_id, description, filter_pattern)
var requiredAlarms = []struct {
	id, title, pattern string
	cis                string
}{
	{"aws_cw_alarm_root_login", "CloudWatch alarm: root account login", `{ $.userIdentity.type = "Root" && $.eventType != "AwsServiceEvent" }`, "3.3"},
	{"aws_cw_alarm_unauth_api", "CloudWatch alarm: unauthorized API calls", `{ ($.errorCode = "AccessDenied") || ($.errorCode = "UnauthorizedOperation") }`, "3.1"},
	{"aws_cw_alarm_no_mfa_console", "CloudWatch alarm: console sign-in without MFA", `{ $.eventName = "ConsoleLogin" && $.additionalEventData.MFAUsed != "Yes" }`, "3.2"},
	{"aws_cw_alarm_iam_policy_change", "CloudWatch alarm: IAM policy changes", `{ ($.eventName = DeleteGroupPolicy) || ($.eventName = DeleteRolePolicy) || ($.eventName = DeleteUserPolicy) || ($.eventName = PutGroupPolicy) || ($.eventName = PutRolePolicy) || ($.eventName = PutUserPolicy) || ($.eventName = CreatePolicy) || ($.eventName = DeletePolicy) || ($.eventName = CreatePolicyVersion) || ($.eventName = DeletePolicyVersion) || ($.eventName = SetDefaultPolicyVersion) }`, "3.4"},
}

func (c *CloudWatchChecker) checkCWAlarms() []engine.Finding {
	// Get all metric filters across all log groups
	filters, err := c.cw.DescribeAlarms(context.Background(), &cloudwatch.DescribeAlarmsInput{})
	if err != nil {
		return []engine.Finding{skip("aws_cw_alarms", "CloudWatch Alarms", err.Error())}
	}

	existingAlarms := map[string]bool{}
	for _, a := range filters.MetricAlarms {
		existingAlarms[strings.ToLower(aws.ToString(a.AlarmName))] = true
		if a.Metrics != nil {
			for _, m := range a.Metrics {
				if m.MetricStat != nil && m.MetricStat.Metric != nil {
					existingAlarms[strings.ToLower(aws.ToString(m.MetricStat.Metric.MetricName))] = true
				}
			}
		}
	}

	var findings []engine.Finding
	for _, req := range requiredAlarms {
		// We can't trivially verify filter patterns from alarm names alone,
		// so we check if any alarm exists whose name contains keywords from the check.
		// A proper implementation would cross-reference CloudWatch Logs metric filters.
		found := false
		keywords := alarmKeywords(req.id)
		for alarmName := range existingAlarms {
			matched := true
			for _, kw := range keywords {
				if !strings.Contains(alarmName, kw) {
					matched = false
					break
				}
			}
			if matched {
				found = true
				break
			}
		}
		if found {
			findings = append(findings, pass(req.id, req.title+" is configured", "AWS/CloudWatch", "alarms",
				soc2("CC7.2"), hipaa("164.312(b)"), cis(req.cis)))
		} else {
			findings = append(findings, fail(
				req.id, req.title+" is not configured",
				"AWS/CloudWatch", "alarms", SeverityMedium,
				fmt.Sprintf("Create a CloudWatch Logs metric filter and alarm:\n  1. Create metric filter with pattern: %s\n  2. Create alarm on the metric\n  3. Connect alarm to an SNS topic", req.pattern),
				soc2("CC7.2"), hipaa("164.312(b)"), cis(req.cis),
			))
		}
	}
	return findings
}

func alarmKeywords(id string) []string {
	switch id {
	case "aws_cw_alarm_root_login":
		return []string{"root"}
	case "aws_cw_alarm_unauth_api":
		return []string{"unauth"}
	case "aws_cw_alarm_no_mfa_console":
		return []string{"mfa", "console"}
	case "aws_cw_alarm_iam_policy_change":
		return []string{"iam", "polic"}
	}
	return nil
}
