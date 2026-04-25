package aws

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/complykit/complykit/internal/engine"
)

// ── AWS P3 Checker ────────────────────────────────────────────────────────────

type P3Checker struct {
	orgs *organizations.Client
	logs *cloudwatchlogs.Client
}

func NewP3Checker(cfg aws.Config) *P3Checker {
	return &P3Checker{
		orgs: organizations.NewFromConfig(cfg),
		logs: cloudwatchlogs.NewFromConfig(cfg),
	}
}

func (c *P3Checker) Integration() string { return "AWS/Governance" }

func (c *P3Checker) Run() ([]engine.Finding, error) {
	var findings []engine.Finding
	findings = append(findings, c.checkOrgSCPs()...)
	findings = append(findings, c.checkCWLogMetricFilters()...)
	return findings, nil
}

// ── AWS Organizations SCPs ────────────────────────────────────────────────────

func (c *P3Checker) checkOrgSCPs() []engine.Finding {
	out, err := c.orgs.ListPolicies(context.Background(), &organizations.ListPoliciesInput{
		Filter: "SERVICE_CONTROL_POLICY",
	})
	if err != nil {
		// Not an Organizations master account or not in an org
		return []engine.Finding{skip("aws_org_scp", "AWS Organizations SCPs", err.Error())}
	}
	// AWS always has "FullAWSAccess" — check for any additional restrictive SCPs
	var custom []string
	for _, p := range out.Policies {
		name := aws.ToString(p.Name)
		if name != "FullAWSAccess" {
			custom = append(custom, name)
		}
	}
	if len(custom) > 0 {
		return []engine.Finding{pass("aws_org_scp",
			fmt.Sprintf("AWS Organizations has %d custom SCP(s) beyond FullAWSAccess: %v", len(custom), truncateList(custom, 5)),
			"AWS/Governance", "organization",
			soc2("CC6.3"), cis("1.x"))}
	}
	return []engine.Finding{fail(
		"aws_org_scp", "No custom Service Control Policies found — only FullAWSAccess is applied",
		"AWS/Governance", "organization", SeverityMedium,
		"Create SCPs to enforce guardrails across all accounts:\n  # Deny disabling CloudTrail\n  # Deny leaving the organization\n  # Deny creating IAM users in member accounts\n  aws organizations create-policy --content file://scp.json --name MyGuardrail --type SERVICE_CONTROL_POLICY",
		soc2("CC6.3"),
	)}
}

// ── CloudWatch Log metric filters cross-reference ────────────────────────────

func (c *P3Checker) checkCWLogMetricFilters() []engine.Finding {
	// Get all log groups
	groups, err := c.logs.DescribeLogGroups(context.Background(), &cloudwatchlogs.DescribeLogGroupsInput{})
	if err != nil {
		return []engine.Finding{skip("aws_cw_log_metric_filters", "CloudWatch Log Metric Filters", err.Error())}
	}

	requiredPatterns := []struct {
		name, pattern string
	}{
		{"root-login", `{ $.userIdentity.type = "Root" }`},
		{"unauth-api", `{ $.errorCode = "AccessDenied" }`},
		{"no-mfa-console", `{ $.eventName = "ConsoleLogin" && $.additionalEventData.MFAUsed != "Yes" }`},
		{"iam-policy-change", `{ $.eventName = "PutGroupPolicy" }`},
	}

	foundPatterns := map[string]bool{}
	for _, group := range groups.LogGroups {
		filters, err := c.logs.DescribeMetricFilters(context.Background(), &cloudwatchlogs.DescribeMetricFiltersInput{
			LogGroupName: group.LogGroupName,
		})
		if err != nil {
			continue
		}
		for _, f := range filters.MetricFilters {
			fp := aws.ToString(f.FilterPattern)
			for _, req := range requiredPatterns {
				if strings.Contains(fp, strings.Split(req.pattern, "&&")[0][2:8]) {
					foundPatterns[req.name] = true
				}
			}
		}
	}

	var missing []string
	for _, req := range requiredPatterns {
		if !foundPatterns[req.name] {
			missing = append(missing, req.name)
		}
	}
	if len(missing) == 0 {
		return []engine.Finding{pass("aws_cw_log_metric_filters",
			"CloudWatch log metric filters found for required security events",
			"AWS/Governance", "cloudwatch",
			soc2("CC7.2"), hipaa("164.312(b)"), cis("3.x"))}
	}
	return []engine.Finding{fail(
		"aws_cw_log_metric_filters",
		fmt.Sprintf("Missing log metric filters for: %v", missing),
		"AWS/Governance", "cloudwatch", SeverityMedium,
		"Create CloudWatch metric filters on CloudTrail log group for each missing pattern.",
		soc2("CC7.2"), hipaa("164.312(b)"), cis("3.x"),
	)}
}
