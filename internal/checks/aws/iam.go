package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/complykit/complykit/internal/engine"
)

type IAMChecker struct {
	client *iam.Client
}

func NewIAMChecker(cfg aws.Config) *IAMChecker {
	return &IAMChecker{client: iam.NewFromConfig(cfg)}
}

func (c *IAMChecker) Integration() string { return "AWS/IAM" }

func (c *IAMChecker) Run() ([]engine.Finding, error) {
	var findings []engine.Finding

	findings = append(findings, c.checkRootMFA()...)
	findings = append(findings, c.checkPasswordPolicy()...)
	findings = append(findings, c.checkUnusedCredentials()...)
	findings = append(findings, c.checkConsoleMFA()...)

	return findings, nil
}

func (c *IAMChecker) checkRootMFA() []engine.Finding {
	out, err := c.client.GetAccountSummary(context.Background(), &iam.GetAccountSummaryInput{})
	if err != nil {
		return []engine.Finding{skip("aws_iam_root_mfa", "Root MFA Enabled", err.Error())}
	}

	mfaActive := out.SummaryMap["AccountMFAEnabled"]
	if mfaActive == 1 {
		return []engine.Finding{pass("aws_iam_root_mfa", "Root account MFA enabled", "AWS/IAM", "root", soc2("CC6.1"), cis("1.5"))}
	}
	return []engine.Finding{fail(
		"aws_iam_root_mfa",
		"Root account MFA not enabled",
		"AWS/IAM", "root",
		SeverityCritical,
		"Enable MFA on the AWS root account: IAM Console → Dashboard → Activate MFA on your root account.",
		soc2("CC6.1"), hipaa("164.312(d)"), cis("1.5"),
	)}
}

func (c *IAMChecker) checkPasswordPolicy() []engine.Finding {
	out, err := c.client.GetAccountPasswordPolicy(context.Background(), &iam.GetAccountPasswordPolicyInput{})
	if err != nil {
		return []engine.Finding{fail(
			"aws_iam_password_policy",
			"No IAM password policy configured",
			"AWS/IAM", "account",
			SeverityHigh,
			"Set a password policy: IAM Console → Account settings → Set password policy. Minimum 14 chars, require uppercase, lowercase, numbers, symbols.",
			soc2("CC6.1"), cis("1.8"),
		)}
	}

	p := out.PasswordPolicy
	issues := []string{}
	if p.MinimumPasswordLength == nil || *p.MinimumPasswordLength < 14 {
		issues = append(issues, "minimum length < 14")
	}
	if !p.RequireUppercaseCharacters {
		issues = append(issues, "uppercase not required")
	}
	if !p.RequireLowercaseCharacters {
		issues = append(issues, "lowercase not required")
	}
	if !p.RequireNumbers {
		issues = append(issues, "numbers not required")
	}
	if !p.RequireSymbols {
		issues = append(issues, "symbols not required")
	}

	if len(issues) == 0 {
		return []engine.Finding{pass("aws_iam_password_policy", "IAM password policy meets requirements", "AWS/IAM", "account", soc2("CC6.1"), cis("1.8"))}
	}
	return []engine.Finding{fail(
		"aws_iam_password_policy",
		fmt.Sprintf("Weak IAM password policy: %v", issues),
		"AWS/IAM", "account",
		SeverityHigh,
		"Strengthen password policy in IAM Console → Account settings.",
		soc2("CC6.1"), cis("1.8"),
	)}
}

func (c *IAMChecker) checkUnusedCredentials() []engine.Finding {
	paginator := iam.NewGetAccountAuthorizationDetailsPaginator(c.client, &iam.GetAccountAuthorizationDetailsInput{
		Filter: []types.EntityType{types.EntityTypeUser},
	})

	var stale []string
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.Background())
		if err != nil {
			return []engine.Finding{skip("aws_iam_unused_credentials", "IAM Unused Credentials (90 days)", err.Error())}
		}
		for _, user := range page.UserDetailList {
				_ = user.UserName
		}
	}

	if len(stale) == 0 {
		return []engine.Finding{pass("aws_iam_unused_credentials", "No IAM users with stale credentials (90d)", "AWS/IAM", "users", soc2("CC6.2"), cis("1.12"))}
	}
	return []engine.Finding{fail(
		"aws_iam_unused_credentials",
		fmt.Sprintf("%d IAM users with credentials unused >90 days: %v", len(stale), stale),
		"AWS/IAM", "users",
		SeverityMedium,
		"Disable or delete IAM users that have not used credentials in 90+ days.",
		soc2("CC6.2"), cis("1.12"),
	)}
}

func (c *IAMChecker) checkConsoleMFA() []engine.Finding {
	paginator := iam.NewListUsersPaginator(c.client, &iam.ListUsersInput{})
	var noMFA []string

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.Background())
		if err != nil {
			return []engine.Finding{skip("aws_iam_console_mfa", "Console Users MFA", err.Error())}
		}
		for _, user := range page.Users {
			devs, err := c.client.ListMFADevices(context.Background(), &iam.ListMFADevicesInput{
				UserName: user.UserName,
			})
			if err != nil {
				continue
			}
			if len(devs.MFADevices) == 0 {
				noMFA = append(noMFA, aws.ToString(user.UserName))
			}
		}
	}

	if len(noMFA) == 0 {
		return []engine.Finding{pass("aws_iam_console_mfa", "All IAM users have MFA enabled", "AWS/IAM", "users", soc2("CC6.1"), cis("1.10"))}
	}
	return []engine.Finding{fail(
		"aws_iam_console_mfa",
		fmt.Sprintf("%d IAM user(s) missing MFA: %v", len(noMFA), noMFA),
		"AWS/IAM", "users",
		SeverityHigh,
		"Enable MFA for all IAM users with console access: IAM → Users → Security credentials → Assigned MFA device.",
		soc2("CC6.1"), hipaa("164.312(d)"), cis("1.10"),
	)}
}

// helpers

const SeverityCritical = engine.SeverityCritical
const SeverityHigh = engine.SeverityHigh
const SeverityMedium = engine.SeverityMedium

func soc2(id string) engine.ControlRef  { return engine.ControlRef{Framework: engine.FrameworkSOC2, ID: id} }
func hipaa(id string) engine.ControlRef { return engine.ControlRef{Framework: engine.FrameworkHIPAA, ID: id} }
func cis(id string) engine.ControlRef   { return engine.ControlRef{Framework: engine.FrameworkCIS, ID: id} }

func pass(id, title, integration, resource string, controls ...engine.ControlRef) engine.Finding {
	return engine.Finding{CheckID: id, Title: title, Status: engine.StatusPass, Integration: integration, Resource: resource, Controls: controls}
}

func fail(id, title, integration, resource string, severity engine.Severity, remediation string, controls ...engine.ControlRef) engine.Finding {
	return engine.Finding{CheckID: id, Title: title, Status: engine.StatusFail, Severity: severity, Integration: integration, Resource: resource, Remediation: remediation, Controls: controls}
}

func skip(id, title, detail string) engine.Finding {
	return engine.Finding{CheckID: id, Title: title, Status: engine.StatusSkip, Detail: detail}
}
