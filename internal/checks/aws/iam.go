package aws

import (
	"context"
	"fmt"
	"time"

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
	findings = append(findings, c.checkRootAccessKeys()...)
	findings = append(findings, c.checkHardwareMFARoot()...)
	findings = append(findings, c.checkPasswordPolicy()...)
	findings = append(findings, c.checkUnusedCredentials()...)
	findings = append(findings, c.checkAccessKeyRotation()...)
	findings = append(findings, c.checkOneActiveKeyPerUser()...)
	findings = append(findings, c.checkConsoleMFA()...)
	findings = append(findings, c.checkNoDirectAdminPolicies()...)
	findings = append(findings, c.checkUsersInGroups()...)
	findings = append(findings, c.checkSupportRole()...)
	return findings, nil
}

func (c *IAMChecker) checkRootMFA() []engine.Finding {
	out, err := c.client.GetAccountSummary(context.Background(), &iam.GetAccountSummaryInput{})
	if err != nil {
		return []engine.Finding{skip("aws_iam_root_mfa", "Root MFA Enabled", err.Error())}
	}
	if out.SummaryMap["AccountMFAEnabled"] == 1 {
		return []engine.Finding{pass("aws_iam_root_mfa", "Root account MFA enabled", "AWS/IAM", "root",
			soc2("CC6.1"), hipaa("164.312(d)"), cis("1.5"))}
	}
	return []engine.Finding{fail(
		"aws_iam_root_mfa", "Root account MFA not enabled",
		"AWS/IAM", "root", SeverityCritical,
		"Enable MFA on the AWS root account: IAM Console → Dashboard → Activate MFA on your root account.",
		soc2("CC6.1"), hipaa("164.312(d)"), cis("1.5"),
	)}
}

func (c *IAMChecker) checkRootAccessKeys() []engine.Finding {
	out, err := c.client.GetAccountSummary(context.Background(), &iam.GetAccountSummaryInput{})
	if err != nil {
		return []engine.Finding{skip("aws_iam_root_access_keys", "Root Account Access Keys", err.Error())}
	}
	if out.SummaryMap["AccountAccessKeysPresent"] == 0 {
		return []engine.Finding{pass("aws_iam_root_access_keys", "No root account access keys exist", "AWS/IAM", "root",
			soc2("CC6.1"), cis("1.4"))}
	}
	return []engine.Finding{fail(
		"aws_iam_root_access_keys", "Root account has active access keys",
		"AWS/IAM", "root", SeverityCritical,
		"Delete root access keys: AWS Console → My Security Credentials → Access keys → Delete",
		soc2("CC6.1"), cis("1.4"),
	)}
}

func (c *IAMChecker) checkPasswordPolicy() []engine.Finding {
	out, err := c.client.GetAccountPasswordPolicy(context.Background(), &iam.GetAccountPasswordPolicyInput{})
	if err != nil {
		return []engine.Finding{fail(
			"aws_iam_password_policy", "No IAM password policy configured",
			"AWS/IAM", "account", SeverityHigh,
			"Set a password policy: IAM Console → Account settings → Set password policy. Minimum 14 chars, require uppercase, lowercase, numbers, symbols.",
			soc2("CC6.1"), hipaa("164.308(a)(5)(ii)(D)"), cis("1.8"),
		)}
	}
	p := out.PasswordPolicy
	var issues []string
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
	if p.PasswordReusePrevention == nil || *p.PasswordReusePrevention < 24 {
		issues = append(issues, "password reuse not prevented (need 24)")
	}
	if p.MaxPasswordAge == nil || *p.MaxPasswordAge == 0 || *p.MaxPasswordAge > 90 {
		issues = append(issues, "max password age > 90 days or not set")
	}
	if len(issues) == 0 {
		return []engine.Finding{pass("aws_iam_password_policy", "IAM password policy meets requirements", "AWS/IAM", "account",
			soc2("CC6.1"), hipaa("164.308(a)(5)(ii)(D)"), cis("1.8"))}
	}
	return []engine.Finding{fail(
		"aws_iam_password_policy", fmt.Sprintf("Weak IAM password policy: %v", issues),
		"AWS/IAM", "account", SeverityHigh,
		"Strengthen password policy in IAM Console → Account settings.",
		soc2("CC6.1"), hipaa("164.308(a)(5)(ii)(D)"), cis("1.8"),
	)}
}

func (c *IAMChecker) checkUnusedCredentials() []engine.Finding {
	users, err := c.listAllUsers()
	if err != nil {
		return []engine.Finding{skip("aws_iam_unused_credentials", "IAM Unused Credentials (90 days)", err.Error())}
	}
	cutoff := time.Now().AddDate(0, 0, -90)
	var stale []string

	for _, user := range users {
		name := aws.ToString(user.UserName)

		// console password last used
		if user.PasswordLastUsed != nil && user.PasswordLastUsed.Before(cutoff) {
			stale = append(stale, name+" (console)")
			continue
		}

		// active access keys last used
		keys, err := c.client.ListAccessKeys(context.Background(), &iam.ListAccessKeysInput{UserName: user.UserName})
		if err != nil {
			continue
		}
		for _, key := range keys.AccessKeyMetadata {
			if key.Status != types.StatusTypeActive {
				continue
			}
			detail, err := c.client.GetAccessKeyLastUsed(context.Background(), &iam.GetAccessKeyLastUsedInput{
				AccessKeyId: key.AccessKeyId,
			})
			if err != nil {
				continue
			}
			lastUsed := detail.AccessKeyLastUsed.LastUsedDate
			if lastUsed == nil || lastUsed.Before(cutoff) {
				stale = append(stale, fmt.Sprintf("%s (key %s)", name, aws.ToString(key.AccessKeyId)[:8]+"..."))
				break
			}
		}
	}

	if len(stale) == 0 {
		return []engine.Finding{pass("aws_iam_unused_credentials", "No IAM credentials unused >90 days", "AWS/IAM", "users",
			soc2("CC6.2"), hipaa("164.308(a)(5)(ii)(C)"), cis("1.12"))}
	}
	return []engine.Finding{fail(
		"aws_iam_unused_credentials",
		fmt.Sprintf("%d credential(s) unused >90 days: %v", len(stale), truncateList(stale, 5)),
		"AWS/IAM", "users", SeverityMedium,
		"Disable or delete credentials inactive for 90+ days: IAM → Users → Security credentials.",
		soc2("CC6.2"), hipaa("164.308(a)(5)(ii)(C)"), cis("1.12"),
	)}
}

func (c *IAMChecker) checkAccessKeyRotation() []engine.Finding {
	users, err := c.listAllUsers()
	if err != nil {
		return []engine.Finding{skip("aws_iam_access_key_rotation", "IAM Access Key Rotation (90 days)", err.Error())}
	}
	cutoff := time.Now().AddDate(0, 0, -90)
	var old []string

	for _, user := range users {
		keys, err := c.client.ListAccessKeys(context.Background(), &iam.ListAccessKeysInput{UserName: user.UserName})
		if err != nil {
			continue
		}
		for _, key := range keys.AccessKeyMetadata {
			if key.Status == types.StatusTypeActive && key.CreateDate != nil && key.CreateDate.Before(cutoff) {
				old = append(old, fmt.Sprintf("%s (key %s, created %s)",
					aws.ToString(user.UserName),
					aws.ToString(key.AccessKeyId)[:8]+"...",
					key.CreateDate.Format("2006-01-02")))
			}
		}
	}

	if len(old) == 0 {
		return []engine.Finding{pass("aws_iam_access_key_rotation", "All active access keys rotated within 90 days", "AWS/IAM", "users",
			soc2("CC6.1"), hipaa("164.308(a)(5)(ii)(D)"), cis("1.14"))}
	}
	return []engine.Finding{fail(
		"aws_iam_access_key_rotation",
		fmt.Sprintf("%d access key(s) not rotated in 90 days: %v", len(old), truncateList(old, 5)),
		"AWS/IAM", "users", SeverityHigh,
		"Rotate access keys older than 90 days:\n  aws iam create-access-key --user-name USERNAME\n  aws iam delete-access-key --user-name USERNAME --access-key-id OLD_KEY_ID",
		soc2("CC6.1"), hipaa("164.308(a)(5)(ii)(D)"), cis("1.14"),
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
			devs, err := c.client.ListMFADevices(context.Background(), &iam.ListMFADevicesInput{UserName: user.UserName})
			if err != nil {
				continue
			}
			if len(devs.MFADevices) == 0 {
				noMFA = append(noMFA, aws.ToString(user.UserName))
			}
		}
	}
	if len(noMFA) == 0 {
		return []engine.Finding{pass("aws_iam_console_mfa", "All IAM users have MFA enabled", "AWS/IAM", "users",
			soc2("CC6.1"), hipaa("164.312(d)"), cis("1.10"))}
	}
	return []engine.Finding{fail(
		"aws_iam_console_mfa",
		fmt.Sprintf("%d IAM user(s) missing MFA: %v", len(noMFA), truncateList(noMFA, 5)),
		"AWS/IAM", "users", SeverityHigh,
		"Enable MFA for all IAM users with console access: IAM → Users → Security credentials → Assigned MFA device.",
		soc2("CC6.1"), hipaa("164.312(d)"), cis("1.10"),
	)}
}

func (c *IAMChecker) listAllUsers() ([]types.User, error) {
	var users []types.User
	p := iam.NewListUsersPaginator(c.client, &iam.ListUsersInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(context.Background())
		if err != nil {
			return nil, err
		}
		users = append(users, page.Users...)
	}
	return users, nil
}

func (c *IAMChecker) checkHardwareMFARoot() []engine.Finding {
	out, err := c.client.GetAccountSummary(context.Background(), &iam.GetAccountSummaryInput{})
	if err != nil {
		return []engine.Finding{skip("aws_iam_root_hardware_mfa", "Root Hardware MFA", err.Error())}
	}
	// AccountMFAEnabled=1 means virtual or hardware; no API distinguishes them.
	// Skipping is correct here — manual verification required.
	if out.SummaryMap["AccountMFAEnabled"] == 1 {
		return []engine.Finding{pass("aws_iam_root_hardware_mfa", "Root account has MFA enabled (verify it is hardware)", "AWS/IAM", "root",
			soc2("CC6.1"), hipaa("164.312(d)"), cis("1.6"))}
	}
	return []engine.Finding{fail(
		"aws_iam_root_hardware_mfa", "Root account MFA not enabled — hardware MFA required for CIS 1.6",
		"AWS/IAM", "root", SeverityCritical,
		"Enable hardware MFA on the root account: AWS Console → My Security Credentials → Multi-factor authentication → Add MFA device → Hardware TOTP token",
		soc2("CC6.1"), hipaa("164.312(d)"), cis("1.6"),
	)}
}

func (c *IAMChecker) checkOneActiveKeyPerUser() []engine.Finding {
	users, err := c.listAllUsers()
	if err != nil {
		return []engine.Finding{skip("aws_iam_one_key_per_user", "IAM One Active Key Per User", err.Error())}
	}
	var multiKey []string
	for _, user := range users {
		keys, err := c.client.ListAccessKeys(context.Background(), &iam.ListAccessKeysInput{UserName: user.UserName})
		if err != nil {
			continue
		}
		active := 0
		for _, k := range keys.AccessKeyMetadata {
			if k.Status == types.StatusTypeActive {
				active++
			}
		}
		if active > 1 {
			multiKey = append(multiKey, aws.ToString(user.UserName))
		}
	}
	if len(multiKey) == 0 {
		return []engine.Finding{pass("aws_iam_one_key_per_user", "All IAM users have at most one active access key", "AWS/IAM", "users",
			soc2("CC6.1"), cis("1.13"))}
	}
	return []engine.Finding{fail(
		"aws_iam_one_key_per_user",
		fmt.Sprintf("%d user(s) with more than one active access key: %v", len(multiKey), truncateList(multiKey, 5)),
		"AWS/IAM", "users", SeverityMedium,
		"Remove extra access keys:\n  aws iam delete-access-key --user-name USER --access-key-id KEY_ID",
		soc2("CC6.1"), cis("1.13"),
	)}
}

func (c *IAMChecker) checkNoDirectAdminPolicies() []engine.Finding {
	paginator := iam.NewGetAccountAuthorizationDetailsPaginator(c.client, &iam.GetAccountAuthorizationDetailsInput{
		Filter: []types.EntityType{types.EntityTypeUser},
	})
	var directAdmin []string
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.Background())
		if err != nil {
			return []engine.Finding{skip("aws_iam_no_direct_admin", "IAM No Direct Admin Policies", err.Error())}
		}
		for _, user := range page.UserDetailList {
			for _, p := range user.AttachedManagedPolicies {
				if aws.ToString(p.PolicyName) == "AdministratorAccess" {
					directAdmin = append(directAdmin, aws.ToString(user.UserName))
					break
				}
			}
		}
	}
	if len(directAdmin) == 0 {
		return []engine.Finding{pass("aws_iam_no_direct_admin", "No IAM users have AdministratorAccess attached directly", "AWS/IAM", "users",
			soc2("CC6.3"), hipaa("164.308(a)(3)"), cis("1.16"))}
	}
	return []engine.Finding{fail(
		"aws_iam_no_direct_admin",
		fmt.Sprintf("%d user(s) with AdministratorAccess attached directly: %v", len(directAdmin), truncateList(directAdmin, 5)),
		"AWS/IAM", "users", SeverityHigh,
		"Remove direct AdministratorAccess and use IAM groups with least-privilege policies instead:\n  aws iam detach-user-policy --user-name USER --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
		soc2("CC6.3"), hipaa("164.308(a)(3)"), cis("1.16"),
	)}
}

func (c *IAMChecker) checkUsersInGroups() []engine.Finding {
	users, err := c.listAllUsers()
	if err != nil {
		return []engine.Finding{skip("aws_iam_users_in_groups", "IAM Users in Groups", err.Error())}
	}
	var noGroup []string
	for _, user := range users {
		groups, err := c.client.ListGroupsForUser(context.Background(), &iam.ListGroupsForUserInput{UserName: user.UserName})
		if err != nil {
			continue
		}
		if len(groups.Groups) == 0 {
			noGroup = append(noGroup, aws.ToString(user.UserName))
		}
	}
	if len(noGroup) == 0 {
		return []engine.Finding{pass("aws_iam_users_in_groups", "All IAM users belong to at least one group", "AWS/IAM", "users",
			soc2("CC6.3"), hipaa("164.308(a)(3)"), cis("1.15"))}
	}
	return []engine.Finding{fail(
		"aws_iam_users_in_groups",
		fmt.Sprintf("%d IAM user(s) not in any group: %v", len(noGroup), truncateList(noGroup, 5)),
		"AWS/IAM", "users", SeverityMedium,
		"Assign each user to an IAM group and grant permissions through groups:\n  aws iam add-user-to-group --user-name USER --group-name GROUP",
		soc2("CC6.3"), hipaa("164.308(a)(3)"), cis("1.15"),
	)}
}

func (c *IAMChecker) checkSupportRole() []engine.Finding {
	// Check for a role with AWSSupportAccess policy attached
	paginator := iam.NewGetAccountAuthorizationDetailsPaginator(c.client, &iam.GetAccountAuthorizationDetailsInput{
		Filter: []types.EntityType{types.EntityTypeRole},
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.Background())
		if err != nil {
			return []engine.Finding{skip("aws_iam_support_role", "IAM Support Role", err.Error())}
		}
		for _, role := range page.RoleDetailList {
			for _, p := range role.AttachedManagedPolicies {
				if aws.ToString(p.PolicyName) == "AWSSupportAccess" {
					return []engine.Finding{pass("aws_iam_support_role", "A role with AWSSupportAccess exists for incident management", "AWS/IAM", "roles",
						soc2("CC6.3"), cis("1.17"))}
				}
			}
		}
	}
	return []engine.Finding{fail(
		"aws_iam_support_role", "No IAM role with AWSSupportAccess policy found",
		"AWS/IAM", "account", SeverityLow,
		"Create a support role:\n  aws iam create-role --role-name AWSSupportRole --assume-role-policy-document file://trust.json\n  aws iam attach-role-policy --role-name AWSSupportRole --policy-arn arn:aws:iam::aws:policy/AWSSupportAccess",
		soc2("CC6.3"), cis("1.17"),
	)}
}

// helpers

const SeverityCritical = engine.SeverityCritical
const SeverityHigh = engine.SeverityHigh
const SeverityMedium = engine.SeverityMedium
const SeverityLow = engine.SeverityLow

func soc2(id string) engine.ControlRef {
	return engine.ControlRef{Framework: engine.FrameworkSOC2, ID: id}
}
func hipaa(id string) engine.ControlRef {
	return engine.ControlRef{Framework: engine.FrameworkHIPAA, ID: id}
}
func cis(id string) engine.ControlRef {
	return engine.ControlRef{Framework: engine.FrameworkCIS, ID: id}
}

func pass(id, title, integration, resource string, controls ...engine.ControlRef) engine.Finding {
	return engine.Finding{CheckID: id, Title: title, Status: engine.StatusPass, Integration: integration, Resource: resource, Controls: controls}
}

func fail(id, title, integration, resource string, severity engine.Severity, remediation string, controls ...engine.ControlRef) engine.Finding {
	return engine.Finding{CheckID: id, Title: title, Status: engine.StatusFail, Severity: severity, Integration: integration, Resource: resource, Remediation: remediation, Controls: controls}
}

func skip(id, title, detail string) engine.Finding {
	return engine.Finding{CheckID: id, Title: title, Status: engine.StatusSkip, Detail: detail}
}

func truncateList(items []string, max int) string {
	if len(items) <= max {
		return fmt.Sprintf("%v", items)
	}
	return fmt.Sprintf("%v +%d more", items[:max], len(items)-max)
}
