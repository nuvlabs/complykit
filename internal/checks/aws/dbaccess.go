package aws

import (
	"context"
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/complykit/complykit/internal/engine"
)

type DBAccessChecker struct {
	iamClient *iam.Client
	smClient  *secretsmanager.Client
}

func NewDBAccessChecker(cfg aws.Config) *DBAccessChecker {
	return &DBAccessChecker{
		iamClient: iam.NewFromConfig(cfg),
		smClient:  secretsmanager.NewFromConfig(cfg),
	}
}

func (c *DBAccessChecker) Integration() string { return "AWS/DB-Access" }

func (c *DBAccessChecker) Run() ([]engine.Finding, error) {
	var findings []engine.Finding
	findings = append(findings, c.checkOverprivilegedIAM()...)
	findings = append(findings, c.checkSecretsManagerRotation()...)
	return findings, nil
}

// broadRDSPolicies are AWS-managed policies that grant unrestricted RDS access.
var broadRDSPolicies = map[string]bool{
	"AmazonRDSFullAccess":           true,
	"AmazonRDSDataFullAccess":       true,
	"AdministratorAccess":           true,
	"PowerUserAccess":               true,
}

// checkOverprivilegedIAM flags IAM users and roles that hold broad RDS permissions
// via managed policies (AmazonRDSFullAccess, AdministratorAccess) or inline policies
// containing rds:* / rds:Connect on resource *.
func (c *DBAccessChecker) checkOverprivilegedIAM() []engine.Finding {
	var flagged []string

	// ── Users ──────────────────────────────────────────────────────────────
	userPaginator := iam.NewListUsersPaginator(c.iamClient, &iam.ListUsersInput{})
	for userPaginator.HasMorePages() {
		page, err := userPaginator.NextPage(context.Background())
		if err != nil {
			return []engine.Finding{skip("aws_rds_overprivileged_iam", "IAM Over-privileged RDS Access", err.Error())}
		}
		for _, user := range page.Users {
			name := aws.ToString(user.UserName)
			if c.hasBroadRDSManagedPolicy(c.iamClient, "user", name) {
				flagged = append(flagged, "user:"+name)
				continue
			}
			if c.hasBroadRDSInlinePolicy(c.iamClient, "user", name) {
				flagged = append(flagged, "user:"+name+" (inline policy)")
			}
		}
	}

	// ── Roles ──────────────────────────────────────────────────────────────
	rolePaginator := iam.NewListRolesPaginator(c.iamClient, &iam.ListRolesInput{})
	for rolePaginator.HasMorePages() {
		page, err := rolePaginator.NextPage(context.Background())
		if err != nil {
			break
		}
		for _, role := range page.Roles {
			name := aws.ToString(role.RoleName)
			// Skip AWS-managed service roles
			if strings.HasPrefix(aws.ToString(role.Path), "/aws-service-role/") {
				continue
			}
			if c.hasBroadRDSManagedPolicy(c.iamClient, "role", name) {
				flagged = append(flagged, "role:"+name)
				continue
			}
			if c.hasBroadRDSInlinePolicy(c.iamClient, "role", name) {
				flagged = append(flagged, "role:"+name+" (inline policy)")
			}
		}
	}

	if len(flagged) == 0 {
		return []engine.Finding{pass("aws_rds_overprivileged_iam",
			"No IAM principals with broad RDS access found",
			"AWS/DB-Access", "iam",
			soc2("CC6.3"), hipaa("164.312(a)(1)"))}
	}
	return []engine.Finding{fail(
		"aws_rds_overprivileged_iam",
		truncateList(flagged, 5)+" have broad RDS access",
		"AWS/DB-Access", truncateList(flagged, 3), SeverityHigh,
		"Replace AmazonRDSFullAccess / AdministratorAccess with least-privilege policies.\n"+
			"Grant only the specific rds:Connect permission scoped to the target DB resource ARN:\n"+
			"  Effect: Allow\n  Action: rds-db:connect\n  Resource: arn:aws:rds-db:<region>:<account>:dbuser/<db-id>/<db-user>",
		soc2("CC6.3"), hipaa("164.312(a)(1)"),
	)}
}

func (c *DBAccessChecker) hasBroadRDSManagedPolicy(client *iam.Client, kind, name string) bool {
	var paginator interface{ HasMorePages() bool }
	var getPolicies func() ([]string, error)

	if kind == "user" {
		p := iam.NewListAttachedUserPoliciesPaginator(client, &iam.ListAttachedUserPoliciesInput{UserName: aws.String(name)})
		getPolicies = func() ([]string, error) {
			var names []string
			for p.HasMorePages() {
				page, err := p.NextPage(context.Background())
				if err != nil {
					return nil, err
				}
				for _, pol := range page.AttachedPolicies {
					names = append(names, aws.ToString(pol.PolicyName))
				}
			}
			return names, nil
		}
		_ = paginator
	} else {
		p := iam.NewListAttachedRolePoliciesPaginator(client, &iam.ListAttachedRolePoliciesInput{RoleName: aws.String(name)})
		getPolicies = func() ([]string, error) {
			var names []string
			for p.HasMorePages() {
				page, err := p.NextPage(context.Background())
				if err != nil {
					return nil, err
				}
				for _, pol := range page.AttachedPolicies {
					names = append(names, aws.ToString(pol.PolicyName))
				}
			}
			return names, nil
		}
	}

	names, err := getPolicies()
	if err != nil {
		return false
	}
	for _, n := range names {
		if broadRDSPolicies[n] {
			return true
		}
	}
	return false
}

func (c *DBAccessChecker) hasBroadRDSInlinePolicy(client *iam.Client, kind, name string) bool {
	var policyNames []string

	if kind == "user" {
		p := iam.NewListUserPoliciesPaginator(client, &iam.ListUserPoliciesInput{UserName: aws.String(name)})
		for p.HasMorePages() {
			page, err := p.NextPage(context.Background())
			if err != nil {
				return false
			}
			policyNames = append(policyNames, page.PolicyNames...)
		}
		for _, pn := range policyNames {
			out, err := client.GetUserPolicy(context.Background(), &iam.GetUserPolicyInput{
				UserName:   aws.String(name),
				PolicyName: aws.String(pn),
			})
			if err != nil {
				continue
			}
			if hasBroadRDSInDoc(aws.ToString(out.PolicyDocument)) {
				return true
			}
		}
	} else {
		p := iam.NewListRolePoliciesPaginator(client, &iam.ListRolePoliciesInput{RoleName: aws.String(name)})
		for p.HasMorePages() {
			page, err := p.NextPage(context.Background())
			if err != nil {
				return false
			}
			policyNames = append(policyNames, page.PolicyNames...)
		}
		for _, pn := range policyNames {
			out, err := client.GetRolePolicy(context.Background(), &iam.GetRolePolicyInput{
				RoleName:   aws.String(name),
				PolicyName: aws.String(pn),
			})
			if err != nil {
				continue
			}
			if hasBroadRDSInDoc(aws.ToString(out.PolicyDocument)) {
				return true
			}
		}
	}
	return false
}

// hasBroadRDSInDoc checks a URL-encoded IAM policy document for rds:* or rds:Connect on *.
func hasBroadRDSInDoc(encoded string) bool {
	doc, err := url.QueryUnescape(encoded)
	if err != nil {
		doc = encoded
	}
	doc = strings.ToLower(doc)
	hasRDSAction := strings.Contains(doc, `"rds:*"`) ||
		strings.Contains(doc, `"rds:connect"`) ||
		strings.Contains(doc, `"rds-db:connect"`)
	hasStar := strings.Contains(doc, `"resource":"*"`) ||
		strings.Contains(doc, `"resource": "*"`)
	return hasRDSAction && hasStar
}

// checkSecretsManagerRotation flags DB secrets in Secrets Manager that do not have rotation enabled.
func (c *DBAccessChecker) checkSecretsManagerRotation() []engine.Finding {
	paginator := secretsmanager.NewListSecretsPaginator(c.smClient, &secretsmanager.ListSecretsInput{})
	var noRotation []string
	dbSecretsFound := 0

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.Background())
		if err != nil {
			return []engine.Finding{skip("aws_secrets_manager_rotation", "Secrets Manager DB Rotation", err.Error())}
		}
		for _, secret := range page.SecretList {
			name := strings.ToLower(aws.ToString(secret.Name))
			desc := strings.ToLower(aws.ToString(secret.Description))
			if !isDBSecret(name, desc) {
				continue
			}
			dbSecretsFound++
			if !aws.ToBool(secret.RotationEnabled) {
				noRotation = append(noRotation, aws.ToString(secret.Name))
			}
		}
	}

	if dbSecretsFound == 0 {
		return nil
	}
	if len(noRotation) == 0 {
		return []engine.Finding{pass("aws_secrets_manager_rotation",
			"All DB secrets in Secrets Manager have rotation enabled",
			"AWS/DB-Access", "secrets",
			soc2("CC6.1"), hipaa("164.312(a)(2)(i)"))}
	}
	return []engine.Finding{fail(
		"aws_secrets_manager_rotation",
		truncateList(noRotation, 5)+" DB secret(s) without rotation",
		"AWS/DB-Access", truncateList(noRotation, 3), SeverityHigh,
		"Enable automatic rotation for database secrets:\n"+
			"  aws secretsmanager rotate-secret --secret-id <name> --rotation-lambda-arn <arn>\n"+
			"  Use the AWS-provided rotation Lambda for RDS:\n"+
			"  https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets.html",
		soc2("CC6.1"), hipaa("164.312(a)(2)(i)"),
	)}
}

func isDBSecret(name, desc string) bool {
	keywords := []string{"rds", "database", "/db/", "-db-", "_db_", "postgres", "mysql", "mongo", "redis"}
	for _, kw := range keywords {
		if strings.Contains(name, kw) || strings.Contains(desc, kw) {
			return true
		}
	}
	return false
}
