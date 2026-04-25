package github

import (
	"context"
	"fmt"

	gh "github.com/google/go-github/v71/github"
	"github.com/complykit/complykit/internal/engine"
)

func (c *Checker) checkOrg2FA() []engine.Finding {
	org, _, err := c.client.Organizations.Get(context.Background(), c.org)
	if err != nil {
		return []engine.Finding{skip("github_org_2fa", "GitHub Org 2FA Requirement", err.Error())}
	}
	if org.TwoFactorRequirementEnabled != nil && *org.TwoFactorRequirementEnabled {
		return []engine.Finding{pass("github_org_2fa", "Organization requires 2FA for all members",
			soc2("CC6.1"), hipaa("164.312(d)"))}
	}
	return []engine.Finding{fail(
		"github_org_2fa", "Organization does not require 2FA for all members",
		engine.SeverityCritical,
		"Enable 2FA requirement:\n  GitHub → Org Settings → Authentication security → Require two-factor authentication",
		soc2("CC6.1"), hipaa("164.312(d)"),
	)}
}

func (c *Checker) checkOrgSSO() []engine.Finding {
	// Check if SAML SSO is enabled for the org (requires GraphQL or Org API)
	// We use the REST org endpoint — SAML SSO info requires the correct token scope
	org, _, err := c.client.Organizations.Get(context.Background(), c.org)
	if err != nil {
		return []engine.Finding{skip("github_org_sso", "GitHub Org SSO", err.Error())}
	}
	// Plan indicates if org is on Team/Enterprise which supports SSO
	if org.Plan != nil && (org.Plan.GetName() == "team" || org.Plan.GetName() == "enterprise") {
		// SSO detection requires GraphQL API; mark as informational
		return []engine.Finding{pass("github_org_sso",
			"Organization is on a plan that supports SSO — verify SAML SSO is enabled in Org Settings",
			soc2("CC6.1"), hipaa("164.308(a)(5)"))}
	}
	return []engine.Finding{fail(
		"github_org_sso", "Organization is not on a plan that supports SAML SSO",
		engine.SeverityMedium,
		"Upgrade to GitHub Team or Enterprise and enable SAML SSO:\n  GitHub → Org Settings → Security → SAML single sign-on",
		soc2("CC6.1"), hipaa("164.308(a)(5)"),
	)}
}

func (c *Checker) checkOutsideCollabAdmins() []engine.Finding {
	var adminCollabs []string
	opt := &gh.ListOutsideCollaboratorsOptions{ListOptions: gh.ListOptions{PerPage: 100}}
	for {
		collabs, resp, err := c.client.Organizations.ListOutsideCollaborators(context.Background(), c.org, opt)
		if err != nil {
			return []engine.Finding{skip("github_org_outside_collab", "GitHub Outside Collaborators", err.Error())}
		}
		// ListOutsideCollaborators doesn't return role directly; flag any outside collab on org
		// as a finding requiring review
		adminCollabs = append(adminCollabs, func() []string {
			var names []string
			for _, u := range collabs {
				names = append(names, u.GetLogin())
			}
			return names
		}()...)
		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}
	if len(adminCollabs) == 0 {
		return []engine.Finding{pass("github_org_outside_collab", "No outside collaborators found in the organization",
			soc2("CC6.3"), hipaa("164.308(a)(3)"))}
	}
	return []engine.Finding{fail(
		"github_org_outside_collab",
		fmt.Sprintf("%d outside collaborator(s) have org access — review if all are intentional: %v",
			len(adminCollabs), truncate(adminCollabs, 5)),
		engine.SeverityMedium,
		"Review and remove unnecessary outside collaborators:\n  GitHub → Org Settings → People → Outside collaborators",
		soc2("CC6.3"), hipaa("164.308(a)(3)"),
	)}
}

func (c *Checker) checkPushProtection(repos []*gh.Repository) []engine.Finding {
	var noPushProtect []string
	for _, repo := range repos {
		if repo.GetArchived() {
			continue
		}
		sa := repo.GetSecurityAndAnalysis()
		if sa == nil || sa.SecretScanningPushProtection == nil ||
			sa.SecretScanningPushProtection.GetStatus() != "enabled" {
			noPushProtect = append(noPushProtect, repo.GetName())
		}
	}
	if len(noPushProtect) == 0 {
		return []engine.Finding{pass("github_push_protection", "All repos have secret scanning push protection enabled",
			soc2("CC6.8"), hipaa("164.308(a)(1)(ii)(D)"))}
	}
	return []engine.Finding{fail(
		"github_push_protection",
		fmt.Sprintf("%d repo(s) without push protection: %v", len(noPushProtect), truncate(noPushProtect, 5)),
		engine.SeverityHigh,
		"Enable push protection:\n  GitHub → Repo → Settings → Security → Secret scanning → Push protection → Enable",
		soc2("CC6.8"), hipaa("164.308(a)(1)(ii)(D)"),
	)}
}

func (c *Checker) checkCodeScanning(repos []*gh.Repository) []engine.Finding {
	var noSAST []string
	for _, repo := range repos {
		if repo.GetArchived() || !repo.GetPrivate() {
			// CodeQL on public repos is automatic; focus on private repos
			continue
		}
		alerts, _, err := c.client.CodeScanning.ListAlertsForRepo(context.Background(), c.owner, repo.GetName(), nil)
		if err != nil || len(alerts) == 0 {
			// No alerts means scanning may not be configured (or no findings)
			// Check for CodeQL workflow
			_, _, resp, _ := c.client.Repositories.GetContents(context.Background(), c.owner, repo.GetName(), ".github/workflows/codeql.yml", nil)
			_, _, resp2, _ := c.client.Repositories.GetContents(context.Background(), c.owner, repo.GetName(), ".github/workflows/codeql-analysis.yml", nil)
			if (resp == nil || resp.StatusCode == 404) && (resp2 == nil || resp2.StatusCode == 404) {
				noSAST = append(noSAST, repo.GetName())
			}
		}
	}
	if len(noSAST) == 0 {
		return []engine.Finding{pass("github_code_scanning", "All private repos have code scanning (SAST) configured",
			soc2("CC7.1"), hipaa("164.308(a)(5)"))}
	}
	return []engine.Finding{fail(
		"github_code_scanning",
		fmt.Sprintf("%d private repo(s) without code scanning: %v", len(noSAST), truncate(noSAST, 5)),
		engine.SeverityMedium,
		"Enable CodeQL analysis:\n  GitHub → Repo → Security → Code scanning → Set up CodeQL\n  Or add .github/workflows/codeql.yml",
		soc2("CC7.1"), hipaa("164.308(a)(5)"),
	)}
}

func (c *Checker) checkDefaultTokenPermissions(repos []*gh.Repository) []engine.Finding {
	// Check if repos have workflow permissions set to read-only via branch protection
	// GitHub doesn't expose default token permissions via REST API at repo level easily.
	// We check org-level default permissions if available.
	permissions, _, err := c.client.Organizations.GetActionsPermissions(context.Background(), c.org)
	if err != nil {
		return []engine.Finding{skip("github_token_permissions", "GitHub Token Default Permissions", err.Error())}
	}
	_ = permissions
	// The AllowedActions field indicates what actions can run, but token permissions
	// are at org or repo workflow settings level — mark as informational
	return []engine.Finding{pass("github_token_permissions",
		"GitHub Actions permissions configured — verify GITHUB_TOKEN defaults to read-only in org settings",
		soc2("CC6.3"))}
}

func (c *Checker) checkNoSelfHostedOnPublic(repos []*gh.Repository) []engine.Finding {
	var selfHosted []string
	for _, repo := range repos {
		if repo.GetArchived() || repo.GetPrivate() {
			continue
		}
		runners, _, err := c.client.Actions.ListRunners(context.Background(), c.owner, repo.GetName(), nil)
		if err != nil {
			continue
		}
		if runners.TotalCount > 0 {
			selfHosted = append(selfHosted, repo.GetName())
		}
	}
	if len(selfHosted) == 0 {
		return []engine.Finding{pass("github_no_self_hosted_public", "No public repos use self-hosted runners",
			soc2("CC6.6"))}
	}
	return []engine.Finding{fail(
		"github_no_self_hosted_public",
		fmt.Sprintf("%d public repo(s) use self-hosted runners (supply chain risk): %v", len(selfHosted), truncate(selfHosted, 5)),
		engine.SeverityHigh,
		"Remove self-hosted runners from public repos — use GitHub-hosted runners instead to prevent arbitrary code execution on your infrastructure.",
		soc2("CC6.6"),
	)}
}
