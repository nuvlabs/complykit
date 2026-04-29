package github

import (
	"context"
	"fmt"
	"os"
	"strings"

	gh "github.com/google/go-github/v71/github"
	"golang.org/x/oauth2"

	"github.com/complykit/complykit/internal/engine"
)

type Checker struct {
	client *gh.Client
	org    string
	owner  string
}

func NewChecker(token, orgOrOwner string) *Checker {
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	tc := oauth2.NewClient(context.Background(), ts)
	return &Checker{
		client: gh.NewClient(tc),
		org:    orgOrOwner,
		owner:  orgOrOwner,
	}
}

func NewCheckerFromEnv() *Checker {
	token := os.Getenv("GITHUB_TOKEN")
	owner := os.Getenv("GITHUB_OWNER")
	if token == "" || owner == "" {
		return nil
	}
	return NewChecker(token, owner)
}

func (c *Checker) Integration() string { return "GitHub" }

func (c *Checker) Run() ([]engine.Finding, error) {
	repos, err := c.listRepos()
	if err != nil {
		return []engine.Finding{skip("github_auth", "GitHub Access", err.Error())}, nil
	}

	var findings []engine.Finding
	findings = append(findings, c.checkBranchProtection(repos)...)
	findings = append(findings, c.checkRequiredStatusChecks(repos)...)
	findings = append(findings, c.checkPublicRepos(repos)...)
	findings = append(findings, c.checkDependabot(repos)...)
	findings = append(findings, c.checkSecretScanning(repos)...)
	findings = append(findings, c.checkActionsVersionPinning(repos)...)
	findings = append(findings, c.checkPullRequestTarget(repos)...)
	findings = append(findings, c.checkEnvironmentProtection(repos)...)
	findings = append(findings, c.checkDefaultTokenPermissions(repos)...)
	findings = append(findings, c.checkNoSelfHostedOnPublic(repos)...)
	findings = append(findings, c.checkPushProtection(repos)...)
	findings = append(findings, c.checkCodeScanning(repos)...)
	findings = append(findings, c.checkOrg2FA()...)
	findings = append(findings, c.checkOrgSSO()...)
	findings = append(findings, c.checkOutsideCollabAdmins()...)
	// P1 additions
	findings = append(findings, c.checkCodeowners(repos)...)
	findings = append(findings, c.checkDependabotAlerts(repos)...)
	findings = append(findings, c.checkBranchDismissStale(repos)...)
	findings = append(findings, c.checkSignedCommits(repos)...)
	// P2 additions
	findings = append(findings, c.checkOIDCCloudAuth(repos)...)
	findings = append(findings, c.checkDBCredentialsInCode()...)
	return findings, nil
}

func (c *Checker) listRepos() ([]*gh.Repository, error) {
	var all []*gh.Repository
	opts := &gh.RepositoryListByOrgOptions{ListOptions: gh.ListOptions{PerPage: 100}}
	for {
		repos, resp, err := c.client.Repositories.ListByOrg(context.Background(), c.org, opts)
		if err != nil {
			// fallback: try as user
			urepos, _, uerr := c.client.Repositories.List(context.Background(), c.owner, &gh.RepositoryListOptions{ListOptions: gh.ListOptions{PerPage: 100}})
			if uerr != nil {
				return nil, fmt.Errorf("cannot list repos: %v", err)
			}
			return urepos, nil
		}
		all = append(all, repos...)
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return all, nil
}

func (c *Checker) checkBranchProtection(repos []*gh.Repository) []engine.Finding {
	var unprotected []string
	for _, repo := range repos {
		if repo.GetArchived() {
			continue
		}
		branch := repo.GetDefaultBranch()
		if branch == "" {
			branch = "main"
		}
		prot, _, err := c.client.Repositories.GetBranchProtection(context.Background(), c.owner, repo.GetName(), branch)
		if err != nil || prot == nil {
			unprotected = append(unprotected, repo.GetName())
			continue
		}
		if prot.RequiredPullRequestReviews == nil || prot.RequiredPullRequestReviews.RequiredApprovingReviewCount < 1 {
			unprotected = append(unprotected, repo.GetName()+" (no required reviews)")
		}
	}

	if len(unprotected) == 0 {
		return []engine.Finding{pass("github_branch_protection", "All repos have branch protection with required reviews",
			soc2("CC8.1"), hipaa("164.308(a)(3)(i)"))}
	}
	return []engine.Finding{fail(
		"github_branch_protection",
		fmt.Sprintf("%d repo(s) missing branch protection: %v", len(unprotected), truncate(unprotected, 5)),
		engine.SeverityHigh,
		"Enable branch protection on default branch:\n  GitHub → Repo → Settings → Branches → Add rule\n  Enable: Require pull request reviews (min 1 approver)",
		soc2("CC8.1"), hipaa("164.308(a)(3)(i)"),
	)}
}

func (c *Checker) checkRequiredStatusChecks(repos []*gh.Repository) []engine.Finding {
	var missing []string
	for _, repo := range repos {
		if repo.GetArchived() {
			continue
		}
		branch := repo.GetDefaultBranch()
		if branch == "" {
			branch = "main"
		}
		prot, _, err := c.client.Repositories.GetBranchProtection(context.Background(), c.owner, repo.GetName(), branch)
		ctxLen := 0
		if prot != nil && prot.RequiredStatusChecks != nil && prot.RequiredStatusChecks.Contexts != nil {
			ctxLen = len(*prot.RequiredStatusChecks.Contexts)
		}
		if err != nil || prot == nil || prot.RequiredStatusChecks == nil || ctxLen == 0 {
			missing = append(missing, repo.GetName())
		}
	}

	if len(missing) == 0 {
		return []engine.Finding{pass("github_required_status_checks", "All repos require status checks before merge",
			soc2("CC8.1"))}
	}
	return []engine.Finding{fail(
		"github_required_status_checks",
		fmt.Sprintf("%d repo(s) missing required status checks: %v", len(missing), truncate(missing, 5)),
		engine.SeverityMedium,
		"Enable required status checks:\n  GitHub → Repo → Settings → Branches → Branch protection rule\n  Enable: Require status checks to pass before merging",
		soc2("CC8.1"),
	)}
}

func (c *Checker) checkPublicRepos(repos []*gh.Repository) []engine.Finding {
	var public []string
	for _, repo := range repos {
		if !repo.GetPrivate() {
			public = append(public, repo.GetName())
		}
	}
	if len(public) == 0 {
		return []engine.Finding{pass("github_public_repos", "No unexpected public repositories",
			soc2("CC6.6"), hipaa("164.308(a)(4)(i)"))}
	}
	return []engine.Finding{fail(
		"github_public_repos",
		fmt.Sprintf("%d public repo(s) — verify intentional: %v", len(public), truncate(public, 5)),
		engine.SeverityMedium,
		"Review each public repo and make private if it contains internal code:\n  GitHub → Repo → Settings → Danger Zone → Change visibility",
		soc2("CC6.6"), hipaa("164.308(a)(4)(i)"),
	)}
}

func (c *Checker) checkDependabot(repos []*gh.Repository) []engine.Finding {
	var missing []string
	for _, repo := range repos {
		if repo.GetArchived() {
			continue
		}
		_, _, resp, err := c.client.Repositories.GetContents(context.Background(), c.owner, repo.GetName(), ".github/dependabot.yml", nil)
		if err != nil {
			_, _, resp2, _ := c.client.Repositories.GetContents(context.Background(), c.owner, repo.GetName(), ".github/dependabot.yaml", nil)
			if resp2 == nil || resp2.StatusCode == 404 {
				if resp == nil || resp.StatusCode == 404 {
					missing = append(missing, repo.GetName())
				}
			}
		}
	}
	if len(missing) == 0 {
		return []engine.Finding{pass("github_dependabot", "All repos have Dependabot configured", soc2("CC7.1"))}
	}
	return []engine.Finding{fail(
		"github_dependabot",
		fmt.Sprintf("%d repo(s) missing Dependabot config: %v", len(missing), truncate(missing, 5)),
		engine.SeverityMedium,
		"Add .github/dependabot.yml to enable automated dependency updates:\n  version: 2\n  updates:\n    - package-ecosystem: npm\n      directory: /\n      schedule:\n        interval: weekly",
		soc2("CC7.1"),
	)}
}

func (c *Checker) checkSecretScanning(repos []*gh.Repository) []engine.Finding {
	var disabled []string
	for _, repo := range repos {
		if repo.GetArchived() || repo.GetPrivate() {
			continue
		}
		ss := repo.GetSecurityAndAnalysis()
		if ss == nil || ss.SecretScanning == nil || ss.SecretScanning.GetStatus() != "enabled" {
			disabled = append(disabled, repo.GetName())
		}
	}
	if len(disabled) == 0 {
		return []engine.Finding{pass("github_secret_scanning", "Secret scanning enabled on public repos",
			soc2("CC6.8"), hipaa("164.308(a)(1)(ii)(D)"))}
	}
	return []engine.Finding{fail(
		"github_secret_scanning",
		fmt.Sprintf("%d public repo(s) without secret scanning: %v", len(disabled), truncate(disabled, 5)),
		engine.SeverityHigh,
		"Enable secret scanning:\n  GitHub → Repo → Settings → Security → Secret scanning → Enable",
		soc2("CC6.8"), hipaa("164.308(a)(1)(ii)(D)"),
	)}
}

func pass(id, title string, controls ...engine.ControlRef) engine.Finding {
	return engine.Finding{CheckID: id, Title: title, Status: engine.StatusPass, Integration: "GitHub", Controls: controls}
}

func fail(id, title string, severity engine.Severity, remediation string, controls ...engine.ControlRef) engine.Finding {
	return engine.Finding{CheckID: id, Title: title, Status: engine.StatusFail, Severity: severity, Integration: "GitHub", Remediation: remediation, Controls: controls}
}

func skip(id, title, detail string) engine.Finding {
	return engine.Finding{CheckID: id, Title: title, Status: engine.StatusSkip, Integration: "GitHub", Detail: detail}
}

func soc2(id string) engine.ControlRef {
	return engine.ControlRef{Framework: engine.FrameworkSOC2, ID: id}
}

func hipaa(id string) engine.ControlRef {
	return engine.ControlRef{Framework: engine.FrameworkHIPAA, ID: id}
}

func truncate(items []string, max int) string {
	if len(items) <= max {
		return strings.Join(items, ", ")
	}
	return strings.Join(items[:max], ", ") + fmt.Sprintf(" +%d more", len(items)-max)
}
