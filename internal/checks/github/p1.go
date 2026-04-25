package github

import (
	"context"
	"fmt"

	gh "github.com/google/go-github/v71/github"
	"github.com/complykit/complykit/internal/engine"
)

func (c *Checker) checkCodeowners(repos []*gh.Repository) []engine.Finding {
	var missing []string
	for _, repo := range repos {
		if repo.GetArchived() {
			continue
		}
		paths := []string{"CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"}
		found := false
		for _, p := range paths {
			_, _, resp, _ := c.client.Repositories.GetContents(
				context.Background(), c.owner, repo.GetName(), p, nil)
			if resp != nil && resp.StatusCode == 200 {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, repo.GetName())
		}
	}
	if len(missing) == 0 {
		return []engine.Finding{pass("github_codeowners", "All repos have a CODEOWNERS file",
			soc2("CC8.1"))}
	}
	return []engine.Finding{fail(
		"github_codeowners",
		fmt.Sprintf("%d repo(s) missing CODEOWNERS: %v", len(missing), truncate(missing, 5)),
		engine.SeverityMedium,
		"Create a CODEOWNERS file to require review from specific teams:\n  # .github/CODEOWNERS\n  *  @org/security-team\n  /src/payments/ @org/payments-team",
		soc2("CC8.1"),
	)}
}

func (c *Checker) checkDependabotAlerts(repos []*gh.Repository) []engine.Finding {
	var noAlerts []string
	for _, repo := range repos {
		if repo.GetArchived() {
			continue
		}
		_, _, err := c.client.Dependabot.GetRepoPublicKey(
			context.Background(), c.owner, repo.GetName())
		// If we can access Dependabot API, alerts are enabled
		// A 403/404 with specific message means disabled
		if err != nil {
			errStr := err.Error()
			if contains(errStr, "403") || contains(errStr, "vulnerability alerts") {
				noAlerts = append(noAlerts, repo.GetName())
			}
		}
	}
	if len(noAlerts) == 0 {
		return []engine.Finding{pass("github_dependabot_alerts", "Dependabot security alerts accessible on all repos",
			soc2("CC7.1"), hipaa("164.308(a)(5)"))}
	}
	return []engine.Finding{fail(
		"github_dependabot_alerts",
		fmt.Sprintf("%d repo(s) may not have Dependabot alerts enabled: %v", len(noAlerts), truncate(noAlerts, 5)),
		engine.SeverityMedium,
		"Enable Dependabot alerts:\n  GitHub → Repo → Settings → Security & analysis → Dependabot alerts → Enable",
		soc2("CC7.1"), hipaa("164.308(a)(5)"),
	)}
}

func (c *Checker) checkBranchDismissStale(repos []*gh.Repository) []engine.Finding {
	var noDismiss []string
	for _, repo := range repos {
		if repo.GetArchived() {
			continue
		}
		branch := repo.GetDefaultBranch()
		if branch == "" {
			branch = "main"
		}
		prot, _, err := c.client.Repositories.GetBranchProtection(
			context.Background(), c.owner, repo.GetName(), branch)
		if err != nil || prot == nil {
			continue // no protection at all — caught by branch_protection check
		}
		if prot.RequiredPullRequestReviews == nil ||
			!prot.RequiredPullRequestReviews.DismissStaleReviews {
			noDismiss = append(noDismiss, repo.GetName())
		}
	}
	if len(noDismiss) == 0 {
		return []engine.Finding{pass("github_branch_dismiss_stale", "All repos dismiss stale reviews on new commits",
			soc2("CC8.1"))}
	}
	return []engine.Finding{fail(
		"github_branch_dismiss_stale",
		fmt.Sprintf("%d repo(s) do not dismiss stale reviews: %v", len(noDismiss), truncate(noDismiss, 5)),
		engine.SeverityMedium,
		"Enable dismiss stale reviews:\n  GitHub → Repo → Settings → Branches → Branch protection rule → Dismiss stale pull request approvals when new commits are pushed",
		soc2("CC8.1"),
	)}
}

func (c *Checker) checkSignedCommits(repos []*gh.Repository) []engine.Finding {
	var noSigning []string
	for _, repo := range repos {
		if repo.GetArchived() {
			continue
		}
		branch := repo.GetDefaultBranch()
		if branch == "" {
			branch = "main"
		}
		sig, _, err := c.client.Repositories.GetSignaturesProtectedBranch(
			context.Background(), c.owner, repo.GetName(), branch)
		if err != nil || sig == nil || !sig.GetEnabled() {
			noSigning = append(noSigning, repo.GetName())
		}
	}
	if len(noSigning) == 0 {
		return []engine.Finding{pass("github_signed_commits", "All repos require signed commits on default branch",
			soc2("CC8.1"))}
	}
	return []engine.Finding{fail(
		"github_signed_commits",
		fmt.Sprintf("%d repo(s) do not require signed commits: %v", len(noSigning), truncate(noSigning, 5)),
		engine.SeverityLow,
		"Require signed commits on default branch:\n  GitHub → Repo → Settings → Branches → Branch protection rule → Require signed commits",
		soc2("CC8.1"),
	)}
}

func contains(s, sub string) bool {
	return len(sub) > 0 && len(s) >= len(sub) && func() bool {
		for i := 0; i <= len(s)-len(sub); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	}()
}
