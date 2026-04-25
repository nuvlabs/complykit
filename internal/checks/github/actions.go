package github

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	gh "github.com/google/go-github/v71/github"
	"github.com/complykit/complykit/internal/engine"
)

// reFloatingAction matches action refs that are a branch/tag (not a full SHA).
// SHA is 40 hex chars. Anything shorter is a floating ref.
var reFloatingAction = regexp.MustCompile(`uses:\s+([^@\s]+)@([0-9a-f]{40})\b`)
var rePRTarget = regexp.MustCompile(`(?m)on:\s*\n.*pull_request_target`)

func (c *Checker) checkActionsVersionPinning(repos []*gh.Repository) []engine.Finding {
	var unpinned []string

	for _, repo := range repos {
		if repo.GetArchived() {
			continue
		}
		// list workflow files
		_, dirContent, _, err := c.client.Repositories.GetContents(
			context.Background(), c.owner, repo.GetName(), ".github/workflows", nil)
		if err != nil || dirContent == nil {
			continue
		}

		for _, f := range dirContent {
			if !strings.HasSuffix(f.GetName(), ".yml") && !strings.HasSuffix(f.GetName(), ".yaml") {
				continue
			}
			file, _, _, err := c.client.Repositories.GetContents(
				context.Background(), c.owner, repo.GetName(), f.GetPath(), nil)
			if err != nil || file == nil {
				continue
			}
			content, err := file.GetContent()
			if err != nil {
				continue
			}

			// Find all "uses:" lines
			lines := strings.Split(content, "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if !strings.HasPrefix(line, "uses:") {
					continue
				}
				// extract ref after @
				parts := strings.SplitN(line, "@", 2)
				if len(parts) < 2 {
					continue
				}
				ref := strings.Fields(parts[1])[0] // first token after @
				// SHA is exactly 40 hex chars
				if len(ref) != 40 || !isHex(ref) {
					unpinned = append(unpinned, fmt.Sprintf("%s/%s: %s", repo.GetName(), f.GetName(), strings.TrimSpace(line)))
				}
			}
		}
	}

	if len(unpinned) == 0 {
		return []engine.Finding{pass("github_actions_pinned", "All GitHub Actions use pinned SHA versions",
			soc2("CC8.1"), soc2("CC7.1"))}
	}
	return []engine.Finding{fail(
		"github_actions_pinned",
		fmt.Sprintf("%d workflow action(s) use floating tags instead of pinned SHAs: %v", len(unpinned), truncate(unpinned, 5)),
		engine.SeverityHigh,
		"Pin all actions to a full commit SHA:\n  # instead of: uses: actions/checkout@v4\n  # use:        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n  Use https://github.com/mheap/pin-github-action to automate pinning.",
		soc2("CC8.1"), soc2("CC7.1"),
	)}
}

func (c *Checker) checkPullRequestTarget(repos []*gh.Repository) []engine.Finding {
	var vulnerable []string

	for _, repo := range repos {
		if repo.GetArchived() {
			continue
		}
		_, dirContent, _, err := c.client.Repositories.GetContents(
			context.Background(), c.owner, repo.GetName(), ".github/workflows", nil)
		if err != nil || dirContent == nil {
			continue
		}

		for _, f := range dirContent {
			if !strings.HasSuffix(f.GetName(), ".yml") && !strings.HasSuffix(f.GetName(), ".yaml") {
				continue
			}
			file, _, _, err := c.client.Repositories.GetContents(
				context.Background(), c.owner, repo.GetName(), f.GetPath(), nil)
			if err != nil || file == nil {
				continue
			}
			content, err := file.GetContent()
			if err != nil {
				continue
			}

			// flag if pull_request_target + checkout of head
			hasPRT := strings.Contains(content, "pull_request_target")
			hasCheckoutHead := strings.Contains(content, "ref: ${{ github.event.pull_request.head") ||
				strings.Contains(content, "ref: ${{ github.head_ref")
			if hasPRT && hasCheckoutHead {
				vulnerable = append(vulnerable, fmt.Sprintf("%s/%s", repo.GetName(), f.GetName()))
			}
		}
	}

	if len(vulnerable) == 0 {
		return []engine.Finding{pass("github_actions_prt", "No unsafe pull_request_target workflows detected",
			soc2("CC8.1"))}
	}
	return []engine.Finding{fail(
		"github_actions_prt",
		fmt.Sprintf("%d workflow(s) use pull_request_target with head ref checkout (supply chain risk): %v",
			len(vulnerable), truncate(vulnerable, 5)),
		engine.SeverityCritical,
		"Do not check out the PR head ref in pull_request_target workflows — this allows arbitrary code execution.\n  Use pull_request event instead, or use a two-workflow pattern with workflow_run.\n  See: https://securitylab.github.com/research/github-actions-preventing-pwn-requests/",
		soc2("CC8.1"),
	)}
}

func (c *Checker) checkEnvironmentProtection(repos []*gh.Repository) []engine.Finding {
	var noProtection []string

	for _, repo := range repos {
		if repo.GetArchived() || repo.GetPrivate() {
			// environment protection rules require GitHub Team/Enterprise for private repos
			continue
		}
		envs, _, err := c.client.Repositories.ListEnvironments(
			context.Background(), c.owner, repo.GetName(), nil)
		if err != nil || envs == nil {
			continue
		}
		for _, env := range envs.Environments {
			if env.GetName() == "production" || env.GetName() == "prod" {
				prot := env.ProtectionRules
				hasReview := false
				for _, rule := range prot {
					if rule.GetType() == "required_reviewers" {
						hasReview = true
						break
					}
				}
				if !hasReview {
					noProtection = append(noProtection, fmt.Sprintf("%s/%s", repo.GetName(), env.GetName()))
				}
			}
		}
	}

	if len(noProtection) == 0 {
		return []engine.Finding{pass("github_env_protection", "All production environments require reviewer approval",
			soc2("CC8.1"), soc2("CC6.3"))}
	}
	return []engine.Finding{fail(
		"github_env_protection",
		fmt.Sprintf("%d production environment(s) without required reviewers: %v", len(noProtection), truncate(noProtection, 5)),
		engine.SeverityHigh,
		"Add required reviewers to production environments:\n  GitHub → Repo → Settings → Environments → production → Required reviewers",
		soc2("CC8.1"), soc2("CC6.3"),
	)}
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
