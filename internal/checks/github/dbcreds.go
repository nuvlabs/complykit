package github

import (
	"context"
	"fmt"
	"strings"

	gh "github.com/google/go-github/v71/github"

	"github.com/complykit/complykit/internal/engine"
)

// dbCredPatterns are code search queries that detect DB credentials in source code.
// Grouped to stay within GitHub's code search rate limits (10 req/min).
var dbCredPatterns = []struct {
	query string
	label string
}{
	{`"postgres://" OR "postgresql://"`, "PostgreSQL connection string"},
	{`"mysql://" OR "mongodb://" OR "mongodb+srv://"`, "MySQL/MongoDB connection string"},
	{`filename:.env DB_PASSWORD= OR filename:.env POSTGRES_PASSWORD= OR filename:.env MYSQL_ROOT_PASSWORD=`, "DB password in .env file"},
	{`filename:.env DATABASE_URL=postgres OR filename:.env DATABASE_URL=mysql`, "DATABASE_URL in .env file"},
}

// checkDBCredentialsInCode searches org repos for database credentials committed to source.
func (c *Checker) checkDBCredentialsInCode() []engine.Finding {
	type hit struct {
		label string
		files []string
	}
	var hits []hit

	for _, p := range dbCredPatterns {
		query := p.query + " org:" + c.org
		results, _, err := c.client.Search.Code(context.Background(), query, &gh.SearchOptions{
			ListOptions: gh.ListOptions{PerPage: 5},
		})
		if err != nil {
			// Rate-limited or insufficient permissions — skip this pattern
			continue
		}
		if results.GetTotal() == 0 {
			continue
		}
		var files []string
		for _, item := range results.CodeResults {
			files = append(files, fmt.Sprintf("%s:%s", item.Repository.GetFullName(), item.GetPath()))
		}
		hits = append(hits, hit{label: p.label, files: files})
	}

	if len(hits) == 0 {
		return []engine.Finding{pass("github_db_credentials",
			"No database credentials detected in repository code",
			soc2("CC6.1"), hipaa("164.312(a)(2)(iv)"))}
	}

	var summary []string
	for _, h := range hits {
		for _, f := range h.files {
			summary = append(summary, f)
		}
	}

	labels := make([]string, 0, len(hits))
	for _, h := range hits {
		labels = append(labels, h.label)
	}

	return []engine.Finding{fail(
		"github_db_credentials",
		fmt.Sprintf("Database credentials found in %d location(s) (%s): %s",
			len(summary), strings.Join(labels, ", "), truncate(summary, 5)),
		engine.SeverityCritical,
		"Remove database credentials from source code immediately:\n"+
			"  1. Rotate the exposed credentials\n"+
			"  2. Remove from code: git filter-repo or BFG Repo Cleaner\n"+
			"  3. Use environment variables injected at runtime, or Secrets Manager / Vault\n"+
			"  4. Add .env to .gitignore to prevent future leaks",
		soc2("CC6.1"), hipaa("164.312(a)(2)(iv)"),
	)}
}
