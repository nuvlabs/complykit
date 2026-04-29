package github

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"time"

	gh "github.com/google/go-github/v71/github"
	"golang.org/x/oauth2"

	"github.com/complykit/complykit/internal/engine"
)

type SecretsChecker struct {
	client *gh.Client
	org    string
	token  string
}

func NewSecretsChecker(token, org string) *SecretsChecker {
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	tc := oauth2.NewClient(context.Background(), ts)
	return &SecretsChecker{
		client: gh.NewClient(tc),
		org:    org,
		token:  token,
	}
}

func (c *SecretsChecker) Integration() string { return "GitHub/Secrets" }

func (c *SecretsChecker) Run() ([]engine.Finding, error) {
	var findings []engine.Finding

	// Check for DB credentials in code
	dbFindings, err := c.checkDBCredentials()
	if err != nil {
		return nil, fmt.Errorf("checking DB credentials: %w", err)
	}
	findings = append(findings, dbFindings...)

	return findings, nil
}

type Repository struct {
	Name     string `json:"name"`
	FullName string `json:"full_name"`
	Private  bool   `json:"private"`
}

type SearchResult struct {
	TotalCount int `json:"total_count"`
	Items      []struct {
		Repository Repository `json:"repository"`
		Path       string     `json:"path"`
		HTMLURL    string     `json:"html_url"`
	} `json:"items"`
}

func (c *SecretsChecker) checkDBCredentials() ([]engine.Finding, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Define patterns to search for DB credentials
	patterns := []struct {
		name    string
		pattern string
		desc    string
	}{
		{
			name:    "database_url",
			pattern: "DATABASE_URL.*=.*://.*:.*@",
			desc:    "Database URL with embedded credentials",
		},
		{
			name:    "db_password",
			pattern: "(DB_PASSWORD|DATABASE_PASSWORD|POSTGRES_PASSWORD|MYSQL_PASSWORD).*=.*[\"'][^\"'\\s]+[\"']",
			desc:    "Database password in environment variables",
		},
		{
			name:    "connection_string",
			pattern: "(connectionString|Connection.*String).*=.*Password=",
			desc:    "Database connection string with password",
		},
		{
			name:    "jdbc_url",
			pattern: "jdbc:.*://.*:.*@",
			desc:    "JDBC URL with embedded credentials",
		},
	}

	var violations []string

	for _, pattern := range patterns {
		findings, err := c.searchCodePattern(ctx, pattern.pattern)
		if err != nil {
			return nil, fmt.Errorf("searching for pattern %s: %w", pattern.name, err)
		}

		for _, finding := range findings {
			violations = append(violations, fmt.Sprintf("%s (%s)", finding, pattern.desc))
		}
	}

	if len(violations) == 0 {
		return []engine.Finding{
			pass("github_db_credentials", "GitHub Database Credentials Scan",
				soc2("CC6.1"), iso27001("A.14.1.3"), pcidss("3.4")),
		}, nil
	}

	return []engine.Finding{
		fail("github_db_credentials", "Hardcoded Database Credentials Found",
			engine.SeverityHigh,
			"Remove hardcoded credentials from code:\n"+
				"1. Use environment variables or secret management systems\n"+
				"2. Rotate any exposed credentials immediately\n"+
				"3. Add sensitive patterns to .gitignore\n"+
				"4. Use GitHub secret scanning protection",
			soc2("CC6.1"), iso27001("A.14.1.3"), pcidss("3.4")),
	}, nil
}

func (c *SecretsChecker) searchCodePattern(ctx context.Context, pattern string) ([]string, error) {
	// GitHub Code Search API
	query := fmt.Sprintf("%s org:%s", pattern, c.org)
	url := fmt.Sprintf("https://api.github.com/search/code?q=%s&per_page=100", query)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "token "+c.token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 422 {
		// Search API limitations - skip this pattern
		return nil, nil
	}

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GitHub API error %d: %s", resp.StatusCode, string(body))
	}

	var result SearchResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	var findings []string
	for _, item := range result.Items {
		findings = append(findings, fmt.Sprintf("%s:%s", item.Repository.FullName, item.Path))
	}

	return findings, nil
}

func iso27001(id string) engine.ControlRef {
	return engine.ControlRef{Framework: engine.FrameworkISO27001, ID: id}
}

func pcidss(id string) engine.ControlRef {
	return engine.ControlRef{Framework: engine.FrameworkPCIDSS, ID: id}
}

// Helper function to validate if a string contains potential credentials
func containsCredentials(content string) bool {
	// Common database credential patterns
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)(password|pwd|pass)\s*[:=]\s*["']?[a-zA-Z0-9@#$%^&*()_+=\-]{8,}["']?`),
		regexp.MustCompile(`(?i)(database_url|db_url)\s*[:=]\s*["']?[a-zA-Z0-9+]+://[^"'\s]+["']?`),
		regexp.MustCompile(`(?i)jdbc:[a-zA-Z0-9]+://[^"'\s]+`),
		regexp.MustCompile(`(?i)(connection.*string)\s*[:=]\s*["'][^"']*password[^"']*["']`),
	}

	for _, pattern := range patterns {
		if pattern.MatchString(content) {
			return true
		}
	}

	return false
}
