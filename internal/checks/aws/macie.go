package aws

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/macie2"
	macie2types "github.com/aws/aws-sdk-go-v2/service/macie2/types"

	"github.com/complykit/complykit/internal/engine"
)

type MacieChecker struct {
	client *macie2.Client
}

func NewMacieChecker(cfg aws.Config) *MacieChecker {
	return &MacieChecker{client: macie2.NewFromConfig(cfg)}
}

func (c *MacieChecker) Integration() string { return "AWS/Macie" }

func (c *MacieChecker) Run() ([]engine.Finding, error) {
	var findings []engine.Finding
	findings = append(findings, c.checkMacieEnabled()...)
	findings = append(findings, c.checkMacieFindings()...)
	return findings, nil
}

// checkMacieEnabled verifies Amazon Macie is enabled and actively running.
func (c *MacieChecker) checkMacieEnabled() []engine.Finding {
	out, err := c.client.GetMacieSession(context.Background(), &macie2.GetMacieSessionInput{})
	if err != nil {
		msg := err.Error()
		// Macie not subscribed / not enabled in this region
		if strings.Contains(msg, "Macie is not enabled") ||
			strings.Contains(msg, "not subscribed") ||
			strings.Contains(msg, "AccessDeniedException") {
			return []engine.Finding{fail(
				"aws_macie_enabled",
				"Amazon Macie is not enabled — S3 buckets are not scanned for PII",
				"AWS/Macie", "account", SeverityHigh,
				"Enable Macie:\n"+
					"  aws macie2 enable-macie\n"+
					"Or via Console: Security Hub → Amazon Macie → Enable Macie\n"+
					"Then create a classification job targeting your S3 buckets.",
				soc2("CC6.8"), hipaa("164.312(a)(2)(iv)"), iso27001("A.18.1.4"),
			)}
		}
		return []engine.Finding{skip("aws_macie_enabled", "Amazon Macie Status", msg)}
	}

	if out.Status == macie2types.MacieStatusEnabled {
		return []engine.Finding{pass("aws_macie_enabled",
			"Amazon Macie is enabled and actively scanning S3 for PII",
			"AWS/Macie", "account",
			soc2("CC6.8"), hipaa("164.312(a)(2)(iv)"), iso27001("A.18.1.4"),
		)}
	}

	return []engine.Finding{fail(
		"aws_macie_enabled",
		fmt.Sprintf("Amazon Macie status is %q — not actively scanning", string(out.Status)),
		"AWS/Macie", "account", SeverityHigh,
		"Resume Macie:\n  aws macie2 enable-macie\nThen configure a classification job to scan S3 buckets.",
		soc2("CC6.8"), hipaa("164.312(a)(2)(iv)"), iso27001("A.18.1.4"),
	)}
}

// checkMacieFindings flags any active HIGH or CRITICAL Macie findings for SSN, CC, or PHI data.
func (c *MacieChecker) checkMacieFindings() []engine.Finding {
	// Only check if Macie is enabled — suppress gracefully if not
	session, err := c.client.GetMacieSession(context.Background(), &macie2.GetMacieSessionInput{})
	if err != nil || session.Status != macie2types.MacieStatusEnabled {
		return nil
	}

	// PII-related finding types we care about
	piiTypes := []string{
		"SensitiveData:S3Object/Personal",
		"SensitiveData:S3Object/Financial",
		"SensitiveData:S3Object/Medical",
		"SensitiveData:S3Object/Credentials",
		"SensitiveData:S3Object/Multiple",
	}

	var highFindings []string
	var nextToken *string

	for {
		out, ferr := c.client.ListFindings(context.Background(), &macie2.ListFindingsInput{
			FindingCriteria: &macie2types.FindingCriteria{
				Criterion: map[string]macie2types.CriterionAdditionalProperties{
					"severity.description": {
						Eq: []string{"HIGH", "CRITICAL"},
					},
					"archived": {
						Eq: []string{"false"},
					},
				},
			},
			NextToken: nextToken,
		})
		if ferr != nil {
			return []engine.Finding{skip("aws_macie_findings", "Amazon Macie PII Findings", ferr.Error())}
		}

		if len(out.FindingIds) > 0 {
			// Fetch finding details to filter by PII type
			details, derr := c.client.GetFindings(context.Background(), &macie2.GetFindingsInput{
				FindingIds: out.FindingIds,
			})
			if derr == nil {
				for _, f := range details.Findings {
					ft := string(f.Type)
					for _, pt := range piiTypes {
						if strings.HasPrefix(ft, pt) || ft == pt {
							bucket := ""
							if f.ResourcesAffected != nil && f.ResourcesAffected.S3Bucket != nil {
								bucket = aws.ToString(f.ResourcesAffected.S3Bucket.Name)
							}
							severity := ""
							if f.Severity != nil {
								severity = string(f.Severity.Description)
							}
							highFindings = append(highFindings,
								fmt.Sprintf("%s in s3://%s (%s)", ft, bucket, severity))
							break
						}
					}
				}
			}
		}

		if out.NextToken == nil {
			break
		}
		nextToken = out.NextToken
	}

	if len(highFindings) == 0 {
		return []engine.Finding{pass("aws_macie_findings",
			"No active HIGH/CRITICAL Macie findings for PII in S3",
			"AWS/Macie", "account",
			soc2("CC6.8"), hipaa("164.312(a)(2)(iv)"), iso27001("A.18.1.4"),
		)}
	}

	detail := strings.Join(highFindings, "\n")
	return []engine.Finding{fail(
		"aws_macie_findings",
		fmt.Sprintf("%d active Macie HIGH/CRITICAL PII finding(s) in S3", len(highFindings)),
		"AWS/Macie", fmt.Sprintf("%d findings", len(highFindings)), SeverityCritical,
		detail+"\n\nRemediation:\n"+
			"  1. Review each finding in the Macie console → Findings\n"+
			"  2. Encrypt or remove PII data from S3 buckets\n"+
			"  3. Apply bucket policies to restrict public access\n"+
			"  4. Archive resolved findings to keep the dashboard current",
		soc2("CC6.8"), hipaa("164.312(a)(2)(iv)"), iso27001("A.18.1.4"),
	)}
}

func iso27001(id string) engine.ControlRef {
	return engine.ControlRef{Framework: engine.FrameworkISO27001, ID: id}
}
