package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	aatypes "github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"
	"github.com/complykit/complykit/internal/engine"
)

type AccessAnalyzerChecker struct {
	client *accessanalyzer.Client
}

func NewAccessAnalyzerChecker(cfg aws.Config) *AccessAnalyzerChecker {
	return &AccessAnalyzerChecker{client: accessanalyzer.NewFromConfig(cfg)}
}

func (c *AccessAnalyzerChecker) Integration() string { return "AWS/IAM" }

func (c *AccessAnalyzerChecker) Run() ([]engine.Finding, error) {
	return c.checkAnalyzerExists(), nil
}

func (c *AccessAnalyzerChecker) checkAnalyzerExists() []engine.Finding {
	out, err := c.client.ListAnalyzers(context.Background(), &accessanalyzer.ListAnalyzersInput{
		Type: aatypes.TypeAccount,
	})
	if err != nil {
		return []engine.Finding{skip("aws_iam_access_analyzer", "IAM Access Analyzer", err.Error())}
	}
	for _, a := range out.Analyzers {
		if a.Status == aatypes.AnalyzerStatusActive {
			return []engine.Finding{pass("aws_iam_access_analyzer", "IAM Access Analyzer is enabled (ACCOUNT type)", "AWS/IAM", "account",
				soc2("CC6.3"), cis("1.20"))}
		}
	}
	return []engine.Finding{fail(
		"aws_iam_access_analyzer", "IAM Access Analyzer is not enabled for this region",
		"AWS/IAM", "account", SeverityMedium,
		"Enable Access Analyzer:\n  aws accessanalyzer create-analyzer --analyzer-name AccessAnalyzer --type ACCOUNT",
		soc2("CC6.3"), cis("1.20"),
	)}
}
