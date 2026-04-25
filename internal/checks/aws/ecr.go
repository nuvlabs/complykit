package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/complykit/complykit/internal/engine"
)

type ECRChecker struct {
	client *ecr.Client
}

func NewECRChecker(cfg aws.Config) *ECRChecker {
	return &ECRChecker{client: ecr.NewFromConfig(cfg)}
}

func (c *ECRChecker) Integration() string { return "AWS/ECR" }

func (c *ECRChecker) Run() ([]engine.Finding, error) {
	var findings []engine.Finding
	findings = append(findings, c.checkScanOnPush()...)
	findings = append(findings, c.checkCriticalFindings()...)
	findings = append(findings, c.checkImmutableTags()...)
	findings = append(findings, c.checkLifecyclePolicy()...)
	findings = append(findings, c.checkRepoNotPublic()...)
	return findings, nil
}

func (c *ECRChecker) checkScanOnPush() []engine.Finding {
	paginator := ecr.NewDescribeRepositoriesPaginator(c.client, &ecr.DescribeRepositoriesInput{})
	var noScan []string
	hasAny := false

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.Background())
		if err != nil {
			return []engine.Finding{skip("aws_ecr_scan_on_push", "ECR Scan on Push", err.Error())}
		}
		for _, repo := range page.Repositories {
			hasAny = true
			if repo.ImageScanningConfiguration == nil || !repo.ImageScanningConfiguration.ScanOnPush {
				noScan = append(noScan, aws.ToString(repo.RepositoryName))
			}
		}
	}

	if !hasAny {
		return []engine.Finding{pass("aws_ecr_scan_on_push", "No ECR repositories found", "AWS/ECR", "account",
			soc2("CC7.1"), hipaa("164.308(a)(5)(ii)(B)"), cis("5.1"))}
	}
	if len(noScan) == 0 {
		return []engine.Finding{pass("aws_ecr_scan_on_push", "All ECR repositories have scan-on-push enabled", "AWS/ECR", "repositories",
			soc2("CC7.1"), hipaa("164.308(a)(5)(ii)(B)"), cis("5.1"))}
	}
	return []engine.Finding{fail(
		"aws_ecr_scan_on_push",
		fmt.Sprintf("%d ECR repository(s) without scan-on-push: %v", len(noScan), truncateList(noScan, 5)),
		"AWS/ECR", fmt.Sprintf("%d repos", len(noScan)), SeverityHigh,
		"Enable scan-on-push:\n  aws ecr put-image-scanning-configuration --repository-name REPO --image-scanning-configuration scanOnPush=true",
		soc2("CC7.1"), hipaa("164.308(a)(5)(ii)(B)"), cis("5.1"),
	)}
}

func (c *ECRChecker) checkCriticalFindings() []engine.Finding {
	paginator := ecr.NewDescribeRepositoriesPaginator(c.client, &ecr.DescribeRepositoriesInput{})
	type vulnRepo struct {
		name     string
		critical int
		high     int
	}
	var affected []vulnRepo

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.Background())
		if err != nil {
			return []engine.Finding{skip("aws_ecr_vulnerabilities", "ECR Image Vulnerabilities", err.Error())}
		}
		for _, repo := range page.Repositories {
			repoName := aws.ToString(repo.RepositoryName)
			images, err := c.client.DescribeImages(context.Background(), &ecr.DescribeImagesInput{
				RepositoryName: repo.RepositoryName,
				MaxResults:     aws.Int32(1),
				Filter:         &ecrtypes.DescribeImagesFilter{TagStatus: ecrtypes.TagStatusTagged},
			})
			if err != nil || len(images.ImageDetails) == 0 {
				continue
			}
			img := images.ImageDetails[0]
			if img.ImageScanFindingsSummary == nil {
				continue
			}
			crit := int(img.ImageScanFindingsSummary.FindingSeverityCounts["CRITICAL"])
			high := int(img.ImageScanFindingsSummary.FindingSeverityCounts["HIGH"])
			if crit > 0 || high > 0 {
				affected = append(affected, vulnRepo{name: repoName, critical: crit, high: high})
			}
		}
	}

	if len(affected) == 0 {
		return []engine.Finding{pass("aws_ecr_vulnerabilities", "No CRITICAL/HIGH CVEs in latest ECR images", "AWS/ECR", "images",
			soc2("CC7.1"), hipaa("164.308(a)(5)(ii)(B)"), cis("5.2"))}
	}
	var details []string
	for _, r := range affected {
		details = append(details, fmt.Sprintf("%s (CRIT:%d HIGH:%d)", r.name, r.critical, r.high))
	}
	return []engine.Finding{fail(
		"aws_ecr_vulnerabilities",
		fmt.Sprintf("%d ECR repository(s) with CRITICAL/HIGH CVEs in latest image: %v", len(affected), truncateList(details, 5)),
		"AWS/ECR", fmt.Sprintf("%d repos", len(affected)), SeverityCritical,
		"Rebuild images with patched base images and dependencies.\n  Review: aws ecr describe-image-scan-findings --repository-name REPO --image-id imageTag=latest",
		soc2("CC7.1"), hipaa("164.308(a)(5)(ii)(B)"), cis("5.2"),
	)}
}

func (c *ECRChecker) checkImmutableTags() []engine.Finding {
	paginator := ecr.NewDescribeRepositoriesPaginator(c.client, &ecr.DescribeRepositoriesInput{})
	var mutable []string
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.Background())
		if err != nil {
			return []engine.Finding{skip("aws_ecr_immutable_tags", "ECR Immutable Tags", err.Error())}
		}
		for _, repo := range page.Repositories {
			if repo.ImageTagMutability != ecrtypes.ImageTagMutabilityImmutable {
				mutable = append(mutable, aws.ToString(repo.RepositoryName))
			}
		}
	}
	if len(mutable) == 0 {
		return []engine.Finding{pass("aws_ecr_immutable_tags", "All ECR repositories have immutable image tags", "AWS/ECR", "repositories",
			soc2("CC7.1"), cis("5.3"))}
	}
	return []engine.Finding{fail(
		"aws_ecr_immutable_tags",
		fmt.Sprintf("%d ECR repository(s) allow mutable image tags: %v", len(mutable), truncateList(mutable, 5)),
		"AWS/ECR", fmt.Sprintf("%d repos", len(mutable)), SeverityMedium,
		"Enable immutable tags:\n  aws ecr put-image-tag-mutability --repository-name REPO --image-tag-mutability IMMUTABLE",
		soc2("CC7.1"), cis("5.3"),
	)}
}

func (c *ECRChecker) checkLifecyclePolicy() []engine.Finding {
	paginator := ecr.NewDescribeRepositoriesPaginator(c.client, &ecr.DescribeRepositoriesInput{})
	var noPolicy []string
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.Background())
		if err != nil {
			return []engine.Finding{skip("aws_ecr_lifecycle_policy", "ECR Lifecycle Policy", err.Error())}
		}
		for _, repo := range page.Repositories {
			_, err := c.client.GetLifecyclePolicy(context.Background(), &ecr.GetLifecyclePolicyInput{
				RepositoryName: repo.RepositoryName,
			})
			if err != nil {
				noPolicy = append(noPolicy, aws.ToString(repo.RepositoryName))
			}
		}
	}
	if len(noPolicy) == 0 {
		return []engine.Finding{pass("aws_ecr_lifecycle_policy", "All ECR repositories have lifecycle policies", "AWS/ECR", "repositories",
			soc2("CC7.1"), cis("5.4"))}
	}
	return []engine.Finding{fail(
		"aws_ecr_lifecycle_policy",
		fmt.Sprintf("%d ECR repository(s) missing lifecycle policy: %v", len(noPolicy), truncateList(noPolicy, 5)),
		"AWS/ECR", fmt.Sprintf("%d repos", len(noPolicy)), SeverityLow,
		"Add a lifecycle policy to limit stale images:\n  aws ecr put-lifecycle-policy --repository-name REPO --lifecycle-policy-text '{\"rules\":[{\"rulePriority\":1,\"description\":\"Keep last 10 images\",\"selection\":{\"tagStatus\":\"any\",\"countType\":\"imageCountMoreThan\",\"countNumber\":10},\"action\":{\"type\":\"expire\"}}]}'",
		soc2("CC7.1"), cis("5.4"),
	)}
}

func (c *ECRChecker) checkRepoNotPublic() []engine.Finding {
	paginator := ecr.NewDescribeRepositoriesPaginator(c.client, &ecr.DescribeRepositoriesInput{})
	var publicRepos []string
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.Background())
		if err != nil {
			return []engine.Finding{skip("aws_ecr_repo_not_public", "ECR Repository Not Public", err.Error())}
		}
		for _, repo := range page.Repositories {
			policy, err := c.client.GetRepositoryPolicy(context.Background(), &ecr.GetRepositoryPolicyInput{
				RepositoryName: repo.RepositoryName,
			})
			if err != nil {
				continue
			}
			// Check if policy grants access to "*" principal
			if policy.PolicyText != nil && (containsStr(*policy.PolicyText, `"*"`) || containsStr(*policy.PolicyText, `"Principal":"*"`)) {
				publicRepos = append(publicRepos, aws.ToString(repo.RepositoryName))
			}
		}
	}
	if len(publicRepos) == 0 {
		return []engine.Finding{pass("aws_ecr_repo_not_public", "No ECR repositories have public access policies", "AWS/ECR", "repositories",
			soc2("CC6.6"), hipaa("164.312(e)(1)"), cis("5.5"))}
	}
	return []engine.Finding{fail(
		"aws_ecr_repo_not_public",
		fmt.Sprintf("%d ECR repository(s) may have public access: %v", len(publicRepos), truncateList(publicRepos, 5)),
		"AWS/ECR", fmt.Sprintf("%d repos", len(publicRepos)), SeverityCritical,
		"Remove public access from repository policy:\n  aws ecr delete-repository-policy --repository-name REPO\n  Then add a policy granting access only to specific accounts/roles.",
		soc2("CC6.6"), hipaa("164.312(e)(1)"), cis("5.5"),
	)}
}

func containsStr(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && (s == substr || len(s) >= len(substr) &&
		func() bool {
			for i := 0; i <= len(s)-len(substr); i++ {
				if s[i:i+len(substr)] == substr {
					return true
				}
			}
			return false
		}())
}
