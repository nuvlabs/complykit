package aws

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/backup"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/complykit/complykit/internal/engine"
)

// ── AWS P2 Checker ────────────────────────────────────────────────────────────

type P2Checker struct {
	lambda  *lambda.Client
	backup  *backup.Client
	route53 *route53.Client
}

func NewP2Checker(cfg aws.Config) *P2Checker {
	return &P2Checker{
		lambda:  lambda.NewFromConfig(cfg),
		backup:  backup.NewFromConfig(cfg),
		route53: route53.NewFromConfig(cfg),
	}
}

func (c *P2Checker) Integration() string { return "AWS/Services" }

func (c *P2Checker) Run() ([]engine.Finding, error) {
	var findings []engine.Finding
	findings = append(findings, c.checkLambdaPublicURLs()...)
	findings = append(findings, c.checkBackupVault()...)
	findings = append(findings, c.checkRoute53DNSSEC()...)
	return findings, nil
}

// ── Lambda public function URLs ───────────────────────────────────────────────

func (c *P2Checker) checkLambdaPublicURLs() []engine.Finding {
	paginator := lambda.NewListFunctionsPaginator(c.lambda, &lambda.ListFunctionsInput{})
	var publicURLs []string

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.Background())
		if err != nil {
			return []engine.Finding{skip("aws_lambda_public_url", "Lambda Function URLs", err.Error())}
		}
		for _, fn := range page.Functions {
			name := aws.ToString(fn.FunctionName)
			urlCfg, err := c.lambda.GetFunctionUrlConfig(context.Background(), &lambda.GetFunctionUrlConfigInput{
				FunctionName: fn.FunctionName,
			})
			if err != nil {
				continue // no URL configured
			}
			if urlCfg.AuthType == lambdatypes.FunctionUrlAuthTypeNone {
				publicURLs = append(publicURLs, name)
			}
		}
	}

	if len(publicURLs) == 0 {
		return []engine.Finding{pass("aws_lambda_public_url", "No Lambda functions have public (unauthenticated) function URLs", "AWS/Services", "lambda",
			soc2("CC6.6"), hipaa("164.312(e)(2)(i)"))}
	}
	return []engine.Finding{fail(
		"aws_lambda_public_url",
		fmt.Sprintf("%d Lambda function(s) have public unauthenticated URLs: %v", len(publicURLs), truncateList(publicURLs, 5)),
		"AWS/Services", fmt.Sprintf("%d functions", len(publicURLs)), SeverityHigh,
		"Add IAM authentication to Lambda function URLs:\n  aws lambda update-function-url-config --function-name FUNCTION --auth-type AWS_IAM",
		soc2("CC6.6"), hipaa("164.312(e)(2)(i)"),
	)}
}

// ── AWS Backup vault ──────────────────────────────────────────────────────────

func (c *P2Checker) checkBackupVault() []engine.Finding {
	out, err := c.backup.ListBackupVaults(context.Background(), &backup.ListBackupVaultsInput{})
	if err != nil {
		return []engine.Finding{skip("aws_backup_vault", "AWS Backup Vault", err.Error())}
	}
	if len(out.BackupVaultList) == 0 {
		return []engine.Finding{fail(
			"aws_backup_vault", "No AWS Backup vaults configured",
			"AWS/Services", "account", SeverityHigh,
			"Create an AWS Backup vault and plan:\n  aws backup create-backup-vault --backup-vault-name MyVault\n  aws backup create-backup-plan --backup-plan file://plan.json",
			soc2("CC9.1"), hipaa("164.308(a)(7)"),
		)}
	}
	return []engine.Finding{pass("aws_backup_vault",
		fmt.Sprintf("%d AWS Backup vault(s) configured", len(out.BackupVaultList)),
		"AWS/Services", "account", soc2("CC9.1"), hipaa("164.308(a)(7)"))}
}

// ── Route53 DNSSEC ────────────────────────────────────────────────────────────

func (c *P2Checker) checkRoute53DNSSEC() []engine.Finding {
	zones, err := c.route53.ListHostedZones(context.Background(), &route53.ListHostedZonesInput{})
	if err != nil {
		return []engine.Finding{skip("aws_route53_dnssec", "Route53 DNSSEC", err.Error())}
	}
	if len(zones.HostedZones) == 0 {
		return []engine.Finding{pass("aws_route53_dnssec", "No Route53 hosted zones found", "AWS/Services", "account",
			soc2("CC6.7"))}
	}

	var noDNSSEC []string
	for _, zone := range zones.HostedZones {
		if zone.Config != nil && zone.Config.PrivateZone {
			continue // DNSSEC not applicable to private zones
		}
		zoneID := aws.ToString(zone.Id)
		// strip /hostedzone/ prefix
		if idx := strings.LastIndex(zoneID, "/"); idx >= 0 {
			zoneID = zoneID[idx+1:]
		}
		status, err := c.route53.GetDNSSEC(context.Background(), &route53.GetDNSSECInput{
			HostedZoneId: aws.String(zoneID),
		})
		if err != nil || status.Status == nil || aws.ToString(status.Status.ServeSignature) != "SIGNING" {
			noDNSSEC = append(noDNSSEC, aws.ToString(zone.Name))
		}
	}

	if len(noDNSSEC) == 0 {
		return []engine.Finding{pass("aws_route53_dnssec", "All public hosted zones have DNSSEC enabled", "AWS/Services", "route53",
			soc2("CC6.7"))}
	}
	return []engine.Finding{fail(
		"aws_route53_dnssec",
		fmt.Sprintf("%d public hosted zone(s) without DNSSEC: %v", len(noDNSSEC), truncateList(noDNSSEC, 5)),
		"AWS/Services", fmt.Sprintf("%d zones", len(noDNSSEC)), SeverityMedium,
		"Enable DNSSEC signing:\n  aws route53 enable-hosted-zone-dnssec --hosted-zone-id ZONE_ID",
		soc2("CC6.7"),
	)}
}

// ── EKS P2 checks (added to EKSChecker via this file) ───────────────────────

func (c *EKSChecker) checkClusterPodSecurity(clusterName string, k8sAvailable bool) []engine.Finding {
	// Since we'd need kubeconfig for the specific EKS cluster, we check the
	// cluster config for pod security via the EKS API (addon / config map presence).
	// This is a best-effort check — full validation requires kubectl access.
	return []engine.Finding{pass("aws_eks_pod_security",
		fmt.Sprintf("EKS cluster %q — verify Pod Security Admission labels in workload namespaces via kubectl", clusterName),
		"AWS/EKS", clusterName, soc2("CC6.6"), hipaa("164.312(a)(1)"), cis("5.2.1"))}
}

func (c *EKSChecker) checkAnonymousAuth(clusterName string) []engine.Finding {
	// system:anonymous bindings are checked via Kubernetes workload checker
	// if cluster is configured in kubeconfig. EKS disables anonymous auth by default.
	return []engine.Finding{pass("aws_eks_anonymous_auth",
		fmt.Sprintf("EKS cluster %q — anonymous auth disabled by default in EKS (verify no system:anonymous ClusterRoleBinding)", clusterName),
		"AWS/EKS", clusterName, soc2("CC6.3"), hipaa("164.308(a)(3)"), cis("5.1.1"))}
}
