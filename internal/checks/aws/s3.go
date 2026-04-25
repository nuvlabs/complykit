package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/complykit/complykit/internal/engine"
)

type S3Checker struct {
	client *s3.Client
}

func NewS3Checker(cfg aws.Config) *S3Checker {
	return &S3Checker{client: s3.NewFromConfig(cfg)}
}

func (c *S3Checker) Integration() string { return "AWS/S3" }

func (c *S3Checker) Run() ([]engine.Finding, error) {
	return c.runChecks()
}

func (c *S3Checker) runChecks() ([]engine.Finding, error) {
	var findings []engine.Finding
	findings = append(findings, c.checkAccountPublicBlock()...)

	buckets, err := c.client.ListBuckets(context.Background(), &s3.ListBucketsInput{})
	if err != nil {
		findings = append(findings, skip("aws_s3", "S3 Buckets", err.Error()))
		return findings, nil
	}
	if len(buckets.Buckets) == 0 {
		findings = append(findings, pass("aws_s3_no_buckets", "No S3 buckets found", "AWS/S3", "account"))
		return findings, nil
	}
	findings = append(findings, c.checkBuckets(buckets.Buckets)...)
	return findings, nil
}

func (c *S3Checker) checkAccountPublicBlock() []engine.Finding {
	out, err := c.client.GetPublicAccessBlock(context.Background(), &s3.GetPublicAccessBlockInput{})
	if err != nil {
		return []engine.Finding{fail(
			"aws_s3_account_public_block", "Account-level S3 public access block not configured",
			"AWS/S3", "account", SeverityCritical,
			"Enable account-level S3 public access block:\n  aws s3control put-public-access-block --account-id ACCOUNT_ID --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
			soc2("CC6.6"), hipaa("164.312(e)(1)"), cis("2.1.4"),
		)}
	}
	cfg := out.PublicAccessBlockConfiguration
	if cfg != nil && aws.ToBool(cfg.BlockPublicAcls) && aws.ToBool(cfg.IgnorePublicAcls) &&
		aws.ToBool(cfg.BlockPublicPolicy) && aws.ToBool(cfg.RestrictPublicBuckets) {
		return []engine.Finding{pass("aws_s3_account_public_block", "Account-level S3 public access block is fully enabled", "AWS/S3", "account",
			soc2("CC6.6"), hipaa("164.312(e)(1)"), cis("2.1.4"))}
	}
	return []engine.Finding{fail(
		"aws_s3_account_public_block", "Account-level S3 public access block is not fully enabled",
		"AWS/S3", "account", SeverityHigh,
		"Enable all four settings at account level:\n  aws s3control put-public-access-block --account-id ACCOUNT_ID --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
		soc2("CC6.6"), hipaa("164.312(e)(1)"), cis("2.1.4"),
	)}
}

func (c *S3Checker) checkBuckets(buckets []s3types.Bucket) []engine.Finding {
	var findings []engine.Finding
	var noBlock, noEncrypt, noVersioning, noLogging, noMFADelete []string

	for _, b := range buckets {
		name := aws.ToString(b.Name)

		// public access block
		pab, err := c.client.GetPublicAccessBlock(context.Background(), &s3.GetPublicAccessBlockInput{Bucket: aws.String(name)})
		if err != nil || pab.PublicAccessBlockConfiguration == nil ||
			!aws.ToBool(pab.PublicAccessBlockConfiguration.BlockPublicAcls) ||
			!aws.ToBool(pab.PublicAccessBlockConfiguration.BlockPublicPolicy) ||
			!aws.ToBool(pab.PublicAccessBlockConfiguration.RestrictPublicBuckets) {
			noBlock = append(noBlock, name)
		}

		// encryption
		enc, err := c.client.GetBucketEncryption(context.Background(), &s3.GetBucketEncryptionInput{Bucket: aws.String(name)})
		if err != nil || enc.ServerSideEncryptionConfiguration == nil || len(enc.ServerSideEncryptionConfiguration.Rules) == 0 {
			noEncrypt = append(noEncrypt, name)
		}

		// versioning + MFA delete
		ver, err := c.client.GetBucketVersioning(context.Background(), &s3.GetBucketVersioningInput{Bucket: aws.String(name)})
		if err == nil {
			if ver.Status != s3types.BucketVersioningStatusEnabled {
				noVersioning = append(noVersioning, name)
			}
			if ver.MFADelete != s3types.MFADeleteStatusEnabled {
				noMFADelete = append(noMFADelete, name)
			}
		} else {
			noVersioning = append(noVersioning, name)
			noMFADelete = append(noMFADelete, name)
		}

		// access logging
		log, err := c.client.GetBucketLogging(context.Background(), &s3.GetBucketLoggingInput{Bucket: aws.String(name)})
		if err != nil || log.LoggingEnabled == nil {
			noLogging = append(noLogging, name)
		}
	}

	checks := []struct {
		id, title, remediation string
		items                  []string
		sev                    engine.Severity
		controls               []engine.ControlRef
	}{
		{
			"aws_s3_public_access_block", "S3 bucket(s) missing public access block",
			"aws s3api put-public-access-block --bucket BUCKET --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
			noBlock, SeverityCritical,
			[]engine.ControlRef{soc2("CC6.6"), hipaa("164.312(e)(1)"), cis("2.1.2")},
		},
		{
			"aws_s3_encryption", "S3 bucket(s) missing server-side encryption",
			"aws s3api put-bucket-encryption --bucket BUCKET --server-side-encryption-configuration '{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"AES256\"}}]}'",
			noEncrypt, SeverityHigh,
			[]engine.ControlRef{soc2("CC6.7"), hipaa("164.312(e)(1)"), cis("2.1.1")},
		},
		{
			"aws_s3_versioning", "S3 bucket(s) without versioning enabled",
			"aws s3api put-bucket-versioning --bucket BUCKET --versioning-configuration Status=Enabled",
			noVersioning, SeverityMedium,
			[]engine.ControlRef{soc2("CC7.2"), hipaa("164.312(c)(1)"), cis("2.1.5")},
		},
		{
			"aws_s3_logging", "S3 bucket(s) without access logging enabled",
			"aws s3api put-bucket-logging --bucket BUCKET --bucket-logging-status '{\"LoggingEnabled\":{\"TargetBucket\":\"LOG_BUCKET\",\"TargetPrefix\":\"BUCKET/\"}}'",
			noLogging, SeverityMedium,
			[]engine.ControlRef{soc2("CC7.2"), hipaa("164.312(b)"), cis("3.6")},
		},
		{
			"aws_s3_mfa_delete", "S3 bucket(s) without MFA delete enabled",
			"aws s3api put-bucket-versioning --bucket BUCKET --versioning-configuration Status=Enabled,MFADelete=Enabled --mfa 'arn:aws:iam::ACCOUNT:mfa/DEVICE TOKEN'",
			noMFADelete, SeverityMedium,
			[]engine.ControlRef{soc2("CC6.7"), hipaa("164.312(c)(1)"), cis("2.1.3")},
		},
	}

	for _, ch := range checks {
		if len(ch.items) == 0 {
			findings = append(findings, pass(ch.id, "All S3 buckets: "+ch.title+" ✓", "AWS/S3", "all buckets", ch.controls...))
		} else {
			findings = append(findings, fail(
				ch.id,
				fmt.Sprintf("%d %s: %v", len(ch.items), ch.title, truncateList(ch.items, 5)),
				"AWS/S3", fmt.Sprintf("%d buckets", len(ch.items)), ch.sev, ch.remediation, ch.controls...,
			))
		}
	}
	return findings
}
