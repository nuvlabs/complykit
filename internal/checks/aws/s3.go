package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
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
	buckets, err := c.client.ListBuckets(context.Background(), &s3.ListBucketsInput{})
	if err != nil {
		return []engine.Finding{skip("aws_s3", "S3 Buckets", err.Error())}, nil
	}

	if len(buckets.Buckets) == 0 {
		return []engine.Finding{pass("aws_s3_public_access_block", "No S3 buckets found", "AWS/S3", "account")}, nil
	}

	var findings []engine.Finding
	var noBlock, noEncrypt []string

	for _, b := range buckets.Buckets {
		name := aws.ToString(b.Name)

		// check public access block
		pab, err := c.client.GetPublicAccessBlock(context.Background(), &s3.GetPublicAccessBlockInput{
			Bucket: aws.String(name),
		})
		if err != nil || pab.PublicAccessBlockConfiguration == nil ||
			!aws.ToBool(pab.PublicAccessBlockConfiguration.BlockPublicAcls) ||
			!aws.ToBool(pab.PublicAccessBlockConfiguration.BlockPublicPolicy) ||
			!aws.ToBool(pab.PublicAccessBlockConfiguration.RestrictPublicBuckets) {
			noBlock = append(noBlock, name)
		}

		// check encryption
		enc, err := c.client.GetBucketEncryption(context.Background(), &s3.GetBucketEncryptionInput{
			Bucket: aws.String(name),
		})
		if err != nil || enc.ServerSideEncryptionConfiguration == nil || len(enc.ServerSideEncryptionConfiguration.Rules) == 0 {
			noEncrypt = append(noEncrypt, name)
		}
	}

	if len(noBlock) == 0 {
		findings = append(findings, pass("aws_s3_public_access_block", "All S3 buckets have public access block enabled", "AWS/S3", "all buckets", soc2("CC6.6"), cis("2.1.2")))
	} else {
		findings = append(findings, fail(
			"aws_s3_public_access_block",
			fmt.Sprintf("%d S3 bucket(s) missing public access block: %v", len(noBlock), noBlock),
			"AWS/S3", fmt.Sprintf("%d buckets", len(noBlock)),
			SeverityCritical,
			"Enable block public access on each bucket:\n  aws s3api put-public-access-block --bucket BUCKET --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
			soc2("CC6.6"), hipaa("164.312(e)(1)"), cis("2.1.2"),
		))
	}

	if len(noEncrypt) == 0 {
		findings = append(findings, pass("aws_s3_encryption", "All S3 buckets have server-side encryption enabled", "AWS/S3", "all buckets", soc2("CC6.7"), cis("2.1.1")))
	} else {
		findings = append(findings, fail(
			"aws_s3_encryption",
			fmt.Sprintf("%d S3 bucket(s) missing encryption: %v", len(noEncrypt), noEncrypt),
			"AWS/S3", fmt.Sprintf("%d buckets", len(noEncrypt)),
			SeverityHigh,
			"Enable default encryption:\n  aws s3api put-bucket-encryption --bucket BUCKET --server-side-encryption-configuration '{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"AES256\"}}]}'",
			soc2("CC6.7"), hipaa("164.312(e)(1)"), cis("2.1.1"),
		))
	}

	return findings, nil
}
