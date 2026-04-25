package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/efs"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/complykit/complykit/internal/engine"
)

type KMSChecker struct {
	kms *kms.Client
	efs *efs.Client
}

func NewKMSChecker(cfg aws.Config) *KMSChecker {
	return &KMSChecker{kms: kms.NewFromConfig(cfg), efs: efs.NewFromConfig(cfg)}
}

func (c *KMSChecker) Integration() string { return "AWS/KMS" }

func (c *KMSChecker) Run() ([]engine.Finding, error) {
	var findings []engine.Finding
	findings = append(findings, c.checkCMKRotation()...)
	findings = append(findings, c.checkEFSEncryption()...)
	return findings, nil
}

func (c *KMSChecker) checkCMKRotation() []engine.Finding {
	paginator := kms.NewListKeysPaginator(c.kms, &kms.ListKeysInput{})
	var noRotation []string

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.Background())
		if err != nil {
			return []engine.Finding{skip("aws_kms_rotation", "KMS CMK Rotation", err.Error())}
		}
		for _, key := range page.Keys {
			meta, err := c.kms.DescribeKey(context.Background(), &kms.DescribeKeyInput{KeyId: key.KeyId})
			if err != nil {
				continue
			}
			k := meta.KeyMetadata
			// skip AWS-managed keys (aws/xxx) and asymmetric keys
			if k.KeyManager == kmstypes.KeyManagerTypeAws || k.KeySpec != kmstypes.KeySpecSymmetricDefault {
				continue
			}
			if k.KeyState != kmstypes.KeyStateEnabled {
				continue
			}
			rot, err := c.kms.GetKeyRotationStatus(context.Background(), &kms.GetKeyRotationStatusInput{KeyId: key.KeyId})
			if err != nil || !rot.KeyRotationEnabled {
				noRotation = append(noRotation, aws.ToString(key.KeyId)[:8]+"...")
			}
		}
	}

	if len(noRotation) == 0 {
		return []engine.Finding{pass("aws_kms_rotation", "All customer-managed KMS keys have rotation enabled", "AWS/KMS", "keys",
			soc2("CC6.7"), hipaa("164.312(a)(2)(iv)"), cis("3.8"))}
	}
	return []engine.Finding{fail(
		"aws_kms_rotation",
		fmt.Sprintf("%d CMK(s) without annual rotation enabled: %v", len(noRotation), truncateList(noRotation, 5)),
		"AWS/KMS", fmt.Sprintf("%d keys", len(noRotation)), SeverityMedium,
		"Enable automatic key rotation:\n  aws kms enable-key-rotation --key-id KEY_ID",
		soc2("CC6.7"), hipaa("164.312(a)(2)(iv)"), cis("3.8"),
	)}
}

func (c *KMSChecker) checkEFSEncryption() []engine.Finding {
	out, err := c.efs.DescribeFileSystems(context.Background(), &efs.DescribeFileSystemsInput{})
	if err != nil {
		return []engine.Finding{skip("aws_efs_encryption", "EFS Encryption at Rest", err.Error())}
	}
	if len(out.FileSystems) == 0 {
		return []engine.Finding{pass("aws_efs_encryption", "No EFS file systems found", "AWS/KMS", "account",
			soc2("CC6.7"), hipaa("164.312(a)(2)(iv)"), cis("2.4.1"))}
	}
	var unencrypted []string
	for _, fs := range out.FileSystems {
		if !aws.ToBool(fs.Encrypted) {
			unencrypted = append(unencrypted, aws.ToString(fs.FileSystemId))
		}
	}
	if len(unencrypted) == 0 {
		return []engine.Finding{pass("aws_efs_encryption", "All EFS file systems are encrypted at rest", "AWS/KMS", "efs",
			soc2("CC6.7"), hipaa("164.312(a)(2)(iv)"), cis("2.4.1"))}
	}
	return []engine.Finding{fail(
		"aws_efs_encryption",
		fmt.Sprintf("%d EFS file system(s) not encrypted at rest: %v", len(unencrypted), truncateList(unencrypted, 5)),
		"AWS/KMS", fmt.Sprintf("%d filesystems", len(unencrypted)), SeverityHigh,
		"EFS encryption must be set at creation. Create a new encrypted EFS and migrate data:\n  aws efs create-file-system --encrypted",
		soc2("CC6.7"), hipaa("164.312(a)(2)(iv)"), cis("2.4.1"),
	)}
}
