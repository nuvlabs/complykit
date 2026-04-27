package aws

// PCI DSS v4.0 specific checks — controls unique to this framework.

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	"github.com/aws/aws-sdk-go-v2/service/inspector2"

	"github.com/complykit/complykit/internal/engine"
)

type PCIDSSChecker struct{ cfg aws.Config }

func NewPCIDSSChecker(cfg aws.Config) *PCIDSSChecker { return &PCIDSSChecker{cfg: cfg} }
func (c *PCIDSSChecker) Integration() string         { return "AWS/PCIDSS" }

func (c *PCIDSSChecker) Run() ([]engine.Finding, error) {
	var findings []engine.Finding
	add := func(f engine.Finding) { findings = append(findings, f) }

	c.checkInspectorEnabled(add)
	c.checkGuardDutyMalware(add)
	c.checkEBSEncryption(add)
	c.checkVPCFlowLogs(add)
	c.checkECRImageScanning(add)

	return findings, nil
}

func pci(id string) engine.ControlRef {
	return engine.ControlRef{Framework: engine.FrameworkPCIDSS, ID: id}
}

// Req 6.3.2 — Vulnerability management: AWS Inspector v2 enabled
func (c *PCIDSSChecker) checkInspectorEnabled(add func(engine.Finding)) {
	svc := inspector2.NewFromConfig(c.cfg)
	out, err := svc.BatchGetAccountStatus(context.Background(),
		&inspector2.BatchGetAccountStatusInput{})
	if err != nil {
		add(engine.Finding{
			CheckID: "pcidss_inspector_enabled", Title: "AWS Inspector v2 enabled for vulnerability scanning",
			Status: engine.StatusSkip, Integration: c.Integration(),
			Controls: []engine.ControlRef{pci("6.3.2"), pci("11.3.1")},
		})
		return
	}
	enabled := false
	for _, acct := range out.Accounts {
		if acct.State != nil && string(acct.State.Status) == "ENABLED" {
			enabled = true
		}
	}
	if !enabled {
		add(engine.Finding{
			CheckID: "pcidss_inspector_enabled", Title: "AWS Inspector v2 enabled for vulnerability scanning",
			Status: engine.StatusFail, Severity: engine.SeverityHigh,
			Integration: c.Integration(),
			Remediation: "Enable AWS Inspector v2:\n  aws inspector2 enable --resource-types EC2 ECR",
			Controls:    []engine.ControlRef{pci("6.3.2"), pci("11.3.1")},
		})
		return
	}
	add(engine.Finding{
		CheckID: "pcidss_inspector_enabled", Title: "AWS Inspector v2 enabled for vulnerability scanning",
		Status: engine.StatusPass, Integration: c.Integration(),
		Controls: []engine.ControlRef{pci("6.3.2"), pci("11.3.1")},
	})
}

// Req 5.2.1 — Anti-malware: GuardDuty malware protection enabled
func (c *PCIDSSChecker) checkGuardDutyMalware(add func(engine.Finding)) {
	svc := guardduty.NewFromConfig(c.cfg)
	detectors, err := svc.ListDetectors(context.Background(), &guardduty.ListDetectorsInput{})
	if err != nil || len(detectors.DetectorIds) == 0 {
		add(engine.Finding{
			CheckID: "pcidss_guardduty_malware", Title: "GuardDuty malware protection enabled",
			Status: engine.StatusFail, Severity: engine.SeverityCritical,
			Integration: c.Integration(),
			Remediation: "Enable GuardDuty with malware protection:\n  aws guardduty create-detector --enable --features '[{\"Name\":\"MALWARE_PROTECTION\",\"Status\":\"ENABLED\"}]'",
			Controls:    []engine.ControlRef{pci("5.2.1"), pci("5.3.2")},
		})
		return
	}
	malwareEnabled := false
	for _, id := range detectors.DetectorIds {
		det, err := svc.GetDetector(context.Background(), &guardduty.GetDetectorInput{DetectorId: aws.String(id)})
		if err != nil {
			continue
		}
		for _, f := range det.Features {
			if string(f.Name) == "MALWARE_PROTECTION" && string(f.Status) == "ENABLED" {
				malwareEnabled = true
			}
		}
	}
	if !malwareEnabled {
		add(engine.Finding{
			CheckID: "pcidss_guardduty_malware", Title: "GuardDuty malware protection enabled",
			Status: engine.StatusFail, Severity: engine.SeverityHigh,
			Integration: c.Integration(),
			Remediation: "Enable malware protection in GuardDuty settings.",
			Controls:    []engine.ControlRef{pci("5.2.1"), pci("5.3.2")},
		})
		return
	}
	add(engine.Finding{
		CheckID: "pcidss_guardduty_malware", Title: "GuardDuty malware protection enabled",
		Status: engine.StatusPass, Integration: c.Integration(),
		Controls: []engine.ControlRef{pci("5.2.1"), pci("5.3.2")},
	})
}

// Req 3.5.1 — Protect stored account data: EBS volumes encrypted
func (c *PCIDSSChecker) checkEBSEncryption(add func(engine.Finding)) {
	svc := ec2.NewFromConfig(c.cfg)
	out, err := svc.DescribeVolumes(context.Background(), &ec2.DescribeVolumesInput{})
	if err != nil {
		return
	}
	unencrypted := []string{}
	for _, v := range out.Volumes {
		if v.Encrypted == nil || !*v.Encrypted {
			unencrypted = append(unencrypted, aws.ToString(v.VolumeId))
		}
	}
	if len(out.Volumes) == 0 {
		return
	}
	if len(unencrypted) > 0 {
		add(engine.Finding{
			CheckID: "pcidss_ebs_encrypted", Title: "All EBS volumes encrypted",
			Status: engine.StatusFail, Severity: engine.SeverityHigh,
			Integration: c.Integration(), Resource: strings.Join(unencrypted, ", "),
			Remediation: "Enable EBS encryption by default:\n  aws ec2 enable-ebs-encryption-by-default\nRe-encrypt existing volumes by creating encrypted snapshots.",
			Controls:    []engine.ControlRef{pci("3.5.1"), pci("3.7.1")},
		})
		return
	}
	add(engine.Finding{
		CheckID: "pcidss_ebs_encrypted", Title: "All EBS volumes encrypted",
		Status: engine.StatusPass, Integration: c.Integration(),
		Controls: []engine.ControlRef{pci("3.5.1"), pci("3.7.1")},
	})
}

// Req 10.2 — Audit log all access: VPC Flow Logs enabled
func (c *PCIDSSChecker) checkVPCFlowLogs(add func(engine.Finding)) {
	svc := ec2.NewFromConfig(c.cfg)
	vpcs, err := svc.DescribeVpcs(context.Background(), &ec2.DescribeVpcsInput{})
	if err != nil || len(vpcs.Vpcs) == 0 {
		return
	}
	logs, err := svc.DescribeFlowLogs(context.Background(), &ec2.DescribeFlowLogsInput{})
	if err != nil {
		return
	}
	loggingVPCs := map[string]bool{}
	for _, fl := range logs.FlowLogs {
		loggingVPCs[aws.ToString(fl.ResourceId)] = true
	}
	missing := []string{}
	for _, v := range vpcs.Vpcs {
		if !loggingVPCs[aws.ToString(v.VpcId)] {
			missing = append(missing, aws.ToString(v.VpcId))
		}
	}
	if len(missing) > 0 {
		add(engine.Finding{
			CheckID: "pcidss_vpc_flow_logs", Title: "VPC Flow Logs enabled on all VPCs",
			Status: engine.StatusFail, Severity: engine.SeverityHigh,
			Integration: c.Integration(), Resource: strings.Join(missing, ", "),
			Remediation: "Enable VPC Flow Logs:\n  aws ec2 create-flow-logs --resource-type VPC --resource-ids <vpc-id> --traffic-type ALL --log-destination-type cloud-watch-logs",
			Controls:    []engine.ControlRef{pci("10.2.1"), pci("10.3.2")},
		})
		return
	}
	add(engine.Finding{
		CheckID: "pcidss_vpc_flow_logs", Title: "VPC Flow Logs enabled on all VPCs",
		Status: engine.StatusPass, Integration: c.Integration(),
		Controls: []engine.ControlRef{pci("10.2.1"), pci("10.3.2")},
	})
}

// Req 6.3.2 — Vulnerability management: ECR image scan on push
func (c *PCIDSSChecker) checkECRImageScanning(add func(engine.Finding)) {
	svc := ecr.NewFromConfig(c.cfg)
	repos, err := svc.DescribeRepositories(context.Background(), &ecr.DescribeRepositoriesInput{})
	if err != nil || len(repos.Repositories) == 0 {
		return
	}
	failing := []string{}
	for _, r := range repos.Repositories {
		if r.ImageScanningConfiguration == nil || !r.ImageScanningConfiguration.ScanOnPush {
			failing = append(failing, aws.ToString(r.RepositoryName))
		}
	}
	if len(failing) > 0 {
		add(engine.Finding{
			CheckID: "pcidss_ecr_scan_on_push", Title: "ECR repositories scan images on push",
			Status: engine.StatusFail, Severity: engine.SeverityHigh,
			Integration: c.Integration(), Resource: strings.Join(failing, ", "),
			Remediation: "Enable scan on push:\n  aws ecr put-image-scanning-configuration --repository-name REPO --image-scanning-configuration scanOnPush=true",
			Controls:    []engine.ControlRef{pci("6.3.2"), pci("11.3.1")},
		})
		return
	}
	add(engine.Finding{
		CheckID: "pcidss_ecr_scan_on_push", Title: "ECR repositories scan images on push",
		Status: engine.StatusPass, Integration: c.Integration(),
		Controls: []engine.ControlRef{pci("6.3.2"), pci("11.3.1")},
	})
}
