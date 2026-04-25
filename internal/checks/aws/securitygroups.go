package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/complykit/complykit/internal/engine"
)

type SecurityGroupChecker struct {
	client *ec2.Client
}

func NewSecurityGroupChecker(cfg aws.Config) *SecurityGroupChecker {
	return &SecurityGroupChecker{client: ec2.NewFromConfig(cfg)}
}

func (c *SecurityGroupChecker) Integration() string { return "AWS/EC2" }

func (c *SecurityGroupChecker) Run() ([]engine.Finding, error) {
	var findings []engine.Finding
	findings = append(findings, c.checkOpenPorts()...)
	findings = append(findings, c.checkUnrestrictedPorts()...)
	findings = append(findings, c.checkDefaultSGRestricted()...)
	findings = append(findings, c.checkVPCFlowLogs()...)
	findings = append(findings, c.checkEBSEncryption()...)
	return findings, nil
}

func (c *SecurityGroupChecker) checkOpenPorts() []engine.Finding {
	paginator := ec2.NewDescribeSecurityGroupsPaginator(c.client, &ec2.DescribeSecurityGroupsInput{})
	var openSSH, openRDP []string

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.Background())
		if err != nil {
			return []engine.Finding{skip("aws_sg_open_ports", "Security Group Open Ports", err.Error())}
		}
		for _, sg := range page.SecurityGroups {
			name := fmt.Sprintf("%s (%s)", aws.ToString(sg.GroupName), aws.ToString(sg.GroupId))
			for _, rule := range sg.IpPermissions {
				if isOpenToAll(rule) {
					from := aws.ToInt32(rule.FromPort)
					to := aws.ToInt32(rule.ToPort)
					if from <= 22 && to >= 22 {
						openSSH = append(openSSH, name)
					}
					if from <= 3389 && to >= 3389 {
						openRDP = append(openRDP, name)
					}
				}
			}
		}
	}

	var findings []engine.Finding
	if len(openSSH) == 0 {
		findings = append(findings, pass("aws_sg_open_ssh", "No security groups with SSH open to 0.0.0.0/0", "AWS/EC2", "security groups",
			soc2("CC6.6"), hipaa("164.312(e)(2)(i)"), cis("4.1")))
	} else {
		findings = append(findings, fail(
			"aws_sg_open_ssh",
			fmt.Sprintf("%d security group(s) allow SSH from 0.0.0.0/0: %v", len(openSSH), truncateList(openSSH, 5)),
			"AWS/EC2", fmt.Sprintf("%d groups", len(openSSH)), SeverityCritical,
			"Restrict SSH to known IP ranges:\n  aws ec2 revoke-security-group-ingress --group-id SG_ID --protocol tcp --port 22 --cidr 0.0.0.0/0",
			soc2("CC6.6"), hipaa("164.312(e)(2)(i)"), cis("4.1"),
		))
	}
	if len(openRDP) == 0 {
		findings = append(findings, pass("aws_sg_open_rdp", "No security groups with RDP open to 0.0.0.0/0", "AWS/EC2", "security groups",
			soc2("CC6.6"), hipaa("164.312(e)(2)(i)"), cis("4.2")))
	} else {
		findings = append(findings, fail(
			"aws_sg_open_rdp",
			fmt.Sprintf("%d security group(s) allow RDP from 0.0.0.0/0: %v", len(openRDP), truncateList(openRDP, 5)),
			"AWS/EC2", fmt.Sprintf("%d groups", len(openRDP)), SeverityCritical,
			"Restrict RDP to known IP ranges:\n  aws ec2 revoke-security-group-ingress --group-id SG_ID --protocol tcp --port 3389 --cidr 0.0.0.0/0",
			soc2("CC6.6"), hipaa("164.312(e)(2)(i)"), cis("4.2"),
		))
	}
	return findings
}

func (c *SecurityGroupChecker) checkVPCFlowLogs() []engine.Finding {
	vpcs, err := c.client.DescribeVpcs(context.Background(), &ec2.DescribeVpcsInput{})
	if err != nil {
		return []engine.Finding{skip("aws_vpc_flow_logs", "VPC Flow Logs", err.Error())}
	}

	var noFlow []string
	for _, vpc := range vpcs.Vpcs {
		vpcID := aws.ToString(vpc.VpcId)
		flows, err := c.client.DescribeFlowLogs(context.Background(), &ec2.DescribeFlowLogsInput{
			Filter: []ec2types.Filter{
				{Name: aws.String("resource-id"), Values: []string{vpcID}},
			},
		})
		if err != nil || len(flows.FlowLogs) == 0 {
			noFlow = append(noFlow, vpcID)
		}
	}

	if len(noFlow) == 0 {
		return []engine.Finding{pass("aws_vpc_flow_logs", "All VPCs have flow logs enabled", "AWS/EC2", "vpcs",
			soc2("CC6.6"), hipaa("164.312(b)"), cis("3.9"))}
	}
	return []engine.Finding{fail(
		"aws_vpc_flow_logs",
		fmt.Sprintf("%d VPC(s) without flow logs: %v", len(noFlow), noFlow),
		"AWS/EC2", fmt.Sprintf("%d VPCs", len(noFlow)), SeverityMedium,
		"Enable VPC flow logs:\n  aws ec2 create-flow-logs --resource-type VPC --resource-ids VPC_ID --traffic-type ALL --log-destination-type cloud-watch-logs --log-group-name /aws/vpc/flowlogs",
		soc2("CC6.6"), hipaa("164.312(b)"), cis("3.9"),
	)}
}

func (c *SecurityGroupChecker) checkEBSEncryption() []engine.Finding {
	out, err := c.client.GetEbsEncryptionByDefault(context.Background(), &ec2.GetEbsEncryptionByDefaultInput{})
	if err != nil {
		return []engine.Finding{skip("aws_ebs_encryption", "EBS Default Encryption", err.Error())}
	}
	if aws.ToBool(out.EbsEncryptionByDefault) {
		return []engine.Finding{pass("aws_ebs_encryption", "EBS default encryption is enabled", "AWS/EC2", "account",
			soc2("CC6.7"), hipaa("164.312(a)(2)(iv)"), cis("2.2.1"))}
	}
	return []engine.Finding{fail(
		"aws_ebs_encryption", "EBS default encryption is not enabled",
		"AWS/EC2", "account", SeverityHigh,
		"Enable EBS default encryption:\n  aws ec2 enable-ebs-encryption-by-default",
		soc2("CC6.7"), hipaa("164.312(a)(2)(iv)"), cis("2.2.1"),
	)}
}

// dangerousPorts: high-risk ports that should never be open to 0.0.0.0/0
var dangerousPorts = []struct{ port int32; name string }{
	{20, "FTP-data"}, {21, "FTP"}, {23, "Telnet"}, {25, "SMTP"},
	{110, "POP3"}, {135, "RPC"}, {143, "IMAP"}, {445, "SMB"},
	{1433, "MSSQL"}, {1521, "Oracle"}, {3306, "MySQL"}, {5432, "PostgreSQL"},
	{5900, "VNC"}, {6379, "Redis"}, {27017, "MongoDB"},
}

func (c *SecurityGroupChecker) checkUnrestrictedPorts() []engine.Finding {
	paginator := ec2.NewDescribeSecurityGroupsPaginator(c.client, &ec2.DescribeSecurityGroupsInput{})
	type hit struct{ sgName, port string }
	var flagged []hit

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.Background())
		if err != nil {
			return []engine.Finding{skip("aws_sg_unrestricted_ports", "Security Group Unrestricted Ports", err.Error())}
		}
		for _, sg := range page.SecurityGroups {
			name := fmt.Sprintf("%s (%s)", aws.ToString(sg.GroupName), aws.ToString(sg.GroupId))
			for _, rule := range sg.IpPermissions {
				if !isOpenToAll(rule) {
					continue
				}
				from := aws.ToInt32(rule.FromPort)
				to := aws.ToInt32(rule.ToPort)
				for _, dp := range dangerousPorts {
					if from <= dp.port && to >= dp.port {
						flagged = append(flagged, hit{name, dp.name})
					}
				}
			}
		}
	}

	if len(flagged) == 0 {
		return []engine.Finding{pass("aws_sg_unrestricted_ports", "No security groups expose high-risk ports to 0.0.0.0/0", "AWS/EC2", "security groups",
			soc2("CC6.6"), hipaa("164.312(e)(2)(i)"), cis("4.3"))}
	}
	var details []string
	for _, h := range flagged {
		details = append(details, fmt.Sprintf("%s→%s", h.sgName, h.port))
	}
	return []engine.Finding{fail(
		"aws_sg_unrestricted_ports",
		fmt.Sprintf("%d high-risk port(s) open to 0.0.0.0/0: %v", len(flagged), truncateList(details, 5)),
		"AWS/EC2", "security groups", SeverityCritical,
		"Restrict access to high-risk ports to known IP ranges or remove rules entirely.",
		soc2("CC6.6"), hipaa("164.312(e)(2)(i)"), cis("4.3"),
	)}
}

func (c *SecurityGroupChecker) checkDefaultSGRestricted() []engine.Finding {
	paginator := ec2.NewDescribeSecurityGroupsPaginator(c.client, &ec2.DescribeSecurityGroupsInput{
		Filters: []ec2types.Filter{{Name: aws.String("group-name"), Values: []string{"default"}}},
	})
	var openDefaults []string
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.Background())
		if err != nil {
			return []engine.Finding{skip("aws_sg_default_restricted", "Default Security Group Restricted", err.Error())}
		}
		for _, sg := range page.SecurityGroups {
			if len(sg.IpPermissions) > 0 || len(sg.IpPermissionsEgress) > 1 {
				openDefaults = append(openDefaults, fmt.Sprintf("%s/%s", aws.ToString(sg.VpcId), aws.ToString(sg.GroupId)))
			}
		}
	}
	if len(openDefaults) == 0 {
		return []engine.Finding{pass("aws_sg_default_restricted", "All default security groups restrict all traffic", "AWS/EC2", "security groups",
			soc2("CC6.6"), hipaa("164.312(e)(2)(i)"), cis("5.4"))}
	}
	return []engine.Finding{fail(
		"aws_sg_default_restricted",
		fmt.Sprintf("%d default security group(s) allow inbound traffic: %v", len(openDefaults), truncateList(openDefaults, 5)),
		"AWS/EC2", "security groups", SeverityHigh,
		"Remove all inbound and outbound rules from default security groups:\n  aws ec2 revoke-security-group-ingress --group-id SG_ID --protocol all --cidr 0.0.0.0/0",
		soc2("CC6.6"), hipaa("164.312(e)(2)(i)"), cis("5.4"),
	)}
}

func isOpenToAll(rule ec2types.IpPermission) bool {
	for _, r := range rule.IpRanges {
		if aws.ToString(r.CidrIp) == "0.0.0.0/0" {
			return true
		}
	}
	for _, r := range rule.Ipv6Ranges {
		if aws.ToString(r.CidrIpv6) == "::/0" {
			return true
		}
	}
	return false
}
