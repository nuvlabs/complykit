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
	return c.checkOpenPorts(), nil
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
		findings = append(findings, pass("aws_sg_open_ssh", "No security groups with SSH open to 0.0.0.0/0", "AWS/EC2", "security groups", soc2("CC6.6"), cis("4.1")))
	} else {
		findings = append(findings, fail(
			"aws_sg_open_ssh",
			fmt.Sprintf("%d security group(s) allow SSH from 0.0.0.0/0: %v", len(openSSH), openSSH),
			"AWS/EC2", fmt.Sprintf("%d groups", len(openSSH)),
			SeverityCritical,
			"Restrict SSH to known IP ranges:\n  aws ec2 revoke-security-group-ingress --group-id SG_ID --protocol tcp --port 22 --cidr 0.0.0.0/0\n  Then add your specific IP range.",
			soc2("CC6.6"), cis("4.1"),
		))
	}

	if len(openRDP) == 0 {
		findings = append(findings, pass("aws_sg_open_rdp", "No security groups with RDP open to 0.0.0.0/0", "AWS/EC2", "security groups", soc2("CC6.6"), cis("4.2")))
	} else {
		findings = append(findings, fail(
			"aws_sg_open_rdp",
			fmt.Sprintf("%d security group(s) allow RDP from 0.0.0.0/0: %v", len(openRDP), openRDP),
			"AWS/EC2", fmt.Sprintf("%d groups", len(openRDP)),
			SeverityCritical,
			"Restrict RDP to known IP ranges:\n  aws ec2 revoke-security-group-ingress --group-id SG_ID --protocol tcp --port 3389 --cidr 0.0.0.0/0",
			soc2("CC6.6"), cis("4.2"),
		))
	}

	return findings
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
