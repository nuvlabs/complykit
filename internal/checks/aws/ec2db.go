package aws

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/complykit/complykit/internal/engine"
)

type EC2DBChecker struct {
	client  *ec2.Client
	cwlogs  *cloudwatchlogs.Client
}

func NewEC2DBChecker(cfg aws.Config) *EC2DBChecker {
	return &EC2DBChecker{
		client: ec2.NewFromConfig(cfg),
		cwlogs: cloudwatchlogs.NewFromConfig(cfg),
	}
}

func (c *EC2DBChecker) Integration() string { return "AWS/EC2-Database" }

func (c *EC2DBChecker) Run() ([]engine.Finding, error) {
	var findings []engine.Finding
	findings = append(findings, c.checkDBEBSEncryption()...)
	findings = append(findings, c.checkDBNoPublicIP()...)
	findings = append(findings, c.checkDBSGExposure()...)
	findings = append(findings, c.checkCloudWatchLogs()...)
	return findings, nil
}

// listDBInstances finds EC2 instances tagged as database servers.
// Detection: Tag Role/Type = database|db, or Name contains db/database/postgres/mysql/mongo/redis.
func (c *EC2DBChecker) listDBInstances() ([]ec2types.Instance, error) {
	out, err := c.client.DescribeInstances(context.Background(), &ec2.DescribeInstancesInput{
		Filters: []ec2types.Filter{
			{Name: aws.String("instance-state-name"), Values: []string{"running", "stopped"}},
		},
	})
	if err != nil {
		return nil, err
	}
	var dbInstances []ec2types.Instance
	for _, r := range out.Reservations {
		for _, inst := range r.Instances {
			if isDBTagged(inst.Tags) {
				dbInstances = append(dbInstances, inst)
			}
		}
	}
	return dbInstances, nil
}

func isDBTagged(tags []ec2types.Tag) bool {
	dbKeywords := []string{"db", "database", "postgres", "mysql", "mongo", "redis", "mariadb"}
	for _, t := range tags {
		key := strings.ToLower(aws.ToString(t.Key))
		val := strings.ToLower(aws.ToString(t.Value))
		if (key == "role" || key == "type") && (val == "database" || val == "db") {
			return true
		}
		if key == "name" {
			for _, kw := range dbKeywords {
				if strings.Contains(val, kw) {
					return true
				}
			}
		}
	}
	return false
}

func ec2InstanceName(tags []ec2types.Tag, fallback string) string {
	for _, t := range tags {
		if aws.ToString(t.Key) == "Name" {
			return aws.ToString(t.Value)
		}
	}
	return fallback
}

// checkDBEBSEncryption verifies that all EBS volumes on DB-tagged EC2 instances are encrypted.
func (c *EC2DBChecker) checkDBEBSEncryption() []engine.Finding {
	instances, err := c.listDBInstances()
	if err != nil {
		return []engine.Finding{skip("aws_ec2_db_ebs_encrypted", "EC2 Database EBS Encryption", err.Error())}
	}
	if len(instances) == 0 {
		return nil
	}

	volToInstance := map[string]string{}
	for _, inst := range instances {
		name := ec2InstanceName(inst.Tags, aws.ToString(inst.InstanceId))
		for _, bdm := range inst.BlockDeviceMappings {
			if bdm.Ebs != nil {
				volToInstance[aws.ToString(bdm.Ebs.VolumeId)] = name
			}
		}
	}
	if len(volToInstance) == 0 {
		return []engine.Finding{pass("aws_ec2_db_ebs_encrypted", "EC2 DB instances have encrypted EBS volumes", "AWS/EC2-Database", "volumes",
			soc2("CC6.7"), hipaa("164.312(a)(2)(iv)"))}
	}

	volIDs := make([]string, 0, len(volToInstance))
	for v := range volToInstance {
		volIDs = append(volIDs, v)
	}
	vols, err := c.client.DescribeVolumes(context.Background(), &ec2.DescribeVolumesInput{VolumeIds: volIDs})
	if err != nil {
		return []engine.Finding{skip("aws_ec2_db_ebs_encrypted", "EC2 Database EBS Encryption", err.Error())}
	}

	var unencrypted []string
	for _, vol := range vols.Volumes {
		if !aws.ToBool(vol.Encrypted) {
			name := volToInstance[aws.ToString(vol.VolumeId)]
			unencrypted = append(unencrypted, fmt.Sprintf("%s/%s", name, aws.ToString(vol.VolumeId)))
		}
	}

	if len(unencrypted) == 0 {
		return []engine.Finding{pass("aws_ec2_db_ebs_encrypted", "EC2 DB instances have encrypted EBS volumes", "AWS/EC2-Database", "volumes",
			soc2("CC6.7"), hipaa("164.312(a)(2)(iv)"))}
	}
	return []engine.Finding{fail(
		"aws_ec2_db_ebs_encrypted",
		fmt.Sprintf("%d unencrypted volume(s) on DB instances: %v", len(unencrypted), truncateList(unencrypted, 5)),
		"AWS/EC2-Database", fmt.Sprintf("%d volumes", len(unencrypted)), SeverityHigh,
		"Enable EBS encryption for DB volumes:\n  1. Stop the instance\n  2. Create an encrypted snapshot: aws ec2 copy-snapshot --encrypted\n  3. Restore from the encrypted snapshot\n  Or enable account-level default encryption:\n  aws ec2 enable-ebs-encryption-by-default",
		soc2("CC6.7"), hipaa("164.312(a)(2)(iv)"),
	)}
}

// checkDBNoPublicIP verifies that DB-tagged EC2 instances have no public IP address.
func (c *EC2DBChecker) checkDBNoPublicIP() []engine.Finding {
	instances, err := c.listDBInstances()
	if err != nil {
		return []engine.Finding{skip("aws_ec2_db_no_public_ip", "EC2 Database Public IP", err.Error())}
	}
	if len(instances) == 0 {
		return nil
	}

	var withPublicIP []string
	for _, inst := range instances {
		if aws.ToString(inst.PublicIpAddress) != "" {
			withPublicIP = append(withPublicIP, ec2InstanceName(inst.Tags, aws.ToString(inst.InstanceId)))
		}
	}

	if len(withPublicIP) == 0 {
		return []engine.Finding{pass("aws_ec2_db_no_public_ip", "No DB instances have public IP addresses", "AWS/EC2-Database", "instances",
			soc2("CC6.1"), hipaa("164.312(a)(1)"))}
	}
	return []engine.Finding{fail(
		"aws_ec2_db_no_public_ip",
		fmt.Sprintf("%d DB instance(s) with public IP address: %v", len(withPublicIP), truncateList(withPublicIP, 5)),
		"AWS/EC2-Database", fmt.Sprintf("%d instances", len(withPublicIP)), SeverityCritical,
		"Place DB servers in private subnets with no route to an internet gateway.\n  Remove the public IP: use a NAT Gateway for outbound traffic and a bastion host or VPN for admin access.",
		soc2("CC6.1"), hipaa("164.312(a)(1)"),
	)}
}

// checkDBSGExposure verifies that security groups on DB instances do not expose DB ports to 0.0.0.0/0.
func (c *EC2DBChecker) checkDBSGExposure() []engine.Finding {
	instances, err := c.listDBInstances()
	if err != nil {
		return []engine.Finding{skip("aws_ec2_db_sg_exposure", "EC2 Database Security Group Exposure", err.Error())}
	}
	if len(instances) == 0 {
		return nil
	}

	sgToInstance := map[string]string{}
	for _, inst := range instances {
		name := ec2InstanceName(inst.Tags, aws.ToString(inst.InstanceId))
		for _, sg := range inst.SecurityGroups {
			sgToInstance[aws.ToString(sg.GroupId)] = name
		}
	}
	if len(sgToInstance) == 0 {
		return nil
	}

	sgIDs := make([]string, 0, len(sgToInstance))
	for id := range sgToInstance {
		sgIDs = append(sgIDs, id)
	}
	sgs, err := c.client.DescribeSecurityGroups(context.Background(), &ec2.DescribeSecurityGroupsInput{GroupIds: sgIDs})
	if err != nil {
		return []engine.Finding{skip("aws_ec2_db_sg_exposure", "EC2 Database Security Group Exposure", err.Error())}
	}

	dbPorts := map[int32]string{
		5432: "PostgreSQL", 3306: "MySQL/MariaDB", 1433: "SQL Server",
		27017: "MongoDB", 6379: "Redis",
	}

	var exposed []string
	for _, sg := range sgs.SecurityGroups {
		instName := sgToInstance[aws.ToString(sg.GroupId)]
		for _, rule := range sg.IpPermissions {
			from := aws.ToInt32(rule.FromPort)
			to := aws.ToInt32(rule.ToPort)
			for port, proto := range dbPorts {
				if port < from || port > to {
					continue
				}
				for _, ipRange := range rule.IpRanges {
					if aws.ToString(ipRange.CidrIp) == "0.0.0.0/0" {
						exposed = append(exposed, fmt.Sprintf("%s (%s/%d from 0.0.0.0/0)", instName, proto, port))
					}
				}
				for _, ipv6Range := range rule.Ipv6Ranges {
					if aws.ToString(ipv6Range.CidrIpv6) == "::/0" {
						exposed = append(exposed, fmt.Sprintf("%s (%s/%d from ::/0)", instName, proto, port))
					}
				}
			}
		}
	}

	if len(exposed) == 0 {
		return []engine.Finding{pass("aws_ec2_db_sg_exposure", "DB instance security groups do not expose database ports to the internet", "AWS/EC2-Database", "security-groups",
			soc2("CC6.6"), hipaa("164.312(a)(1)"))}
	}
	return []engine.Finding{fail(
		"aws_ec2_db_sg_exposure",
		fmt.Sprintf("%d DB port(s) exposed to internet: %v", len(exposed), truncateList(exposed, 5)),
		"AWS/EC2-Database", fmt.Sprintf("%d rules", len(exposed)), SeverityCritical,
		"Restrict inbound rules on DB security groups:\n  Remove rules allowing ports 5432/3306/1433/27017/6379 from 0.0.0.0/0\n  Replace with the specific security group ID of your application servers.",
		soc2("CC6.6"), hipaa("164.312(a)(1)"),
	)}
}

// checkCloudWatchLogs verifies that EC2-hosted DB instances have a matching
// CloudWatch Logs log group (by instance ID or Name tag).
func (c *EC2DBChecker) checkCloudWatchLogs() []engine.Finding {
	instances, err := c.listDBInstances()
	if err != nil {
		return []engine.Finding{skip("aws_ec2_db_cloudwatch_logs", "EC2 DB CloudWatch Logs", err.Error())}
	}
	if len(instances) == 0 {
		return nil
	}

	// Collect all log group names once — cheaper than one API call per instance.
	logGroups := map[string]bool{}
	pagInput := &cloudwatchlogs.DescribeLogGroupsInput{}
	for {
		out, lerr := c.cwlogs.DescribeLogGroups(context.Background(), pagInput)
		if lerr != nil {
			return []engine.Finding{skip("aws_ec2_db_cloudwatch_logs", "EC2 DB CloudWatch Logs", lerr.Error())}
		}
		for _, lg := range out.LogGroups {
			logGroups[aws.ToString(lg.LogGroupName)] = true
		}
		if out.NextToken == nil {
			break
		}
		pagInput.NextToken = out.NextToken
	}

	var noLogs []string
	for _, inst := range instances {
		id := aws.ToString(inst.InstanceId)
		nameTag := ""
		for _, t := range inst.Tags {
			if aws.ToString(t.Key) == "Name" {
				nameTag = aws.ToString(t.Value)
			}
		}

		// Match if any log group contains the instance ID or Name tag.
		found := false
		for lg := range logGroups {
			if strings.Contains(lg, id) || (nameTag != "" && strings.Contains(lg, nameTag)) {
				found = true
				break
			}
		}
		if !found {
			label := id
			if nameTag != "" {
				label = nameTag + " (" + id + ")"
			}
			noLogs = append(noLogs, label)
		}
	}

	if len(noLogs) == 0 {
		return []engine.Finding{pass("aws_ec2_db_cloudwatch_logs",
			"All EC2 DB instances have CloudWatch log groups",
			"AWS/EC2-Database", "instances",
			soc2("CC7.2"), hipaa("164.312(b)"),
		)}
	}
	return []engine.Finding{fail(
		"aws_ec2_db_cloudwatch_logs",
		fmt.Sprintf("%d EC2 DB instance(s) without CloudWatch log groups: %v", len(noLogs), truncateList(noLogs, 5)),
		"AWS/EC2-Database", fmt.Sprintf("%d instances", len(noLogs)), SeverityHigh,
		"Install the CloudWatch Logs agent and configure log groups:\n"+
			"  sudo yum install amazon-cloudwatch-agent\n"+
			"  Configure /opt/aws/amazon-cloudwatch-agent/bin/config.json to stream\n"+
			"  database logs (e.g. /var/log/postgresql/*.log) to a log group named\n"+
			"  after the instance ID or Name tag.",
		soc2("CC7.2"), hipaa("164.312(b)"),
	)}
}
