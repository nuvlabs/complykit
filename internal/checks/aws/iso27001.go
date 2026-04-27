package aws

// ISO 27001:2022 specific checks — controls unique to this framework
// that are not covered by the existing SOC2/CIS checkers.

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/rds"

	"github.com/complykit/complykit/internal/engine"
)

type ISO27001Checker struct{ cfg aws.Config }

func NewISO27001Checker(cfg aws.Config) *ISO27001Checker { return &ISO27001Checker{cfg: cfg} }
func (c *ISO27001Checker) Integration() string           { return "AWS/ISO27001" }

func (c *ISO27001Checker) Run() ([]engine.Finding, error) {
	var findings []engine.Finding
	add := func(f engine.Finding) { findings = append(findings, f) }

	c.checkAssetTagging(add)
	c.checkRDSMultiAZ(add)
	c.checkRDSBackupRetention(add)
	c.checkHTTPSRedirect(add)
	c.checkCloudWatchAlarms(add)

	return findings, nil
}

func iso(id string) engine.ControlRef {
	return engine.ControlRef{Framework: engine.FrameworkISO27001, ID: id}
}

// A.8.1 — Asset inventory: EC2 instances must have Owner + Environment tags
func (c *ISO27001Checker) checkAssetTagging(add func(engine.Finding)) {
	svc := ec2.NewFromConfig(c.cfg)
	out, err := svc.DescribeInstances(context.Background(), &ec2.DescribeInstancesInput{})
	if err != nil {
		add(engine.Finding{
			CheckID: "iso27001_asset_tagging", Title: "EC2 instances tagged with Owner and Environment",
			Status: engine.StatusSkip, Integration: c.Integration(),
			Controls: []engine.ControlRef{iso("A.8.1")},
		})
		return
	}

	required := []string{"Owner", "Environment"}
	missing := 0
	total := 0
	for _, r := range out.Reservations {
		for _, inst := range r.Instances {
			if inst.State != nil && inst.State.Name == "terminated" {
				continue
			}
			total++
			tags := map[string]bool{}
			for _, t := range inst.Tags {
				tags[aws.ToString(t.Key)] = true
			}
			for _, req := range required {
				if !tags[req] {
					missing++
					break
				}
			}
		}
	}

	if total == 0 {
		return
	}
	if missing > 0 {
		add(engine.Finding{
			CheckID: "iso27001_asset_tagging",
			Title:   "EC2 instances tagged with Owner and Environment",
			Status:  engine.StatusFail, Severity: engine.SeverityMedium,
			Integration: c.Integration(),
			Resource:    "ec2-instances",
			Detail:      fmt.Sprintf("%d of %d instances missing required tags", missing, total),
			Remediation: "Tag all EC2 instances with Owner and Environment tags for ISO 27001 asset inventory compliance.",
			Controls:    []engine.ControlRef{iso("A.8.1"), iso("A.8.2")},
		})
		return
	}
	add(engine.Finding{
		CheckID: "iso27001_asset_tagging", Title: "EC2 instances tagged with Owner and Environment",
		Status: engine.StatusPass, Integration: c.Integration(),
		Controls: []engine.ControlRef{iso("A.8.1"), iso("A.8.2")},
	})
}

// A.17.1 — Business continuity: RDS Multi-AZ enabled
func (c *ISO27001Checker) checkRDSMultiAZ(add func(engine.Finding)) {
	svc := rds.NewFromConfig(c.cfg)
	out, err := svc.DescribeDBInstances(context.Background(), &rds.DescribeDBInstancesInput{})
	if err != nil {
		return
	}
	failing := []string{}
	for _, db := range out.DBInstances {
		if db.MultiAZ == nil || !*db.MultiAZ {
			failing = append(failing, aws.ToString(db.DBInstanceIdentifier))
		}
	}
	if len(out.DBInstances) == 0 {
		return
	}
	if len(failing) > 0 {
		add(engine.Finding{
			CheckID: "iso27001_rds_multi_az", Title: "RDS instances have Multi-AZ enabled",
			Status: engine.StatusFail, Severity: engine.SeverityHigh,
			Integration: c.Integration(), Resource: strings.Join(failing, ", "),
			Remediation: "Enable Multi-AZ on RDS instances for high availability and business continuity.",
			Controls:    []engine.ControlRef{iso("A.17.1.2"), iso("A.17.2.1")},
		})
		return
	}
	add(engine.Finding{
		CheckID: "iso27001_rds_multi_az", Title: "RDS instances have Multi-AZ enabled",
		Status: engine.StatusPass, Integration: c.Integration(),
		Controls: []engine.ControlRef{iso("A.17.1.2"), iso("A.17.2.1")},
	})
}

// A.12.3 — Backup: RDS backup retention ≥ 7 days
func (c *ISO27001Checker) checkRDSBackupRetention(add func(engine.Finding)) {
	svc := rds.NewFromConfig(c.cfg)
	out, err := svc.DescribeDBInstances(context.Background(), &rds.DescribeDBInstancesInput{})
	if err != nil {
		return
	}
	failing := []string{}
	for _, db := range out.DBInstances {
		if db.BackupRetentionPeriod == nil || *db.BackupRetentionPeriod < 7 {
			failing = append(failing, aws.ToString(db.DBInstanceIdentifier))
		}
	}
	if len(out.DBInstances) == 0 {
		return
	}
	if len(failing) > 0 {
		add(engine.Finding{
			CheckID: "iso27001_rds_backup_retention", Title: "RDS backup retention ≥ 7 days",
			Status: engine.StatusFail, Severity: engine.SeverityHigh,
			Integration: c.Integration(), Resource: strings.Join(failing, ", "),
			Remediation: "Set BackupRetentionPeriod ≥ 7 on all RDS instances.\n  aws rds modify-db-instance --backup-retention-period 7",
			Controls:    []engine.ControlRef{iso("A.12.3.1"), iso("A.17.1.2")},
		})
		return
	}
	add(engine.Finding{
		CheckID: "iso27001_rds_backup_retention", Title: "RDS backup retention ≥ 7 days",
		Status: engine.StatusPass, Integration: c.Integration(),
		Controls: []engine.ControlRef{iso("A.12.3.1"), iso("A.17.1.2")},
	})
}

// A.10.1 — Encryption in transit: ALBs redirect HTTP to HTTPS
func (c *ISO27001Checker) checkHTTPSRedirect(add func(engine.Finding)) {
	svc := elasticloadbalancingv2.NewFromConfig(c.cfg)
	lbs, err := svc.DescribeLoadBalancers(context.Background(), &elasticloadbalancingv2.DescribeLoadBalancersInput{})
	if err != nil {
		return
	}
	failing := []string{}
	for _, lb := range lbs.LoadBalancers {
		listeners, err := svc.DescribeListeners(context.Background(),
			&elasticloadbalancingv2.DescribeListenersInput{LoadBalancerArn: lb.LoadBalancerArn})
		if err != nil {
			continue
		}
		hasHTTP := false
		hasRedirect := false
		for _, l := range listeners.Listeners {
			if aws.ToInt32(l.Port) == 80 {
				hasHTTP = true
				for _, a := range l.DefaultActions {
					if a.Type == "redirect" {
						hasRedirect = true
					}
				}
			}
		}
		if hasHTTP && !hasRedirect {
			failing = append(failing, aws.ToString(lb.LoadBalancerName))
		}
	}
	if len(lbs.LoadBalancers) == 0 {
		return
	}
	if len(failing) > 0 {
		add(engine.Finding{
			CheckID: "iso27001_alb_https_redirect", Title: "ALB HTTP listeners redirect to HTTPS",
			Status: engine.StatusFail, Severity: engine.SeverityHigh,
			Integration: c.Integration(), Resource: strings.Join(failing, ", "),
			Remediation: "Add an HTTP→HTTPS redirect rule on port 80 listeners.",
			Controls:    []engine.ControlRef{iso("A.10.1.1"), iso("A.13.2.3")},
		})
		return
	}
	add(engine.Finding{
		CheckID: "iso27001_alb_https_redirect", Title: "ALB HTTP listeners redirect to HTTPS",
		Status: engine.StatusPass, Integration: c.Integration(),
		Controls: []engine.ControlRef{iso("A.10.1.1"), iso("A.13.2.3")},
	})
}

// A.16.1 — Incident detection: CloudWatch alarms exist for critical metrics
func (c *ISO27001Checker) checkCloudWatchAlarms(add func(engine.Finding)) {
	svc := cloudwatch.NewFromConfig(c.cfg)
	out, err := svc.DescribeAlarms(context.Background(), &cloudwatch.DescribeAlarmsInput{})
	if err != nil || len(out.MetricAlarms) == 0 {
		add(engine.Finding{
			CheckID: "iso27001_cloudwatch_alarms", Title: "CloudWatch alarms configured for incident detection",
			Status: engine.StatusFail, Severity: engine.SeverityMedium,
			Integration: c.Integration(),
			Remediation: "Create CloudWatch alarms for: CPU utilisation, error rates, and authentication failures.",
			Controls:    []engine.ControlRef{iso("A.16.1.2"), iso("A.12.4.1")},
		})
		return
	}
	add(engine.Finding{
		CheckID: "iso27001_cloudwatch_alarms", Title: "CloudWatch alarms configured for incident detection",
		Status: engine.StatusPass, Integration: c.Integration(),
		Controls: []engine.ControlRef{iso("A.16.1.2"), iso("A.12.4.1")},
	})
}

