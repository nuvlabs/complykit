package gcp

import (
	"context"
	"fmt"
	"os"
	"strings"

	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/compute/v1"
	iamapi "google.golang.org/api/iam/v1"
	"google.golang.org/api/option"
	sqladmin "google.golang.org/api/sqladmin/v1beta4"
	"google.golang.org/api/storage/v1"

	"github.com/complykit/complykit/internal/engine"
)

type Checker struct {
	projectID string
	opts      []option.ClientOption
}

func NewChecker(projectID string) *Checker    { return &Checker{projectID: projectID} }
func NewCheckerFromEnv() *Checker {
	proj := os.Getenv("GCP_PROJECT_ID")
	if proj == "" {
		proj = os.Getenv("GOOGLE_CLOUD_PROJECT")
	}
	if proj == "" {
		return nil
	}
	return NewChecker(proj)
}
func (c *Checker) Integration() string { return "GCP" }
func (c *Checker) ProjectID() string   { return c.projectID }

func (c *Checker) Run() ([]engine.Finding, error) {
	var out []engine.Finding
	out = append(out, c.checkIAMServiceAccounts()...)
	out = append(out, c.checkGCSBuckets()...)
	out = append(out, c.checkOrgPolicies()...)
	out = append(out, c.checkAuditLogs()...)
	out = append(out, c.checkFirewallRules()...)
	out = append(out, c.checkVPCFlowLogs()...)
	out = append(out, c.checkCloudSQL()...)
	return out, nil
}

// ── IAM ──────────────────────────────────────────────────────────────────────

func (c *Checker) checkIAMServiceAccounts() []engine.Finding {
	ctx := context.Background()
	svc, err := iamapi.NewService(ctx, c.opts...)
	if err != nil {
		return []engine.Finding{skip("gcp_iam", "GCP IAM Service Accounts", err.Error())}
	}
	resp, err := svc.Projects.ServiceAccounts.List("projects/" + c.projectID).Do()
	if err != nil {
		return []engine.Finding{skip("gcp_iam_sa", "GCP Service Accounts", err.Error())}
	}
	var withUserKeys []string
	for _, sa := range resp.Accounts {
		if sa.Disabled {
			continue
		}
		keys, err := svc.Projects.ServiceAccounts.Keys.List(sa.Name).KeyTypes("USER_MANAGED").Do()
		if err != nil {
			continue
		}
		if len(keys.Keys) > 0 {
			withUserKeys = append(withUserKeys, sa.Email)
		}
	}
	if len(withUserKeys) == 0 {
		return []engine.Finding{pass("gcp_iam_sa_keys", "No service accounts with user-managed keys",
			soc2("CC6.1"), hipaa("164.308(a)(3)(ii)(A)"), cis("1.4"))}
	}
	return []engine.Finding{fail(
		"gcp_iam_sa_keys",
		fmt.Sprintf("%d service account(s) with user-managed keys: %v", len(withUserKeys), truncate(withUserKeys, 3)),
		engine.SeverityHigh,
		"Use Workload Identity Federation instead of service account keys:\n  https://cloud.google.com/iam/docs/workload-identity-federation\n  Or delete unused keys: gcloud iam service-accounts keys delete KEY_ID --iam-account=SA_EMAIL",
		soc2("CC6.1"), soc2("CC6.2"), hipaa("164.308(a)(3)(ii)(A)"), cis("1.4"),
	)}
}

// ── Storage ───────────────────────────────────────────────────────────────────

func (c *Checker) checkGCSBuckets() []engine.Finding {
	ctx := context.Background()
	svc, err := storage.NewService(ctx, c.opts...)
	if err != nil {
		return []engine.Finding{skip("gcp_gcs", "GCP Cloud Storage", err.Error())}
	}
	buckets, err := svc.Buckets.List(c.projectID).Do()
	if err != nil {
		return []engine.Finding{skip("gcp_gcs_buckets", "GCP Cloud Storage Buckets", err.Error())}
	}
	if len(buckets.Items) == 0 {
		return []engine.Finding{pass("gcp_gcs_no_buckets", "No GCS buckets found",
			soc2("CC6.6"), hipaa("164.312(e)(1)"), cis("5.1"))}
	}

	var noUniform, publicACL []string
	for _, b := range buckets.Items {
		if !b.IamConfiguration.UniformBucketLevelAccess.Enabled {
			noUniform = append(noUniform, b.Name)
		}
		policy, err := svc.Buckets.GetIamPolicy(b.Name).Do()
		if err == nil {
			for _, binding := range policy.Bindings {
				for _, member := range binding.Members {
					if member == "allUsers" || member == "allAuthenticatedUsers" {
						publicACL = append(publicACL, b.Name)
						break
					}
				}
			}
		}
	}

	var findings []engine.Finding
	if len(noUniform) == 0 {
		findings = append(findings, pass("gcp_gcs_uniform_iam", "All GCS buckets have uniform bucket-level access enabled",
			soc2("CC6.6"), soc2("CC6.7"), hipaa("164.312(e)(1)"), cis("5.2")))
	} else {
		findings = append(findings, fail(
			"gcp_gcs_uniform_iam",
			fmt.Sprintf("%d GCS bucket(s) missing uniform bucket-level access: %v", len(noUniform), truncate(noUniform, 3)),
			engine.SeverityHigh,
			"Enable uniform bucket-level access:\n  gcloud storage buckets update gs://BUCKET_NAME --uniform-bucket-level-access",
			soc2("CC6.6"), soc2("CC6.7"), hipaa("164.312(e)(1)"), cis("5.2"),
		))
	}
	if len(publicACL) == 0 {
		findings = append(findings, pass("gcp_gcs_public_access", "No GCS buckets are publicly accessible",
			soc2("CC6.6"), hipaa("164.312(e)(1)"), cis("5.1")))
	} else {
		findings = append(findings, fail(
			"gcp_gcs_public_access",
			fmt.Sprintf("%d GCS bucket(s) publicly accessible (allUsers/allAuthenticatedUsers): %v", len(publicACL), truncate(publicACL, 3)),
			engine.SeverityCritical,
			"Remove public IAM bindings:\n  gcloud storage buckets remove-iam-policy-binding gs://BUCKET_NAME --member=allUsers --role=ROLE",
			soc2("CC6.6"), hipaa("164.312(e)(1)"), cis("5.1"),
		))
	}
	return findings
}

// ── Org Policy ────────────────────────────────────────────────────────────────

func (c *Checker) checkOrgPolicies() []engine.Finding {
	ctx := context.Background()
	svc, err := cloudresourcemanager.NewService(ctx, c.opts...)
	if err != nil {
		return []engine.Finding{skip("gcp_org_policy", "GCP Org Policies", err.Error())}
	}
	policy, err := svc.Projects.GetOrgPolicy("projects/"+c.projectID,
		&cloudresourcemanager.GetOrgPolicyRequest{Constraint: "constraints/iam.allowedPolicyMemberDomains"},
	).Do()
	if err != nil || policy == nil || policy.BooleanPolicy == nil {
		return []engine.Finding{fail(
			"gcp_org_domain_restrict", "GCP domain-restricted sharing policy not enforced",
			engine.SeverityMedium,
			"Enforce domain restriction:\n  gcloud resource-manager org-policies set-policy policy.json --project=PROJECT_ID\n  Constraint: constraints/iam.allowedPolicyMemberDomains",
			soc2("CC6.1"), soc2("CC6.6"), hipaa("164.308(a)(4)(i)"), cis("1.8"),
		)}
	}
	return []engine.Finding{pass("gcp_org_domain_restrict", "GCP domain-restricted sharing policy enforced",
		soc2("CC6.1"), hipaa("164.308(a)(4)(i)"), cis("1.8"))}
}

// ── Audit Logs ────────────────────────────────────────────────────────────────

func (c *Checker) checkAuditLogs() []engine.Finding {
	ctx := context.Background()
	svc, err := cloudresourcemanager.NewService(ctx, c.opts...)
	if err != nil {
		return []engine.Finding{skip("gcp_audit_logs", "GCP Cloud Audit Logs", err.Error())}
	}
	policy, err := svc.Projects.GetIamPolicy("projects/"+c.projectID,
		&cloudresourcemanager.GetIamPolicyRequest{
			Options: &cloudresourcemanager.GetPolicyOptions{RequestedPolicyVersion: 3},
		},
	).Do()
	if err != nil {
		return []engine.Finding{skip("gcp_audit_logs", "GCP Cloud Audit Logs", err.Error())}
	}
	for _, ac := range policy.AuditConfigs {
		if ac.Service == "allServices" {
			hasRead, hasWrite := false, false
			for _, lc := range ac.AuditLogConfigs {
				switch lc.LogType {
				case "DATA_READ":
					hasRead = true
				case "DATA_WRITE":
					hasWrite = true
				}
			}
			if hasRead && hasWrite {
				return []engine.Finding{pass("gcp_audit_logs",
					"Cloud Audit Logs enabled for all services (DATA_READ + DATA_WRITE)",
					soc2("CC7.2"), hipaa("164.312(b)"), cis("2.1"))}
			}
		}
	}
	return []engine.Finding{fail(
		"gcp_audit_logs", "Cloud Audit Logs DATA_READ and DATA_WRITE not fully enabled for allServices",
		engine.SeverityHigh,
		"Enable full audit logging:\n  Cloud Console → IAM & Admin → Audit Logs → Select 'All Services' → Enable DATA_READ and DATA_WRITE",
		soc2("CC7.2"), hipaa("164.312(b)"), cis("2.1"),
	)}
}

// ── Firewall ──────────────────────────────────────────────────────────────────

func (c *Checker) checkFirewallRules() []engine.Finding {
	ctx := context.Background()
	svc, err := compute.NewService(ctx, c.opts...)
	if err != nil {
		return []engine.Finding{skip("gcp_firewall", "GCP Firewall Rules", err.Error())}
	}
	rules, err := svc.Firewalls.List(c.projectID).Do()
	if err != nil {
		return []engine.Finding{skip("gcp_firewall", "GCP Firewall Rules", err.Error())}
	}

	var openSSH, openRDP []string
	for _, rule := range rules.Items {
		if rule.Disabled || rule.Direction != "INGRESS" {
			continue
		}
		openToAll := false
		for _, src := range rule.SourceRanges {
			if src == "0.0.0.0/0" || src == "::/0" {
				openToAll = true
				break
			}
		}
		if !openToAll {
			continue
		}
		for _, allowed := range rule.Allowed {
			proto := strings.ToLower(allowed.IPProtocol)
			if proto != "tcp" && proto != "all" {
				continue
			}
			if len(allowed.Ports) == 0 {
				openSSH = append(openSSH, rule.Name)
				openRDP = append(openRDP, rule.Name)
				break
			}
			for _, portSpec := range allowed.Ports {
				if portMatches(portSpec, 22) {
					openSSH = append(openSSH, rule.Name)
				}
				if portMatches(portSpec, 3389) {
					openRDP = append(openRDP, rule.Name)
				}
			}
		}
	}

	var findings []engine.Finding
	if len(openSSH) == 0 {
		findings = append(findings, pass("gcp_firewall_ssh", "No firewall rules allow SSH from 0.0.0.0/0",
			soc2("CC6.6"), hipaa("164.312(e)(2)(i)"), cis("3.1")))
	} else {
		findings = append(findings, fail(
			"gcp_firewall_ssh",
			fmt.Sprintf("%d firewall rule(s) allow SSH from 0.0.0.0/0: %v", len(openSSH), truncate(openSSH, 5)),
			engine.SeverityCritical,
			"Restrict SSH access:\n  gcloud compute firewall-rules update RULE_NAME --source-ranges=YOUR_IP/32",
			soc2("CC6.6"), hipaa("164.312(e)(2)(i)"), cis("3.1"),
		))
	}
	if len(openRDP) == 0 {
		findings = append(findings, pass("gcp_firewall_rdp", "No firewall rules allow RDP from 0.0.0.0/0",
			soc2("CC6.6"), hipaa("164.312(e)(2)(i)"), cis("3.2")))
	} else {
		findings = append(findings, fail(
			"gcp_firewall_rdp",
			fmt.Sprintf("%d firewall rule(s) allow RDP from 0.0.0.0/0: %v", len(openRDP), truncate(openRDP, 5)),
			engine.SeverityCritical,
			"Restrict RDP access:\n  gcloud compute firewall-rules update RULE_NAME --source-ranges=YOUR_IP/32",
			soc2("CC6.6"), hipaa("164.312(e)(2)(i)"), cis("3.2"),
		))
	}
	return findings
}

// ── VPC Flow Logs ─────────────────────────────────────────────────────────────

func (c *Checker) checkVPCFlowLogs() []engine.Finding {
	ctx := context.Background()
	svc, err := compute.NewService(ctx, c.opts...)
	if err != nil {
		return []engine.Finding{skip("gcp_vpc_flow_logs", "GCP VPC Flow Logs", err.Error())}
	}
	subnets, err := svc.Subnetworks.AggregatedList(c.projectID).Do()
	if err != nil {
		return []engine.Finding{skip("gcp_vpc_flow_logs", "GCP VPC Flow Logs", err.Error())}
	}
	var noFlow []string
	for _, scopedList := range subnets.Items {
		for _, subnet := range scopedList.Subnetworks {
			if subnet.LogConfig == nil || !subnet.LogConfig.Enable {
				noFlow = append(noFlow, subnet.Name)
			}
		}
	}
	if len(noFlow) == 0 {
		return []engine.Finding{pass("gcp_vpc_flow_logs", "All subnets have VPC flow logs enabled",
			soc2("CC6.6"), hipaa("164.312(b)"), cis("3.8"))}
	}
	return []engine.Finding{fail(
		"gcp_vpc_flow_logs",
		fmt.Sprintf("%d subnet(s) without flow logs: %v", len(noFlow), truncate(noFlow, 5)),
		engine.SeverityMedium,
		"Enable flow logs:\n  gcloud compute networks subnets update SUBNET --region=REGION --enable-flow-logs",
		soc2("CC6.6"), hipaa("164.312(b)"), cis("3.8"),
	)}
}

// ── Cloud SQL ─────────────────────────────────────────────────────────────────

func (c *Checker) checkCloudSQL() []engine.Finding {
	ctx := context.Background()
	svc, err := sqladmin.NewService(ctx, c.opts...)
	if err != nil {
		return []engine.Finding{skip("gcp_cloudsql", "GCP Cloud SQL", err.Error())}
	}
	instances, err := svc.Instances.List(c.projectID).Do()
	if err != nil {
		return []engine.Finding{skip("gcp_cloudsql", "GCP Cloud SQL", err.Error())}
	}
	if len(instances.Items) == 0 {
		return []engine.Finding{pass("gcp_cloudsql_ssl", "No Cloud SQL instances found",
			soc2("CC6.7"), hipaa("164.312(a)(2)(iv)"), cis("6.3.7"))}
	}

	var noSSL, publicIP []string
	for _, inst := range instances.Items {
		if inst.Settings == nil || inst.Settings.IpConfiguration == nil {
			continue
		}
		if !inst.Settings.IpConfiguration.RequireSsl {
			noSSL = append(noSSL, inst.Name)
		}
		for _, ip := range inst.IpAddresses {
			if ip.Type == "PRIMARY" {
				publicIP = append(publicIP, inst.Name)
				break
			}
		}
	}

	var findings []engine.Finding
	if len(noSSL) == 0 {
		findings = append(findings, pass("gcp_cloudsql_ssl", "All Cloud SQL instances require SSL",
			soc2("CC6.7"), hipaa("164.312(a)(2)(iv)"), cis("6.3.7")))
	} else {
		findings = append(findings, fail(
			"gcp_cloudsql_ssl",
			fmt.Sprintf("%d Cloud SQL instance(s) not requiring SSL: %v", len(noSSL), truncate(noSSL, 5)),
			engine.SeverityHigh,
			"Enable SSL requirement:\n  gcloud sql instances patch INSTANCE_NAME --require-ssl",
			soc2("CC6.7"), hipaa("164.312(a)(2)(iv)"), cis("6.3.7"),
		))
	}
	if len(publicIP) == 0 {
		findings = append(findings, pass("gcp_cloudsql_public_ip", "No Cloud SQL instances with public IP",
			soc2("CC6.6"), hipaa("164.312(e)(2)(i)"), cis("6.4")))
	} else {
		findings = append(findings, fail(
			"gcp_cloudsql_public_ip",
			fmt.Sprintf("%d Cloud SQL instance(s) with public IP: %v", len(publicIP), truncate(publicIP, 5)),
			engine.SeverityMedium,
			"Use private IP and Cloud SQL Auth Proxy:\n  gcloud sql instances patch INSTANCE_NAME --no-assign-ip",
			soc2("CC6.6"), hipaa("164.312(e)(2)(i)"), cis("6.4"),
		))
	}
	return findings
}

// ── helpers ───────────────────────────────────────────────────────────────────

func portMatches(spec string, port int) bool {
	parts := strings.SplitN(spec, "-", 2)
	if len(parts) == 1 {
		if parts[0] == "*" {
			return true
		}
		var p int
		fmt.Sscanf(parts[0], "%d", &p)
		return p == port
	}
	var lo, hi int
	fmt.Sscanf(parts[0], "%d", &lo)
	fmt.Sscanf(parts[1], "%d", &hi)
	return port >= lo && port <= hi
}

func pass(id, title string, controls ...engine.ControlRef) engine.Finding {
	return engine.Finding{CheckID: id, Title: title, Status: engine.StatusPass, Integration: "GCP", Controls: controls}
}
func fail(id, title string, severity engine.Severity, remediation string, controls ...engine.ControlRef) engine.Finding {
	return engine.Finding{CheckID: id, Title: title, Status: engine.StatusFail, Severity: severity, Integration: "GCP", Remediation: remediation, Controls: controls}
}
func skip(id, title, detail string) engine.Finding {
	return engine.Finding{CheckID: id, Title: title, Status: engine.StatusSkip, Integration: "GCP", Detail: detail}
}
func soc2(id string) engine.ControlRef  { return engine.ControlRef{Framework: engine.FrameworkSOC2, ID: id} }
func hipaa(id string) engine.ControlRef { return engine.ControlRef{Framework: engine.FrameworkHIPAA, ID: id} }
func cis(id string) engine.ControlRef   { return engine.ControlRef{Framework: engine.FrameworkCIS, ID: id} }
func truncate(items []string, max int) string {
	if len(items) <= max {
		return strings.Join(items, ", ")
	}
	return strings.Join(items[:max], ", ") + fmt.Sprintf(" +%d more", len(items)-max)
}
