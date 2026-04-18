package gcp

import (
	"context"
	"fmt"
	"os"
	"strings"

	"google.golang.org/api/cloudresourcemanager/v1"
	iamapi "google.golang.org/api/iam/v1"
	"google.golang.org/api/option"
	"google.golang.org/api/storage/v1"

	"github.com/complykit/complykit/internal/engine"
)

type Checker struct {
	projectID string
	opts      []option.ClientOption
}

func NewChecker(projectID string) *Checker {
	return &Checker{projectID: projectID}
}

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

func (c *Checker) Run() ([]engine.Finding, error) {
	var findings []engine.Finding
	findings = append(findings, c.checkIAMServiceAccounts()...)
	findings = append(findings, c.checkGCSBuckets()...)
	findings = append(findings, c.checkOrgPolicies()...)
	return findings, nil
}

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
		keys, err := svc.Projects.ServiceAccounts.Keys.List(sa.Name).
			KeyTypes("USER_MANAGED").Do()
		if err != nil {
			continue
		}
		if len(keys.Keys) > 0 {
			withUserKeys = append(withUserKeys, sa.Email)
		}
	}

	if len(withUserKeys) == 0 {
		return []engine.Finding{pass("gcp_iam_sa_keys", "No service accounts with user-managed keys", soc2("CC6.1"))}
	}
	return []engine.Finding{fail(
		"gcp_iam_sa_keys",
		fmt.Sprintf("%d service account(s) with user-managed keys: %v", len(withUserKeys), truncate(withUserKeys, 3)),
		engine.SeverityHigh,
		"Rotate to Workload Identity Federation instead of service account keys:\n  https://cloud.google.com/iam/docs/workload-identity-federation\n  Or delete unused keys: gcloud iam service-accounts keys delete KEY_ID --iam-account=SA_EMAIL",
		soc2("CC6.1"), soc2("CC6.2"),
	)}
}

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
		return []engine.Finding{pass("gcp_gcs_public", "No GCS buckets found", soc2("CC6.6"))}
	}

	var publicBuckets, unencrypted []string

	for _, b := range buckets.Items {
		// check uniform bucket-level access (prevents ACL-based public access)
		if !b.IamConfiguration.UniformBucketLevelAccess.Enabled {
			publicBuckets = append(publicBuckets, b.Name+" (non-uniform IAM)")
		}

		// check encryption
		if b.Encryption == nil || b.Encryption.DefaultKmsKeyName == "" {
			// Google-managed keys are fine for SOC2; only flag if truly unencrypted
			// GCS always encrypts at rest by default, so this is informational
			_ = b.Name
		}
	}

	var findings []engine.Finding
	if len(publicBuckets) == 0 {
		findings = append(findings, pass("gcp_gcs_uniform_iam", "All GCS buckets have uniform bucket-level access enabled", soc2("CC6.6")))
	} else {
		findings = append(findings, fail(
			"gcp_gcs_uniform_iam",
			fmt.Sprintf("%d GCS bucket(s) missing uniform bucket-level access: %v", len(publicBuckets), truncate(publicBuckets, 3)),
			engine.SeverityHigh,
			"Enable uniform bucket-level access:\n  gcloud storage buckets update gs://BUCKET_NAME --uniform-bucket-level-access",
			soc2("CC6.6"), soc2("CC6.7"),
		))
	}
	_ = unencrypted
	return findings
}

func (c *Checker) checkOrgPolicies() []engine.Finding {
	ctx := context.Background()
	svc, err := cloudresourcemanager.NewService(ctx, c.opts...)
	if err != nil {
		return []engine.Finding{skip("gcp_org_policy", "GCP Org Policies", err.Error())}
	}

	// check if domain-restricted sharing is enabled
	policy, err := svc.Projects.GetOrgPolicy(
		"projects/"+c.projectID,
		&cloudresourcemanager.GetOrgPolicyRequest{
			Constraint: "constraints/iam.allowedPolicyMemberDomains",
		},
	).Do()

	if err != nil || policy == nil || policy.BooleanPolicy == nil {
		return []engine.Finding{fail(
			"gcp_org_domain_restrict",
			"GCP domain-restricted sharing policy not enforced",
			engine.SeverityMedium,
			"Enforce domain restriction to prevent sharing resources with external accounts:\n  gcloud resource-manager org-policies set-policy policy.json --project=PROJECT_ID\n  Policy: constraints/iam.allowedPolicyMemberDomains",
			soc2("CC6.1"), soc2("CC6.6"),
		)}
	}

	return []engine.Finding{pass("gcp_org_domain_restrict", "GCP domain-restricted sharing policy enforced", soc2("CC6.1"))}
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

func soc2(id string) engine.ControlRef { return engine.ControlRef{Framework: engine.FrameworkSOC2, ID: id} }

func truncate(items []string, max int) string {
	if len(items) <= max {
		return strings.Join(items, ", ")
	}
	return strings.Join(items[:max], ", ") + fmt.Sprintf(" +%d more", len(items)-max)
}
