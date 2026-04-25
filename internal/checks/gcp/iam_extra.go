package gcp

import (
	"context"
	"fmt"
	"strings"
	"time"

	"google.golang.org/api/cloudresourcemanager/v1"
	iamapi "google.golang.org/api/iam/v1"
	"github.com/complykit/complykit/internal/engine"
)

type IAMExtraChecker struct {
	projectID string
}

func NewIAMExtraChecker(projectID string) *IAMExtraChecker {
	return &IAMExtraChecker{projectID: projectID}
}

func (c *IAMExtraChecker) Integration() string { return "GCP/IAM" }

func (c *IAMExtraChecker) Run() ([]engine.Finding, error) {
	var findings []engine.Finding
	findings = append(findings, c.checkPrimitiveRoles()...)
	findings = append(findings, c.checkGmailAccounts()...)
	findings = append(findings, c.checkSAProjectOwner()...)
	findings = append(findings, c.checkSAKeyAge()...)
	return findings, nil
}

func (c *IAMExtraChecker) checkPrimitiveRoles() []engine.Finding {
	ctx := context.Background()
	svc, err := cloudresourcemanager.NewService(ctx)
	if err != nil {
		return []engine.Finding{skip("gcp_iam_primitive_roles", "GCP Primitive Roles", err.Error())}
	}
	policy, err := svc.Projects.GetIamPolicy("projects/"+c.projectID, &cloudresourcemanager.GetIamPolicyRequest{}).Do()
	if err != nil {
		return []engine.Finding{skip("gcp_iam_primitive_roles", "GCP Primitive Roles", err.Error())}
	}
	var owners, editors []string
	for _, binding := range policy.Bindings {
		if binding.Role == "roles/owner" || binding.Role == "roles/editor" {
			for _, member := range binding.Members {
				if !strings.HasPrefix(member, "serviceAccount:") {
					if binding.Role == "roles/owner" {
						owners = append(owners, member)
					} else {
						editors = append(editors, member)
					}
				}
			}
		}
	}
	var findings []engine.Finding
	if len(owners) == 0 && len(editors) == 0 {
		findings = append(findings, pass("gcp_iam_primitive_roles", "No users with primitive Owner/Editor roles",
			soc2("CC6.3"), hipaa("164.308(a)(3)"), cis("1.1")))
	} else {
		all := append(owners, editors...)
		findings = append(findings, fail(
			"gcp_iam_primitive_roles",
			fmt.Sprintf("%d member(s) with primitive Owner/Editor roles: %v", len(all), truncate(all, 5)),
			engine.SeverityHigh,
			"Replace primitive roles with predefined or custom IAM roles:\n  gcloud projects remove-iam-policy-binding PROJECT --member=MEMBER --role=roles/owner",
			soc2("CC6.3"), hipaa("164.308(a)(3)"), cis("1.1"),
		))
	}
	return findings
}

func (c *IAMExtraChecker) checkGmailAccounts() []engine.Finding {
	ctx := context.Background()
	svc, err := cloudresourcemanager.NewService(ctx)
	if err != nil {
		return []engine.Finding{skip("gcp_iam_gmail", "GCP Gmail Accounts", err.Error())}
	}
	policy, err := svc.Projects.GetIamPolicy("projects/"+c.projectID, &cloudresourcemanager.GetIamPolicyRequest{}).Do()
	if err != nil {
		return []engine.Finding{skip("gcp_iam_gmail", "GCP Gmail Accounts", err.Error())}
	}
	var gmail []string
	for _, binding := range policy.Bindings {
		for _, member := range binding.Members {
			if strings.Contains(member, "@gmail.com") {
				gmail = append(gmail, member)
			}
		}
	}
	if len(gmail) == 0 {
		return []engine.Finding{pass("gcp_iam_gmail", "No gmail.com accounts have project IAM bindings",
			soc2("CC6.1"), hipaa("164.308(a)(3)"), cis("1.2"))}
	}
	return []engine.Finding{fail(
		"gcp_iam_gmail",
		fmt.Sprintf("%d gmail.com account(s) in project IAM: %v", len(gmail), truncate(gmail, 5)),
		engine.SeverityHigh,
		"Use corporate Google Workspace accounts instead of personal gmail accounts:\n  gcloud projects remove-iam-policy-binding PROJECT --member=user:email@gmail.com --role=ROLE",
		soc2("CC6.1"), hipaa("164.308(a)(3)"), cis("1.2"),
	)}
}

func (c *IAMExtraChecker) checkSAProjectOwner() []engine.Finding {
	ctx := context.Background()
	svc, err := cloudresourcemanager.NewService(ctx)
	if err != nil {
		return []engine.Finding{skip("gcp_iam_sa_owner", "GCP SA Project Owner", err.Error())}
	}
	policy, err := svc.Projects.GetIamPolicy("projects/"+c.projectID, &cloudresourcemanager.GetIamPolicyRequest{}).Do()
	if err != nil {
		return []engine.Finding{skip("gcp_iam_sa_owner", "GCP SA Project Owner", err.Error())}
	}
	var saOwners []string
	for _, binding := range policy.Bindings {
		if binding.Role != "roles/owner" {
			continue
		}
		for _, member := range binding.Members {
			if strings.HasPrefix(member, "serviceAccount:") {
				saOwners = append(saOwners, member)
			}
		}
	}
	if len(saOwners) == 0 {
		return []engine.Finding{pass("gcp_iam_sa_owner", "No service accounts have project Owner role",
			soc2("CC6.3"), hipaa("164.308(a)(3)"), cis("1.5"))}
	}
	return []engine.Finding{fail(
		"gcp_iam_sa_owner",
		fmt.Sprintf("%d service account(s) with project Owner role: %v", len(saOwners), truncate(saOwners, 5)),
		engine.SeverityCritical,
		"Remove Owner role from service accounts:\n  gcloud projects remove-iam-policy-binding PROJECT --member=serviceAccount:SA --role=roles/owner",
		soc2("CC6.3"), hipaa("164.308(a)(3)"), cis("1.5"),
	)}
}

func (c *IAMExtraChecker) checkSAKeyAge() []engine.Finding {
	ctx := context.Background()
	svc, err := iamapi.NewService(ctx)
	if err != nil {
		return []engine.Finding{skip("gcp_iam_sa_key_age", "GCP SA Key Age", err.Error())}
	}
	resp, err := svc.Projects.ServiceAccounts.List("projects/" + c.projectID).Do()
	if err != nil {
		return []engine.Finding{skip("gcp_iam_sa_key_age", "GCP SA Key Age", err.Error())}
	}
	cutoff := time.Now().AddDate(0, 0, -90)
	var stale []string
	for _, sa := range resp.Accounts {
		if sa.Disabled {
			continue
		}
		keys, err := svc.Projects.ServiceAccounts.Keys.List(sa.Name).KeyTypes("USER_MANAGED").Do()
		if err != nil {
			continue
		}
		for _, key := range keys.Keys {
			created, err := time.Parse(time.RFC3339, key.ValidAfterTime)
			if err != nil {
				continue
			}
			if created.Before(cutoff) {
				stale = append(stale, fmt.Sprintf("%s (key %s)", sa.Email, key.Name[len(key.Name)-8:]))
			}
		}
	}
	if len(stale) == 0 {
		return []engine.Finding{pass("gcp_iam_sa_key_age", "All service account keys created within 90 days",
			soc2("CC6.1"), hipaa("164.308(a)(5)"), cis("1.7"))}
	}
	return []engine.Finding{fail(
		"gcp_iam_sa_key_age",
		fmt.Sprintf("%d service account key(s) older than 90 days: %v", len(stale), truncate(stale, 5)),
		engine.SeverityHigh,
		"Rotate service account keys:\n  gcloud iam service-accounts keys delete OLD_KEY_ID --iam-account=SA_EMAIL\n  gcloud iam service-accounts keys create new-key.json --iam-account=SA_EMAIL",
		soc2("CC6.1"), hipaa("164.308(a)(5)"), cis("1.7"),
	)}
}
