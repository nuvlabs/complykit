package gcp

import (
	"context"
	"fmt"
	"strings"
	"time"

	dlp "google.golang.org/api/dlp/v2"

	"github.com/complykit/complykit/internal/engine"
)

// checkDLPJobs verifies that at least one active GCP DLP inspection job or
// job trigger exists that targets Cloud Storage within the project.
func (c *Checker) checkDLPJobs() []engine.Finding {
	ctx := context.Background()
	svc, err := dlp.NewService(ctx, c.opts...)
	if err != nil {
		return []engine.Finding{skip("gcp_dlp_job_active", "GCP DLP Inspection Jobs", err.Error())}
	}

	parent := fmt.Sprintf("projects/%s", c.projectID)

	// Check 1: active job triggers (scheduled, ongoing scans)
	triggerCount, terr := c.countActiveDLPTriggers(ctx, svc, parent)
	if terr != nil {
		if isDLPAPIError(terr) {
			return []engine.Finding{fail(
				"gcp_dlp_job_active",
				"Cloud DLP API is not enabled — no PII scanning configured for Cloud Storage",
				engine.SeverityHigh,
				"Enable the DLP API and create an inspection job trigger:\n"+
					"  gcloud services enable dlp.googleapis.com\n"+
					"  Console → Security → Data Loss Prevention → Create Job Trigger\n"+
					"  Add info types: US_SOCIAL_SECURITY_NUMBER, CREDIT_CARD_NUMBER,\n"+
					"  EMAIL_ADDRESS, PHONE_NUMBER, PERSON_NAME",
				soc2("CC6.8"), hipaa("164.312(a)(2)(iv)"),
			)}
		}
		if isPermissionError(terr) {
			return []engine.Finding{skip("gcp_dlp_job_active", "GCP DLP Jobs",
				"Permission denied — grant roles/dlp.reader to the service account")}
		}
	}

	if triggerCount > 0 {
		return []engine.Finding{pass(
			"gcp_dlp_job_active",
			fmt.Sprintf("%d active GCP DLP job trigger(s) scanning Cloud Storage for PII", triggerCount),
			soc2("CC6.8"), hipaa("164.312(a)(2)(iv)"),
		)}
	}

	// Check 2: recent completed jobs (last 30 days) as fallback
	recentJobs, jerr := c.countRecentDLPJobs(ctx, svc, parent)
	if jerr == nil && recentJobs > 0 {
		return []engine.Finding{pass(
			"gcp_dlp_job_active",
			fmt.Sprintf("%d GCP DLP inspection job(s) completed within the last 30 days", recentJobs),
			soc2("CC6.8"), hipaa("164.312(a)(2)(iv)"),
		)}
	}

	return []engine.Finding{fail(
		"gcp_dlp_job_active",
		"No active or recent GCP DLP inspection jobs found for Cloud Storage",
		engine.SeverityHigh,
		"Create a DLP inspection job trigger targeting Cloud Storage:\n"+
			"  1. Console → Security → Data Loss Prevention → Create Job Trigger\n"+
			"  2. Select storage scope: Cloud Storage bucket(s) containing sensitive data\n"+
			"  3. Add info types: US_SOCIAL_SECURITY_NUMBER, CREDIT_CARD_NUMBER,\n"+
			"     EMAIL_ADDRESS, PHONE_NUMBER, PERSON_NAME\n"+
			"  4. Set schedule: at least monthly",
		soc2("CC6.8"), hipaa("164.312(a)(2)(iv)"),
	)}
}

func (c *Checker) countActiveDLPTriggers(ctx context.Context, svc *dlp.Service, parent string) (int, error) {
	count := 0
	err := svc.Projects.JobTriggers.List(parent).Filter("status=HEALTHY").Pages(ctx,
		func(page *dlp.GooglePrivacyDlpV2ListJobTriggersResponse) error {
			for _, t := range page.JobTriggers {
				if t.InspectJob != nil &&
					t.InspectJob.StorageConfig != nil &&
					t.InspectJob.StorageConfig.CloudStorageOptions != nil {
					count++
				}
			}
			return nil
		})
	return count, err
}

func (c *Checker) countRecentDLPJobs(ctx context.Context, svc *dlp.Service, parent string) (int, error) {
	count := 0
	cutoff := time.Now().Add(-30 * 24 * time.Hour)
	err := svc.Projects.DlpJobs.List(parent).
		Type("INSPECT_JOB").
		Filter("state=DONE").
		Pages(ctx, func(page *dlp.GooglePrivacyDlpV2ListDlpJobsResponse) error {
			for _, job := range page.Jobs {
				if job.EndTime == "" {
					continue
				}
				t, perr := time.Parse(time.RFC3339, job.EndTime)
				if perr != nil || t.Before(cutoff) {
					continue
				}
				if job.InspectDetails != nil &&
					job.InspectDetails.RequestedOptions != nil &&
					job.InspectDetails.RequestedOptions.JobConfig != nil &&
					job.InspectDetails.RequestedOptions.JobConfig.StorageConfig != nil &&
					job.InspectDetails.RequestedOptions.JobConfig.StorageConfig.CloudStorageOptions != nil {
					count++
				}
			}
			return nil
		})
	return count, err
}

func isDLPAPIError(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "API has not been used") ||
		strings.Contains(msg, "not been enabled") ||
		strings.Contains(msg, "SERVICE_DISABLED")
}

func isPermissionError(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "403") ||
		strings.Contains(msg, "PERMISSION_DENIED") ||
		strings.Contains(msg, "Access denied")
}
