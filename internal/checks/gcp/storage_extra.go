package gcp

import (
	"context"
	"fmt"

	"google.golang.org/api/storage/v1"
	"github.com/complykit/complykit/internal/engine"
)

type StorageExtraChecker struct {
	projectID string
}

func NewStorageExtraChecker(projectID string) *StorageExtraChecker {
	return &StorageExtraChecker{projectID: projectID}
}

func (c *StorageExtraChecker) Integration() string { return "GCP/Storage" }

func (c *StorageExtraChecker) Run() ([]engine.Finding, error) {
	ctx := context.Background()
	svc, err := storage.NewService(ctx)
	if err != nil {
		return []engine.Finding{skip("gcp_gcs_extra", "GCP Cloud Storage Extra", err.Error())}, nil
	}
	buckets, err := svc.Buckets.List(c.projectID).Do()
	if err != nil {
		return []engine.Finding{skip("gcp_gcs_extra", "GCP Cloud Storage Extra", err.Error())}, nil
	}
	if len(buckets.Items) == 0 {
		return nil, nil
	}

	var noVersioning, noLogging, noCMEK []string
	for _, b := range buckets.Items {
		if b.Versioning == nil || !b.Versioning.Enabled {
			noVersioning = append(noVersioning, b.Name)
		}
		if b.Logging == nil || b.Logging.LogBucket == "" {
			noLogging = append(noLogging, b.Name)
		}
		if b.Encryption == nil || b.Encryption.DefaultKmsKeyName == "" {
			noCMEK = append(noCMEK, b.Name)
		}
	}

	var findings []engine.Finding
	for _, check := range []struct {
		id, title, remediation string
		items                  []string
		sev                    engine.Severity
		controls               []engine.ControlRef
	}{
		{"gcp_gcs_versioning", "GCS bucket(s) without versioning",
			"gcloud storage buckets update gs://BUCKET --versioning",
			noVersioning, engine.SeverityMedium,
			[]engine.ControlRef{soc2("CC7.2"), hipaa("164.312(c)(1)"), cis("5.3")}},
		{"gcp_gcs_logging", "GCS bucket(s) without access logging",
			"gcloud storage buckets update gs://BUCKET --log-bucket=LOG_BUCKET",
			noLogging, engine.SeverityMedium,
			[]engine.ControlRef{soc2("CC7.2"), hipaa("164.312(b)"), cis("5.4")}},
		{"gcp_gcs_cmek", "GCS bucket(s) not using CMEK encryption",
			"gcloud storage buckets update gs://BUCKET --default-encryption-key=KMS_KEY_NAME",
			noCMEK, engine.SeverityLow,
			[]engine.ControlRef{soc2("CC6.7"), hipaa("164.312(a)(2)(iv)"), cis("5.5")}},
	} {
		if len(check.items) == 0 {
			findings = append(findings, pass(check.id, "All GCS buckets: "+check.title+" ✓", check.controls...))
		} else {
			findings = append(findings, fail(
				check.id,
				fmt.Sprintf("%d %s: %v", len(check.items), check.title, truncate(check.items, 5)),
				check.sev, check.remediation, check.controls...,
			))
		}
	}
	return findings, nil
}
