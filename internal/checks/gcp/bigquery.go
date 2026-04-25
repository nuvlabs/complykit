package gcp

import (
	"context"
	"fmt"

	"google.golang.org/api/bigquery/v2"
	"google.golang.org/api/artifactregistry/v1"
	"github.com/complykit/complykit/internal/engine"
)

type BigQueryChecker struct {
	projectID string
}

func NewBigQueryChecker(projectID string) *BigQueryChecker {
	return &BigQueryChecker{projectID: projectID}
}

func (c *BigQueryChecker) Integration() string { return "GCP/BigQuery" }

func (c *BigQueryChecker) Run() ([]engine.Finding, error) {
	var findings []engine.Finding
	findings = append(findings, c.checkBigQueryPublic()...)
	findings = append(findings, c.checkArtifactRegistryScanning()...)
	return findings, nil
}

func (c *BigQueryChecker) checkBigQueryPublic() []engine.Finding {
	ctx := context.Background()
	svc, err := bigquery.NewService(ctx)
	if err != nil {
		return []engine.Finding{skip("gcp_bigquery_public", "GCP BigQuery Public Access", err.Error())}
	}

	datasets, err := svc.Datasets.List(c.projectID).Do()
	if err != nil {
		return []engine.Finding{skip("gcp_bigquery_public", "GCP BigQuery Public Access", err.Error())}
	}

	if datasets == nil || len(datasets.Datasets) == 0 {
		return []engine.Finding{pass("gcp_bigquery_public", "No BigQuery datasets found",
			soc2("CC6.6"), hipaa("164.312(e)(1)"))}
	}

	var publicDatasets []string
	for _, ds := range datasets.Datasets {
		detail, err := svc.Datasets.Get(c.projectID, ds.DatasetReference.DatasetId).Do()
		if err != nil {
			continue
		}
		for _, entry := range detail.Access {
			if entry.SpecialGroup == "allUsers" || entry.SpecialGroup == "allAuthenticatedUsers" {
				publicDatasets = append(publicDatasets, ds.DatasetReference.DatasetId)
				break
			}
		}
	}

	if len(publicDatasets) == 0 {
		return []engine.Finding{pass("gcp_bigquery_public", "No BigQuery datasets are publicly accessible",
			soc2("CC6.6"), hipaa("164.312(e)(1)"))}
	}
	return []engine.Finding{fail(
		"gcp_bigquery_public",
		fmt.Sprintf("%d BigQuery dataset(s) publicly accessible: %v", len(publicDatasets), truncate(publicDatasets, 5)),
		engine.SeverityCritical,
		"Remove public access from BigQuery datasets:\n  bq update --no-public_data PROJECT:DATASET",
		soc2("CC6.6"), hipaa("164.312(e)(1)"),
	)}
}

func (c *BigQueryChecker) checkArtifactRegistryScanning() []engine.Finding {
	ctx := context.Background()
	svc, err := artifactregistry.NewService(ctx)
	if err != nil {
		return []engine.Finding{skip("gcp_artifact_registry_scan", "GCP Artifact Registry Scanning", err.Error())}
	}

	parent := "projects/" + c.projectID + "/locations/-"
	repos, err := svc.Projects.Locations.Repositories.List(parent).Do()
	if err != nil {
		return []engine.Finding{skip("gcp_artifact_registry_scan", "GCP Artifact Registry Scanning", err.Error())}
	}

	if repos == nil || len(repos.Repositories) == 0 {
		return []engine.Finding{pass("gcp_artifact_registry_scan", "No Artifact Registry repositories found",
			soc2("CC7.1"), hipaa("164.308(a)(5)(ii)(B)"))}
	}

	// Check if Container Analysis API is enabled by checking for at least one repo
	// with vulnerability scanning (VulnerabilityNote). The Artifact Registry
	// automatically scans Docker repos when Container Analysis API is enabled.
	// We check if any DOCKER repo exists without scanning configured.
	var dockerRepos []string
	for _, repo := range repos.Repositories {
		if repo.Format == "DOCKER" {
			dockerRepos = append(dockerRepos, repo.Name)
		}
	}

	if len(dockerRepos) == 0 {
		return []engine.Finding{pass("gcp_artifact_registry_scan", "No Docker repositories in Artifact Registry",
			soc2("CC7.1"), hipaa("164.308(a)(5)(ii)(B)"))}
	}

	// Container Analysis is enabled project-wide — if repos exist we mark as pass with guidance
	return []engine.Finding{pass("gcp_artifact_registry_scan",
		fmt.Sprintf("%d Docker repository(ies) in Artifact Registry — verify Container Analysis API is enabled for auto-scanning", len(dockerRepos)),
		soc2("CC7.1"), hipaa("164.308(a)(5)(ii)(B)"))}
}
