package gcp

import (
	"context"
	"fmt"

	"google.golang.org/api/cloudkms/v1"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/container/v1"
	sqladmin "google.golang.org/api/sqladmin/v1beta4"
	"github.com/complykit/complykit/internal/engine"
)

type GCPP2Checker struct {
	projectID string
}

func NewGCPP2Checker(projectID string) *GCPP2Checker {
	return &GCPP2Checker{projectID: projectID}
}

func (c *GCPP2Checker) Integration() string { return "GCP/Encryption" }

func (c *GCPP2Checker) Run() ([]engine.Finding, error) {
	var findings []engine.Finding
	findings = append(findings, c.checkCloudSQLCMEK()...)
	findings = append(findings, c.checkGKEDatabaseEncryption()...)
	findings = append(findings, c.checkKMSKeyRotation()...)
	findings = append(findings, c.checkVMDiskCMEK()...)
	return findings, nil
}

// ── Cloud SQL CMEK ────────────────────────────────────────────────────────────

func (c *GCPP2Checker) checkCloudSQLCMEK() []engine.Finding {
	ctx := context.Background()
	svc, err := sqladmin.NewService(ctx)
	if err != nil {
		return []engine.Finding{skip("gcp_cloudsql_cmek", "GCP Cloud SQL CMEK", err.Error())}
	}
	instances, err := svc.Instances.List(c.projectID).Do()
	if err != nil {
		return []engine.Finding{skip("gcp_cloudsql_cmek", "GCP Cloud SQL CMEK", err.Error())}
	}
	if len(instances.Items) == 0 {
		return []engine.Finding{pass("gcp_cloudsql_cmek", "No Cloud SQL instances found",
			soc2("CC6.7"), hipaa("164.312(a)(2)(iv)"), cis("6.1"))}
	}
	var noCMEK []string
	for _, inst := range instances.Items {
		if inst.DiskEncryptionConfiguration == nil || inst.DiskEncryptionConfiguration.KmsKeyName == "" {
			noCMEK = append(noCMEK, inst.Name)
		}
	}
	if len(noCMEK) == 0 {
		return []engine.Finding{pass("gcp_cloudsql_cmek", "All Cloud SQL instances use CMEK encryption",
			soc2("CC6.7"), hipaa("164.312(a)(2)(iv)"), cis("6.1"))}
	}
	return []engine.Finding{fail(
		"gcp_cloudsql_cmek",
		fmt.Sprintf("%d Cloud SQL instance(s) without CMEK: %v", len(noCMEK), truncate(noCMEK, 5)),
		engine.SeverityMedium,
		"CMEK must be set at instance creation. Create new instance with CMEK:\n  gcloud sql instances create INSTANCE --disk-encryption-key=projects/PROJECT/locations/REGION/keyRings/RING/cryptoKeys/KEY",
		soc2("CC6.7"), hipaa("164.312(a)(2)(iv)"), cis("6.1"),
	)}
}

// ── GKE application-layer secrets encryption ─────────────────────────────────

func (c *GCPP2Checker) checkGKEDatabaseEncryption() []engine.Finding {
	ctx := context.Background()
	svc, err := container.NewService(ctx)
	if err != nil {
		return []engine.Finding{skip("gcp_gke_database_encryption", "GKE Database Encryption", err.Error())}
	}
	resp, err := svc.Projects.Locations.Clusters.List("projects/" + c.projectID + "/locations/-").Do()
	if err != nil {
		return []engine.Finding{skip("gcp_gke_database_encryption", "GKE Database Encryption", err.Error())}
	}
	if len(resp.Clusters) == 0 {
		return nil
	}
	var noEncryption []string
	for _, cl := range resp.Clusters {
		if cl.DatabaseEncryption == nil || cl.DatabaseEncryption.State != "ENCRYPTED" {
			noEncryption = append(noEncryption, cl.Name)
		}
	}
	if len(noEncryption) == 0 {
		return []engine.Finding{pass("gcp_gke_database_encryption", "All GKE clusters have application-layer secrets encryption enabled",
			soc2("CC6.7"), hipaa("164.312(a)(2)(iv)"), cis("6.3.1"))}
	}
	return []engine.Finding{fail(
		"gcp_gke_database_encryption",
		fmt.Sprintf("%d GKE cluster(s) without application-layer secrets encryption: %v", len(noEncryption), truncate(noEncryption, 5)),
		engine.SeverityMedium,
		"Enable application-layer secrets encryption:\n  gcloud container clusters update CLUSTER --database-encryption-key=projects/PROJECT/locations/REGION/keyRings/RING/cryptoKeys/KEY",
		soc2("CC6.7"), hipaa("164.312(a)(2)(iv)"), cis("6.3.1"),
	)}
}

// ── Cloud KMS key rotation ────────────────────────────────────────────────────

func (c *GCPP2Checker) checkKMSKeyRotation() []engine.Finding {
	ctx := context.Background()
	svc, err := cloudkms.NewService(ctx)
	if err != nil {
		return []engine.Finding{skip("gcp_kms_key_rotation", "GCP KMS Key Rotation", err.Error())}
	}

	parent := fmt.Sprintf("projects/%s/locations/-", c.projectID)
	keyrings, err := svc.Projects.Locations.KeyRings.List(parent).Do()
	if err != nil {
		return []engine.Finding{skip("gcp_kms_key_rotation", "GCP KMS Key Rotation", err.Error())}
	}
	if len(keyrings.KeyRings) == 0 {
		return []engine.Finding{pass("gcp_kms_key_rotation", "No Cloud KMS key rings found",
			soc2("CC6.7"), hipaa("164.312(a)(2)(iv)"))}
	}

	var noRotation []string
	for _, kr := range keyrings.KeyRings {
		keys, err := svc.Projects.Locations.KeyRings.CryptoKeys.List(kr.Name).Do()
		if err != nil {
			continue
		}
		for _, key := range keys.CryptoKeys {
			if key.Purpose != "ENCRYPT_DECRYPT" {
				continue
			}
			if key.RotationPeriod == "" && key.NextRotationTime == "" {
				noRotation = append(noRotation, key.Name)
			}
		}
	}

	if len(noRotation) == 0 {
		return []engine.Finding{pass("gcp_kms_key_rotation", "All Cloud KMS symmetric keys have rotation configured",
			soc2("CC6.7"), hipaa("164.312(a)(2)(iv)"))}
	}
	return []engine.Finding{fail(
		"gcp_kms_key_rotation",
		fmt.Sprintf("%d KMS key(s) without automatic rotation: %v", len(noRotation), truncate(noRotation, 5)),
		engine.SeverityMedium,
		"Enable automatic rotation:\n  gcloud kms keys update KEY_NAME --keyring=KEYRING --location=LOCATION --rotation-period=90d --next-rotation-time=$(date -d '+90 days' --iso-8601=seconds)",
		soc2("CC6.7"), hipaa("164.312(a)(2)(iv)"),
	)}
}

// ── VM disk CMEK ──────────────────────────────────────────────────────────────

func (c *GCPP2Checker) checkVMDiskCMEK() []engine.Finding {
	ctx := context.Background()
	svc, err := compute.NewService(ctx)
	if err != nil {
		return []engine.Finding{skip("gcp_vm_disk_cmek", "GCP VM Disk CMEK", err.Error())}
	}

	disks, err := svc.Disks.AggregatedList(c.projectID).Do()
	if err != nil {
		return []engine.Finding{skip("gcp_vm_disk_cmek", "GCP VM Disk CMEK", err.Error())}
	}

	var noCMEK []string
	for _, scopedList := range disks.Items {
		for _, disk := range scopedList.Disks {
			if disk.DiskEncryptionKey == nil || disk.DiskEncryptionKey.KmsKeyName == "" {
				noCMEK = append(noCMEK, disk.Name)
			}
		}
	}

	if len(noCMEK) == 0 {
		return []engine.Finding{pass("gcp_vm_disk_cmek", "All VM disks use CMEK encryption",
			soc2("CC6.7"), hipaa("164.312(a)(2)(iv)"), cis("4.7"))}
	}
	return []engine.Finding{fail(
		"gcp_vm_disk_cmek",
		fmt.Sprintf("%d VM disk(s) not using CMEK: %v", len(noCMEK), truncate(noCMEK, 5)),
		engine.SeverityLow,
		"CMEK must be set at disk creation. Create new disks with CMEK:\n  gcloud compute disks create DISK --kms-key=projects/PROJECT/locations/REGION/keyRings/RING/cryptoKeys/KEY",
		soc2("CC6.7"), hipaa("164.312(a)(2)(iv)"), cis("4.7"),
	)}
}
