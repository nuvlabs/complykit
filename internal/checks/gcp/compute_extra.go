package gcp

import (
	"context"
	"fmt"
	"strings"

	"google.golang.org/api/compute/v1"
	sqladmin "google.golang.org/api/sqladmin/v1beta4"
	"github.com/complykit/complykit/internal/engine"
)

type ComputeExtraChecker struct {
	projectID string
}

func NewComputeExtraChecker(projectID string) *ComputeExtraChecker {
	return &ComputeExtraChecker{projectID: projectID}
}

func (c *ComputeExtraChecker) Integration() string { return "GCP/Compute" }

func (c *ComputeExtraChecker) Run() ([]engine.Finding, error) {
	var findings []engine.Finding
	findings = append(findings, c.checkNoDefaultNetwork()...)
	findings = append(findings, c.checkVMOSLogin()...)
	findings = append(findings, c.checkVMProjectSSHKeys()...)
	findings = append(findings, c.checkVMSerialPort()...)
	findings = append(findings, c.checkVMShieldedVM()...)
	findings = append(findings, c.checkCloudSQLBackup()...)
	return findings, nil
}

func (c *ComputeExtraChecker) checkNoDefaultNetwork() []engine.Finding {
	ctx := context.Background()
	svc, err := compute.NewService(ctx)
	if err != nil {
		return []engine.Finding{skip("gcp_no_default_network", "GCP No Default Network", err.Error())}
	}
	nets, err := svc.Networks.List(c.projectID).Do()
	if err != nil {
		return []engine.Finding{skip("gcp_no_default_network", "GCP No Default Network", err.Error())}
	}
	for _, net := range nets.Items {
		if net.Name == "default" {
			return []engine.Finding{fail(
				"gcp_no_default_network", "Default VPC network exists in the project",
				engine.SeverityMedium,
				"Delete the default network:\n  gcloud compute networks delete default",
				soc2("CC6.6"), hipaa("164.312(e)(2)(i)"), cis("3.1"),
			)}
		}
	}
	return []engine.Finding{pass("gcp_no_default_network", "Default VPC network does not exist",
		soc2("CC6.6"), hipaa("164.312(e)(2)(i)"), cis("3.1"))}
}

func (c *ComputeExtraChecker) checkVMOSLogin() []engine.Finding {
	ctx := context.Background()
	svc, err := compute.NewService(ctx)
	if err != nil {
		return []engine.Finding{skip("gcp_vm_os_login", "GCP VM OS Login", err.Error())}
	}
	// Check project-level metadata
	proj, err := svc.Projects.Get(c.projectID).Do()
	if err != nil {
		return []engine.Finding{skip("gcp_vm_os_login", "GCP VM OS Login", err.Error())}
	}
	if proj.CommonInstanceMetadata != nil {
		for _, item := range proj.CommonInstanceMetadata.Items {
			if item.Key == "enable-oslogin" && strings.ToLower(*item.Value) == "true" {
				return []engine.Finding{pass("gcp_vm_os_login", "OS Login enabled at project level",
					soc2("CC6.1"), hipaa("164.308(a)(3)"), cis("4.4"))}
			}
		}
	}
	return []engine.Finding{fail(
		"gcp_vm_os_login", "OS Login not enabled at project level",
		engine.SeverityMedium,
		"Enable OS Login project-wide:\n  gcloud compute project-info add-metadata --metadata enable-oslogin=TRUE",
		soc2("CC6.1"), hipaa("164.308(a)(3)"), cis("4.4"),
	)}
}

func (c *ComputeExtraChecker) checkVMProjectSSHKeys() []engine.Finding {
	ctx := context.Background()
	svc, err := compute.NewService(ctx)
	if err != nil {
		return []engine.Finding{skip("gcp_vm_project_ssh_keys", "GCP Project-Wide SSH Keys", err.Error())}
	}
	proj, err := svc.Projects.Get(c.projectID).Do()
	if err != nil {
		return []engine.Finding{skip("gcp_vm_project_ssh_keys", "GCP Project-Wide SSH Keys", err.Error())}
	}
	if proj.CommonInstanceMetadata != nil {
		for _, item := range proj.CommonInstanceMetadata.Items {
			if item.Key == "ssh-keys" && item.Value != nil && *item.Value != "" {
				return []engine.Finding{fail(
					"gcp_vm_project_ssh_keys", "Project-wide SSH keys are configured",
					engine.SeverityMedium,
					"Remove project-wide SSH keys and use OS Login instead:\n  gcloud compute project-info remove-metadata --keys=ssh-keys",
					soc2("CC6.1"), hipaa("164.308(a)(3)"), cis("4.3"),
				)}
			}
		}
	}
	return []engine.Finding{pass("gcp_vm_project_ssh_keys", "No project-wide SSH keys configured",
		soc2("CC6.1"), hipaa("164.308(a)(3)"), cis("4.3"))}
}

func (c *ComputeExtraChecker) checkVMSerialPort() []engine.Finding {
	ctx := context.Background()
	svc, err := compute.NewService(ctx)
	if err != nil {
		return []engine.Finding{skip("gcp_vm_serial_port", "GCP VM Serial Port", err.Error())}
	}
	instances, err := svc.Instances.AggregatedList(c.projectID).Do()
	if err != nil {
		return []engine.Finding{skip("gcp_vm_serial_port", "GCP VM Serial Port", err.Error())}
	}
	var enabled []string
	for _, scoped := range instances.Items {
		for _, inst := range scoped.Instances {
			if inst.Metadata != nil {
				for _, item := range inst.Metadata.Items {
					if item.Key == "serial-port-enable" && item.Value != nil &&
						(strings.ToLower(*item.Value) == "true" || *item.Value == "1") {
						enabled = append(enabled, inst.Name)
					}
				}
			}
		}
	}
	if len(enabled) == 0 {
		return []engine.Finding{pass("gcp_vm_serial_port", "No VM instances have serial port access enabled",
			soc2("CC6.6"), hipaa("164.312(e)(2)(i)"), cis("4.5"))}
	}
	return []engine.Finding{fail(
		"gcp_vm_serial_port",
		fmt.Sprintf("%d VM(s) with serial port access enabled: %v", len(enabled), truncate(enabled, 5)),
		engine.SeverityMedium,
		"Disable serial port access:\n  gcloud compute instances add-metadata INSTANCE --metadata serial-port-enable=false",
		soc2("CC6.6"), hipaa("164.312(e)(2)(i)"), cis("4.5"),
	)}
}

func (c *ComputeExtraChecker) checkVMShieldedVM() []engine.Finding {
	ctx := context.Background()
	svc, err := compute.NewService(ctx)
	if err != nil {
		return []engine.Finding{skip("gcp_vm_shielded", "GCP Shielded VM", err.Error())}
	}
	instances, err := svc.Instances.AggregatedList(c.projectID).Do()
	if err != nil {
		return []engine.Finding{skip("gcp_vm_shielded", "GCP Shielded VM", err.Error())}
	}
	var notShielded []string
	for _, scoped := range instances.Items {
		for _, inst := range scoped.Instances {
			if inst.ShieldedInstanceConfig == nil || !inst.ShieldedInstanceConfig.EnableSecureBoot {
				notShielded = append(notShielded, inst.Name)
			}
		}
	}
	if len(notShielded) == 0 {
		return []engine.Finding{pass("gcp_vm_shielded", "All VM instances have Shielded VM (Secure Boot) enabled",
			soc2("CC6.6"), cis("4.8"))}
	}
	return []engine.Finding{fail(
		"gcp_vm_shielded",
		fmt.Sprintf("%d VM(s) without Shielded VM enabled: %v", len(notShielded), truncate(notShielded, 5)),
		engine.SeverityMedium,
		"Enable Secure Boot on VMs:\n  gcloud compute instances update INSTANCE --shielded-secure-boot",
		soc2("CC6.6"), cis("4.8"),
	)}
}

func (c *ComputeExtraChecker) checkCloudSQLBackup() []engine.Finding {
	ctx := context.Background()
	svc, err := sqladmin.NewService(ctx)
	if err != nil {
		return []engine.Finding{skip("gcp_cloudsql_backup", "GCP Cloud SQL Backup", err.Error())}
	}
	instances, err := svc.Instances.List(c.projectID).Do()
	if err != nil {
		return []engine.Finding{skip("gcp_cloudsql_backup", "GCP Cloud SQL Backup", err.Error())}
	}
	if len(instances.Items) == 0 {
		return []engine.Finding{pass("gcp_cloudsql_backup", "No Cloud SQL instances found",
			soc2("CC9.1"), hipaa("164.308(a)(7)"), cis("6.7"))}
	}
	var noBackup []string
	for _, inst := range instances.Items {
		if inst.Settings == nil || inst.Settings.BackupConfiguration == nil || !inst.Settings.BackupConfiguration.Enabled {
			noBackup = append(noBackup, inst.Name)
		}
	}
	if len(noBackup) == 0 {
		return []engine.Finding{pass("gcp_cloudsql_backup", "All Cloud SQL instances have automated backups enabled",
			soc2("CC9.1"), hipaa("164.308(a)(7)"), cis("6.7"))}
	}
	return []engine.Finding{fail(
		"gcp_cloudsql_backup",
		fmt.Sprintf("%d Cloud SQL instance(s) without automated backups: %v", len(noBackup), truncate(noBackup, 5)),
		engine.SeverityHigh,
		"Enable automated backups:\n  gcloud sql instances patch INSTANCE --backup-start-time=02:00",
		soc2("CC9.1"), hipaa("164.308(a)(7)"), cis("6.7"),
	)}
}
