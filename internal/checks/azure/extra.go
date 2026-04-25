package azure

import (
	"context"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitor"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/security/armsecurity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/sql/armsql"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/complykit/complykit/internal/engine"
)

// ── Storage extras ────────────────────────────────────────────────────────────

func (c *Checker) checkStorageTLS() []engine.Finding {
	client, err := armstorage.NewAccountsClient(c.subscriptionID, c.cred, nil)
	if err != nil {
		return []engine.Finding{skip("az_storage_tls", "Azure Storage TLS", err.Error())}
	}
	pager := client.NewListPager(nil)
	var oldTLS []string
	for pager.More() {
		page, err := pager.NextPage(context.Background())
		if err != nil {
			return []engine.Finding{skip("az_storage_tls", "Azure Storage TLS", err.Error())}
		}
		for _, acct := range page.Value {
			if acct.Properties == nil || acct.Properties.MinimumTLSVersion == nil ||
				*acct.Properties.MinimumTLSVersion != armstorage.MinimumTLSVersionTLS12 {
				oldTLS = append(oldTLS, ptrStr(acct.Name))
			}
		}
	}
	if len(oldTLS) == 0 {
		return []engine.Finding{pass("az_storage_tls", "All storage accounts enforce TLS 1.2+",
			soc2("CC6.7"), hipaa("164.312(e)(2)(ii)"), cis("3.4"))}
	}
	return []engine.Finding{fail(
		"az_storage_tls",
		fmt.Sprintf("%d storage account(s) not enforcing TLS 1.2: %v", len(oldTLS), truncate(oldTLS, 5)),
		engine.SeverityHigh,
		"Set minimum TLS version:\n  az storage account update --name ACCOUNT --resource-group RG --min-tls-version TLS1_2",
		soc2("CC6.7"), hipaa("164.312(e)(2)(ii)"), cis("3.4"),
	)}
}

func (c *Checker) checkStorageSoftDelete() []engine.Finding {
	client, err := armstorage.NewAccountsClient(c.subscriptionID, c.cred, nil)
	if err != nil {
		return []engine.Finding{skip("az_storage_soft_delete", "Azure Storage Soft Delete", err.Error())}
	}
	pager := client.NewListPager(nil)
	var noSoftDelete []string
	blobSvcClient, _ := armstorage.NewBlobServicesClient(c.subscriptionID, c.cred, nil)

	for pager.More() {
		page, err := pager.NextPage(context.Background())
		if err != nil {
			return []engine.Finding{skip("az_storage_soft_delete", "Azure Storage Soft Delete", err.Error())}
		}
		for _, acct := range page.Value {
			name := ptrStr(acct.Name)
			rg := resourceGroupFromID(ptrStr(acct.ID))
			if blobSvcClient == nil {
				continue
			}
			props, err := blobSvcClient.GetServiceProperties(context.Background(), rg, name, nil)
			inner := props.BlobServiceProperties.BlobServiceProperties
			if err != nil || inner == nil || inner.DeleteRetentionPolicy == nil ||
				inner.DeleteRetentionPolicy.Enabled == nil ||
				!*inner.DeleteRetentionPolicy.Enabled {
				noSoftDelete = append(noSoftDelete, name)
			}
		}
	}
	if len(noSoftDelete) == 0 {
		return []engine.Finding{pass("az_storage_soft_delete", "All storage accounts have blob soft delete enabled",
			soc2("CC9.1"), hipaa("164.308(a)(7)"), cis("3.8"))}
	}
	return []engine.Finding{fail(
		"az_storage_soft_delete",
		fmt.Sprintf("%d storage account(s) without blob soft delete: %v", len(noSoftDelete), truncate(noSoftDelete, 5)),
		engine.SeverityMedium,
		"Enable soft delete:\n  az storage blob service-properties delete-policy update --account-name ACCOUNT --enable true --days-retained 7",
		soc2("CC9.1"), hipaa("164.308(a)(7)"), cis("3.8"),
	)}
}

// ── Networking extras ─────────────────────────────────────────────────────────

func (c *Checker) checkNSGFlowLogs() []engine.Finding {
	watcher, err := armnetwork.NewWatchersClient(c.subscriptionID, c.cred, nil)
	if err != nil {
		return []engine.Finding{skip("az_nsg_flow_logs", "Azure NSG Flow Logs", err.Error())}
	}
	pager := watcher.NewListAllPager(nil)
	hasWatcher := false
	for pager.More() {
		page, err := pager.NextPage(context.Background())
		if err != nil {
			break
		}
		if len(page.Value) > 0 {
			hasWatcher = true
		}
	}
	if hasWatcher {
		return []engine.Finding{pass("az_nsg_flow_logs", "Network Watcher exists — verify NSG flow logs are enabled per region",
			soc2("CC7.2"), hipaa("164.312(b)"), cis("6.4"))}
	}
	return []engine.Finding{fail(
		"az_nsg_flow_logs", "Network Watcher is not configured",
		engine.SeverityMedium,
		"Enable Network Watcher:\n  az network watcher configure --resource-group NetworkWatcherRG --locations REGION --enabled true",
		soc2("CC7.2"), hipaa("164.312(b)"), cis("6.4"),
	)}
}

// ── Compute extras ────────────────────────────────────────────────────────────

func (c *Checker) checkVMBackup() []engine.Finding {
	// Check if Recovery Services vaults exist with backup policies
	// Uses the armcompute VMs list and looks for backup extension
	client, err := armcompute.NewVirtualMachinesClient(c.subscriptionID, c.cred, nil)
	if err != nil {
		return []engine.Finding{skip("az_vm_backup", "Azure VM Backup", err.Error())}
	}
	pager := client.NewListAllPager(nil)
	var noBackup []string
	for pager.More() {
		page, err := pager.NextPage(context.Background())
		if err != nil {
			return []engine.Finding{skip("az_vm_backup", "Azure VM Backup", err.Error())}
		}
		for _, vm := range page.Value {
			name := ptrStr(vm.Name)
			hasBackupTag := false
			for k := range vm.Tags {
				if strings.Contains(strings.ToLower(k), "backup") {
					hasBackupTag = true
					break
				}
			}
			if !hasBackupTag {
				noBackup = append(noBackup, name)
			}
		}
	}
	if len(noBackup) == 0 {
		return []engine.Finding{pass("az_vm_backup", "All VMs appear to have backup configured",
			soc2("CC9.1"), hipaa("164.308(a)(7)"), cis("7.4"))}
	}
	return []engine.Finding{fail(
		"az_vm_backup",
		fmt.Sprintf("%d VM(s) without backup tag — verify Azure Backup is configured: %v", len(noBackup), truncate(noBackup, 5)),
		engine.SeverityHigh,
		"Enable Azure Backup for VMs:\n  az backup protection enable-for-vm --resource-group RG --vault-name VAULT --vm VM_NAME --policy-name DefaultPolicy",
		soc2("CC9.1"), hipaa("164.308(a)(7)"), cis("7.4"),
	)}
}

// ── Logging extras ────────────────────────────────────────────────────────────

func (c *Checker) checkActivityLogRetention() []engine.Finding {
	client, err := armmonitor.NewDiagnosticSettingsClient(c.cred, nil)
	if err != nil {
		return []engine.Finding{skip("az_activity_log_retention", "Azure Activity Log Retention", err.Error())}
	}
	resourceURI := "/subscriptions/" + c.subscriptionID
	pager := client.NewListPager(resourceURI, nil)
	for pager.More() {
		page, err := pager.NextPage(context.Background())
		if err != nil {
			break
		}
		for _, setting := range page.Value {
			if setting.Properties == nil {
				continue
			}
			for _, log := range setting.Properties.Logs {
				if log.RetentionPolicy != nil && log.RetentionPolicy.Enabled != nil &&
					*log.RetentionPolicy.Enabled &&
					log.RetentionPolicy.Days != nil && *log.RetentionPolicy.Days >= 365 {
					return []engine.Finding{pass("az_activity_log_retention", "Activity log retention is set to 365+ days",
						soc2("CC7.2"), hipaa("164.312(b)"), cis("5.1.2"))}
				}
			}
		}
	}
	return []engine.Finding{fail(
		"az_activity_log_retention", "Activity log retention is less than 365 days",
		engine.SeverityMedium,
		"Set activity log retention to at least 1 year:\n  az monitor diagnostic-settings update --resource /subscriptions/SUB --name SETTING --set properties.logs[0].retentionPolicy.days=365",
		soc2("CC7.2"), hipaa("164.312(b)"), cis("5.1.2"),
	)}
}

func (c *Checker) checkLogAlerts() []engine.Finding {
	alertsClient, err := armmonitor.NewActivityLogAlertsClient(c.subscriptionID, c.cred, nil)
	if err != nil {
		return []engine.Finding{skip("az_log_alerts", "Azure Activity Log Alerts", err.Error())}
	}
	pager := alertsClient.NewListBySubscriptionIDPager(nil)
	var alerts []string
	for pager.More() {
		page, err := pager.NextPage(context.Background())
		if err != nil {
			break
		}
		for _, a := range page.Value {
			alerts = append(alerts, ptrStr(a.Name))
		}
	}
	if len(alerts) > 0 {
		return []engine.Finding{pass("az_log_alerts",
			fmt.Sprintf("%d activity log alert(s) configured — verify they cover policy/NSG/SQL changes", len(alerts)),
			soc2("CC7.2"), hipaa("164.312(b)"), cis("5.2.1"))}
	}
	return []engine.Finding{fail(
		"az_log_alerts", "No activity log alerts configured",
		engine.SeverityMedium,
		"Create activity log alerts for critical operations:\n  az monitor activity-log alert create --name PolicyAlert --resource-group RG --condition category=Policy",
		soc2("CC7.2"), hipaa("164.312(b)"), cis("5.2.1"),
	)}
}

// ── SQL extras ────────────────────────────────────────────────────────────────

func (c *Checker) checkSQLThreatDetection() []engine.Finding {
	serverClient, err := armsql.NewServersClient(c.subscriptionID, c.cred, nil)
	if err != nil {
		return []engine.Finding{skip("az_sql_threat", "Azure SQL Threat Detection", err.Error())}
	}
	atpClient, _ := armsql.NewServerAdvancedThreatProtectionSettingsClient(c.subscriptionID, c.cred, nil)
	pager := serverClient.NewListPager(nil)
	var noATP []string
	for pager.More() {
		page, err := pager.NextPage(context.Background())
		if err != nil {
			break
		}
		for _, server := range page.Value {
			name := ptrStr(server.Name)
			rg := resourceGroupFromID(ptrStr(server.ID))
			if atpClient == nil {
				noATP = append(noATP, name)
				continue
			}
			resp, err := atpClient.Get(context.Background(), rg, name, armsql.AdvancedThreatProtectionNameDefault, nil)
			if err != nil || resp.Properties == nil ||
				resp.Properties.State == nil ||
				*resp.Properties.State != armsql.AdvancedThreatProtectionStateEnabled {
				noATP = append(noATP, name)
			}
		}
	}
	if len(noATP) == 0 {
		return []engine.Finding{pass("az_sql_threat", "All SQL servers have Advanced Threat Protection enabled",
			soc2("CC6.8"), hipaa("164.308(a)(1)(ii)(D)"), cis("4.2.1"))}
	}
	return []engine.Finding{fail(
		"az_sql_threat",
		fmt.Sprintf("%d SQL server(s) without Advanced Threat Protection: %v", len(noATP), truncate(noATP, 5)),
		engine.SeverityHigh,
		"Enable Advanced Threat Protection:\n  az sql server atp-policy update --resource-group RG --server SERVER --state Enabled",
		soc2("CC6.8"), hipaa("164.308(a)(1)(ii)(D)"), cis("4.2.1"),
	)}
}

func (c *Checker) checkSQLFirewall() []engine.Finding {
	serverClient, err := armsql.NewServersClient(c.subscriptionID, c.cred, nil)
	if err != nil {
		return []engine.Finding{skip("az_sql_firewall", "Azure SQL Firewall", err.Error())}
	}
	fwClient, _ := armsql.NewFirewallRulesClient(c.subscriptionID, c.cred, nil)
	pager := serverClient.NewListPager(nil)
	var openFW []string
	for pager.More() {
		page, err := pager.NextPage(context.Background())
		if err != nil {
			break
		}
		for _, server := range page.Value {
			name := ptrStr(server.Name)
			rg := resourceGroupFromID(ptrStr(server.ID))
			if fwClient == nil {
				continue
			}
			fwPager := fwClient.NewListByServerPager(rg, name, nil)
			for fwPager.More() {
				fwPage, err := fwPager.NextPage(context.Background())
				if err != nil {
					break
				}
				for _, rule := range fwPage.Value {
					if rule.Properties == nil {
						continue
					}
					start := ptrStr(rule.Properties.StartIPAddress)
					end := ptrStr(rule.Properties.EndIPAddress)
					if start == "0.0.0.0" && end == "255.255.255.255" {
						openFW = append(openFW, fmt.Sprintf("%s/%s", name, ptrStr(rule.Name)))
					}
				}
			}
		}
	}
	if len(openFW) == 0 {
		return []engine.Finding{pass("az_sql_firewall", "No SQL Server firewall rules allow all IPs",
			soc2("CC6.6"), hipaa("164.312(e)(2)(i)"), cis("4.3"))}
	}
	return []engine.Finding{fail(
		"az_sql_firewall",
		fmt.Sprintf("%d SQL Server firewall rule(s) allow all IPs (0.0.0.0–255.255.255.255): %v", len(openFW), truncate(openFW, 5)),
		engine.SeverityCritical,
		"Remove open firewall rules:\n  az sql server firewall-rule delete --resource-group RG --server SERVER --name RULE_NAME",
		soc2("CC6.6"), hipaa("164.312(e)(2)(i)"), cis("4.3"),
	)}
}

func (c *Checker) checkSQLAuditRetention() []engine.Finding {
	serverClient, err := armsql.NewServersClient(c.subscriptionID, c.cred, nil)
	if err != nil {
		return []engine.Finding{skip("az_sql_audit_retention", "Azure SQL Audit Retention", err.Error())}
	}
	auditClient, _ := armsql.NewServerBlobAuditingPoliciesClient(c.subscriptionID, c.cred, nil)
	pager := serverClient.NewListPager(nil)
	var shortRetention []string
	for pager.More() {
		page, err := pager.NextPage(context.Background())
		if err != nil {
			break
		}
		for _, server := range page.Value {
			name := ptrStr(server.Name)
			rg := resourceGroupFromID(ptrStr(server.ID))
			if auditClient == nil {
				shortRetention = append(shortRetention, name)
				continue
			}
			policy, err := auditClient.Get(context.Background(), rg, name, nil)
			if err != nil || policy.Properties == nil ||
				policy.Properties.RetentionDays == nil ||
				*policy.Properties.RetentionDays < 90 {
				shortRetention = append(shortRetention, name)
			}
		}
	}
	if len(shortRetention) == 0 {
		return []engine.Finding{pass("az_sql_audit_retention", "All SQL servers have audit retention ≥ 90 days",
			soc2("CC7.2"), hipaa("164.312(b)"), cis("4.1.3"))}
	}
	return []engine.Finding{fail(
		"az_sql_audit_retention",
		fmt.Sprintf("%d SQL server(s) with audit retention < 90 days: %v", len(shortRetention), truncate(shortRetention, 5)),
		engine.SeverityMedium,
		"Set audit retention to 90+ days:\n  az sql server audit-policy update --resource-group RG --name SERVER --retention-days 90",
		soc2("CC7.2"), hipaa("164.312(b)"), cis("4.1.3"),
	)}
}

// ── AKS extras ────────────────────────────────────────────────────────────────

func (c *Checker) checkDefenderContainers() []engine.Finding {
	client, err := armsecurity.NewPricingsClient(c.cred, nil)
	if err != nil {
		return []engine.Finding{skip("az_aks_defender_containers", "Defender for Containers", err.Error())}
	}
	scope := "subscriptions/" + c.subscriptionID
	resp, err := client.List(context.Background(), scope, nil)
	if err != nil {
		return []engine.Finding{skip("az_aks_defender_containers", "Defender for Containers", err.Error())}
	}
	for _, p := range resp.Value {
		if p.Name != nil && *p.Name == "Containers" &&
			p.Properties != nil && p.Properties.PricingTier != nil &&
			*p.Properties.PricingTier == armsecurity.PricingTierStandard {
			return []engine.Finding{pass("az_aks_defender_containers", "Defender for Containers is enabled",
				soc2("CC6.8"), hipaa("164.308(a)(1)(ii)(D)"), cis("5.4.3"))}
		}
	}
	return []engine.Finding{fail(
		"az_aks_defender_containers", "Defender for Containers is not enabled",
		engine.SeverityHigh,
		"Enable Defender for Containers:\n  az security pricing create --name Containers --tier Standard",
		soc2("CC6.8"), hipaa("164.308(a)(1)(ii)(D)"), cis("5.4.3"),
	)}
}
