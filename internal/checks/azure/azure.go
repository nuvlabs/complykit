package azure

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitor"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/security/armsecurity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/sql/armsql"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"

	"github.com/complykit/complykit/internal/engine"
)

type Checker struct {
	subscriptionID string
	cred           *azidentity.DefaultAzureCredential
}

func NewChecker(subscriptionID string) (*Checker, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, err
	}
	return &Checker{subscriptionID: subscriptionID, cred: cred}, nil
}

func NewCheckerFromEnv() *Checker {
	subID := os.Getenv("AZURE_SUBSCRIPTION_ID")
	if subID == "" {
		return nil
	}
	c, err := NewChecker(subID)
	if err != nil {
		return nil
	}
	return c
}

func (c *Checker) Integration() string { return "Azure" }

func (c *Checker) Run() ([]engine.Finding, error) {
	var out []engine.Finding
	out = append(out, c.checkStorageAccounts()...)
	out = append(out, c.checkStorageTLS()...)
	out = append(out, c.checkStorageSoftDelete()...)
	out = append(out, c.checkNSGRules()...)
	out = append(out, c.checkNSGFlowLogs()...)
	out = append(out, c.checkVMDiskEncryption()...)
	out = append(out, c.checkVMBackup()...)
	out = append(out, c.checkDefenderForCloud()...)
	out = append(out, c.checkDefenderContainers()...)
	out = append(out, c.checkActivityLogs()...)
	out = append(out, c.checkActivityLogRetention()...)
	out = append(out, c.checkLogAlerts()...)
	out = append(out, c.checkSQLSecurity()...)
	out = append(out, c.checkSQLThreatDetection()...)
	out = append(out, c.checkSQLFirewall()...)
	out = append(out, c.checkSQLAuditRetention()...)
	out = append(out, c.checkAKSClusters()...)
	out = append(out, c.checkKeyVault()...)
	out = append(out, c.checkStorageInfraEncryption()...)
	out = append(out, c.checkSQLVulnAssessment()...)
	out = append(out, c.checkAKSNodeAutoUpgrade()...)
	// P2 additions
	out = append(out, c.checkConditionalAccessMFA()...)
	out = append(out, c.checkNoGuestAdmins()...)
	out = append(out, c.checkPIM()...)
	out = append(out, c.checkAKSCSISecrets()...)
	out = append(out, c.checkNetworkWatcherAllRegions()...)
	// P3 additions
	out = append(out, c.checkVMTrustedLaunch()...)
	return out, nil
}

// ── Storage Accounts ──────────────────────────────────────────────────────────

func (c *Checker) checkStorageAccounts() []engine.Finding {
	client, err := armstorage.NewAccountsClient(c.subscriptionID, c.cred, nil)
	if err != nil {
		return []engine.Finding{skip("az_storage", "Azure Storage Accounts", err.Error())}
	}
	pager := client.NewListPager(nil)
	var noHTTPS, publicAccess []string
	hasAny := false

	for pager.More() {
		page, err := pager.NextPage(context.Background())
		if err != nil {
			return []engine.Finding{skip("az_storage", "Azure Storage Accounts", err.Error())}
		}
		for _, acct := range page.Value {
			hasAny = true
			name := ptrStr(acct.Name)
			if acct.Properties == nil || acct.Properties.EnableHTTPSTrafficOnly == nil || !*acct.Properties.EnableHTTPSTrafficOnly {
				noHTTPS = append(noHTTPS, name)
			}
			if acct.Properties != nil && acct.Properties.AllowBlobPublicAccess != nil && *acct.Properties.AllowBlobPublicAccess {
				publicAccess = append(publicAccess, name)
			}
		}
	}

	var findings []engine.Finding
	if !hasAny {
		return []engine.Finding{pass("az_storage_https", "No Azure Storage accounts found",
			soc2("CC6.7"), hipaa("164.312(e)(2)(ii)"), cis("3.1"))}
	}
	if len(noHTTPS) == 0 {
		findings = append(findings, pass("az_storage_https", "All storage accounts enforce HTTPS-only traffic",
			soc2("CC6.7"), hipaa("164.312(e)(2)(ii)"), cis("3.1")))
	} else {
		findings = append(findings, fail(
			"az_storage_https",
			fmt.Sprintf("%d storage account(s) not enforcing HTTPS: %v", len(noHTTPS), truncate(noHTTPS, 5)),
			engine.SeverityHigh,
			"Enable HTTPS-only traffic:\n  az storage account update --name ACCOUNT --resource-group RG --https-only true",
			soc2("CC6.7"), hipaa("164.312(e)(2)(ii)"), cis("3.1"),
		))
	}
	if len(publicAccess) == 0 {
		findings = append(findings, pass("az_storage_public", "No storage accounts allow public blob access",
			soc2("CC6.6"), hipaa("164.312(e)(1)"), cis("3.7")))
	} else {
		findings = append(findings, fail(
			"az_storage_public",
			fmt.Sprintf("%d storage account(s) allow public blob access: %v", len(publicAccess), truncate(publicAccess, 5)),
			engine.SeverityCritical,
			"Disable public blob access:\n  az storage account update --name ACCOUNT --resource-group RG --allow-blob-public-access false",
			soc2("CC6.6"), hipaa("164.312(e)(1)"), cis("3.7"),
		))
	}
	return findings
}

// ── Network Security Groups ───────────────────────────────────────────────────

func (c *Checker) checkNSGRules() []engine.Finding {
	client, err := armnetwork.NewSecurityGroupsClient(c.subscriptionID, c.cred, nil)
	if err != nil {
		return []engine.Finding{skip("az_nsg", "Azure NSG Rules", err.Error())}
	}
	pager := client.NewListAllPager(nil)
	var openSSH, openRDP []string

	for pager.More() {
		page, err := pager.NextPage(context.Background())
		if err != nil {
			return []engine.Finding{skip("az_nsg", "Azure NSG Rules", err.Error())}
		}
		for _, nsg := range page.Value {
			nsgName := ptrStr(nsg.Name)
			if nsg.Properties == nil {
				continue
			}
			for _, rule := range nsg.Properties.SecurityRules {
				if rule.Properties == nil {
					continue
				}
				p := rule.Properties
				if p.Access == nil || *p.Access != armnetwork.SecurityRuleAccessAllow {
					continue
				}
				if p.Direction == nil || *p.Direction != armnetwork.SecurityRuleDirectionInbound {
					continue
				}
				src := ptrStr(p.SourceAddressPrefix)
				if src != "*" && src != "Internet" && src != "0.0.0.0/0" {
					continue
				}
				label := fmt.Sprintf("%s/%s", nsgName, ptrStr(rule.Name))
				if nsgPortMatches(p, 22) {
					openSSH = append(openSSH, label)
				}
				if nsgPortMatches(p, 3389) {
					openRDP = append(openRDP, label)
				}
			}
		}
	}

	var findings []engine.Finding
	if len(openSSH) == 0 {
		findings = append(findings, pass("az_nsg_ssh", "No NSG rules allow SSH from Internet",
			soc2("CC6.6"), hipaa("164.312(e)(2)(i)"), cis("6.2")))
	} else {
		findings = append(findings, fail(
			"az_nsg_ssh",
			fmt.Sprintf("%d NSG rule(s) allow SSH from Internet: %v", len(openSSH), truncate(openSSH, 5)),
			engine.SeverityCritical,
			"Restrict SSH (port 22) to specific IPs:\n  az network nsg rule update --nsg-name NSG --name RULE --resource-group RG --source-address-prefixes YOUR_IP",
			soc2("CC6.6"), hipaa("164.312(e)(2)(i)"), cis("6.2"),
		))
	}
	if len(openRDP) == 0 {
		findings = append(findings, pass("az_nsg_rdp", "No NSG rules allow RDP from Internet",
			soc2("CC6.6"), hipaa("164.312(e)(2)(i)"), cis("6.1")))
	} else {
		findings = append(findings, fail(
			"az_nsg_rdp",
			fmt.Sprintf("%d NSG rule(s) allow RDP from Internet: %v", len(openRDP), truncate(openRDP, 5)),
			engine.SeverityCritical,
			"Restrict RDP (port 3389) to specific IPs:\n  az network nsg rule update --nsg-name NSG --name RULE --resource-group RG --source-address-prefixes YOUR_IP",
			soc2("CC6.6"), hipaa("164.312(e)(2)(i)"), cis("6.1"),
		))
	}
	return findings
}

// ── VM Disk Encryption ────────────────────────────────────────────────────────

func (c *Checker) checkVMDiskEncryption() []engine.Finding {
	client, err := armcompute.NewDisksClient(c.subscriptionID, c.cred, nil)
	if err != nil {
		return []engine.Finding{skip("az_disk_encryption", "Azure VM Disk Encryption", err.Error())}
	}
	pager := client.NewListPager(nil)
	var unencrypted []string
	hasAny := false

	for pager.More() {
		page, err := pager.NextPage(context.Background())
		if err != nil {
			return []engine.Finding{skip("az_disk_encryption", "Azure VM Disk Encryption", err.Error())}
		}
		for _, disk := range page.Value {
			hasAny = true
			if disk.Properties == nil {
				continue
			}
			// Flag disks that have no encryption type set (unmanaged or explicitly unencrypted)
			encrypted := true
			if disk.Properties.EncryptionSettingsCollection != nil &&
				disk.Properties.EncryptionSettingsCollection.Enabled != nil &&
				!*disk.Properties.EncryptionSettingsCollection.Enabled {
				encrypted = false
			}
			if !encrypted {
				unencrypted = append(unencrypted, ptrStr(disk.Name))
			}
		}
	}

	if !hasAny {
		return []engine.Finding{pass("az_disk_encryption", "No Azure managed disks found",
			soc2("CC6.7"), hipaa("164.312(a)(2)(iv)"), cis("7.2"))}
	}
	if len(unencrypted) == 0 {
		return []engine.Finding{pass("az_disk_encryption", "All Azure managed disks have encryption enabled",
			soc2("CC6.7"), hipaa("164.312(a)(2)(iv)"), cis("7.2"))}
	}
	return []engine.Finding{fail(
		"az_disk_encryption",
		fmt.Sprintf("%d disk(s) with encryption disabled: %v", len(unencrypted), truncate(unencrypted, 5)),
		engine.SeverityHigh,
		"Enable Azure Disk Encryption:\n  az vm encryption enable --resource-group RG --name VM_NAME --disk-encryption-keyvault KEY_VAULT_ID",
		soc2("CC6.7"), hipaa("164.312(a)(2)(iv)"), cis("7.2"),
	)}
}

// ── Defender for Cloud ────────────────────────────────────────────────────────

func (c *Checker) checkDefenderForCloud() []engine.Finding {
	client, err := armsecurity.NewPricingsClient(c.cred, nil)
	if err != nil {
		return []engine.Finding{skip("az_defender", "Microsoft Defender for Cloud", err.Error())}
	}
	scope := "subscriptions/" + c.subscriptionID
	resp, err := client.List(context.Background(), scope, nil)
	if err != nil {
		return []engine.Finding{skip("az_defender", "Microsoft Defender for Cloud", err.Error())}
	}

	key := []string{"VirtualMachines", "SqlServers", "AppServices", "StorageAccounts", "Containers"}
	pricingMap := map[string]string{}
	for _, p := range resp.Value {
		if p.Name != nil && p.Properties != nil && p.Properties.PricingTier != nil {
			pricingMap[*p.Name] = string(*p.Properties.PricingTier)
		}
	}
	var free []string
	for _, svc := range key {
		if tier, ok := pricingMap[svc]; !ok || tier == string(armsecurity.PricingTierFree) {
			free = append(free, svc)
		}
	}

	if len(free) == 0 {
		return []engine.Finding{pass("az_defender", "Microsoft Defender for Cloud enabled for key services",
			soc2("CC6.8"), hipaa("164.308(a)(1)(ii)(D)"), cis("2.1"))}
	}
	return []engine.Finding{fail(
		"az_defender",
		fmt.Sprintf("Defender for Cloud not enabled (Standard tier) for: %v", free),
		engine.SeverityHigh,
		"Enable Defender for Cloud:\n  az security pricing create --name VirtualMachines --tier Standard\n  Repeat for: SqlServers, AppServices, StorageAccounts, Containers",
		soc2("CC6.8"), hipaa("164.308(a)(1)(ii)(D)"), cis("2.1"),
	)}
}

// ── Activity Logs ─────────────────────────────────────────────────────────────

func (c *Checker) checkActivityLogs() []engine.Finding {
	client, err := armmonitor.NewDiagnosticSettingsClient(c.cred, nil)
	if err != nil {
		return []engine.Finding{skip("az_activity_logs", "Azure Activity Logs", err.Error())}
	}
	resourceURI := "/subscriptions/" + c.subscriptionID
	pager := client.NewListPager(resourceURI, nil)
	hasSettings := false

	for pager.More() {
		page, err := pager.NextPage(context.Background())
		if err != nil {
			return []engine.Finding{skip("az_activity_logs", "Azure Activity Logs", err.Error())}
		}
		if len(page.Value) > 0 {
			hasSettings = true
		}
	}

	if hasSettings {
		return []engine.Finding{pass("az_activity_logs", "Activity log diagnostic settings are configured",
			soc2("CC7.2"), hipaa("164.312(b)"), cis("5.1.1"))}
	}
	return []engine.Finding{fail(
		"az_activity_logs", "No activity log diagnostic settings configured for the subscription",
		engine.SeverityHigh,
		"Configure activity log export:\n  az monitor diagnostic-settings create --name ActivityLogs \\\n    --resource /subscriptions/SUB_ID \\\n    --storage-account STORAGE_ID \\\n    --logs '[{\"category\":\"Administrative\",\"enabled\":true},{\"category\":\"Security\",\"enabled\":true}]'",
		soc2("CC7.2"), hipaa("164.312(b)"), cis("5.1.1"),
	)}
}

// ── SQL Security ──────────────────────────────────────────────────────────────

func (c *Checker) checkSQLSecurity() []engine.Finding {
	serverClient, err := armsql.NewServersClient(c.subscriptionID, c.cred, nil)
	if err != nil {
		return []engine.Finding{skip("az_sql", "Azure SQL Security", err.Error())}
	}
	pager := serverClient.NewListPager(nil)
	var noAudit, noTDE []string
	hasAny := false

	auditClient, _ := armsql.NewServerBlobAuditingPoliciesClient(c.subscriptionID, c.cred, nil)
	tdeClient, _ := armsql.NewTransparentDataEncryptionsClient(c.subscriptionID, c.cred, nil)
	dbClient, _ := armsql.NewDatabasesClient(c.subscriptionID, c.cred, nil)

	for pager.More() {
		page, err := pager.NextPage(context.Background())
		if err != nil {
			return []engine.Finding{skip("az_sql", "Azure SQL Security", err.Error())}
		}
		for _, server := range page.Value {
			hasAny = true
			serverName := ptrStr(server.Name)
			rg := resourceGroupFromID(ptrStr(server.ID))

			// auditing
			if auditClient != nil {
				auditResp, err := auditClient.Get(context.Background(), rg, serverName, nil)
				if err != nil || auditResp.Properties == nil ||
					auditResp.Properties.State == nil ||
					*auditResp.Properties.State != armsql.BlobAuditingPolicyStateEnabled {
					noAudit = append(noAudit, serverName)
				}
			}

			// TDE per database
			if tdeClient != nil && dbClient != nil {
				dbPager := dbClient.NewListByServerPager(rg, serverName, nil)
				for dbPager.More() {
					dbPage, err := dbPager.NextPage(context.Background())
					if err != nil {
						break
					}
					for _, db := range dbPage.Value {
						dbName := ptrStr(db.Name)
						if dbName == "master" {
							continue
						}
						tdeResp, err := tdeClient.Get(context.Background(), rg, serverName, dbName, "current", nil)
						if err != nil || tdeResp.Properties == nil ||
							tdeResp.Properties.State == nil ||
							*tdeResp.Properties.State != armsql.TransparentDataEncryptionStateEnabled {
							noTDE = append(noTDE, fmt.Sprintf("%s/%s", serverName, dbName))
						}
					}
				}
			}
		}
	}

	if !hasAny {
		return []engine.Finding{pass("az_sql_tde", "No Azure SQL servers found",
			soc2("CC6.7"), hipaa("164.312(a)(2)(iv)"), cis("4.1.2"))}
	}

	var findings []engine.Finding
	if len(noAudit) == 0 {
		findings = append(findings, pass("az_sql_auditing", "All SQL servers have auditing enabled",
			soc2("CC7.2"), hipaa("164.312(b)"), cis("4.1.1")))
	} else {
		findings = append(findings, fail(
			"az_sql_auditing",
			fmt.Sprintf("%d SQL server(s) without auditing: %v", len(noAudit), truncate(noAudit, 5)),
			engine.SeverityHigh,
			"Enable SQL auditing:\n  az sql server audit-policy update --resource-group RG --name SERVER --state Enabled --storage-account STORAGE",
			soc2("CC7.2"), hipaa("164.312(b)"), cis("4.1.1"),
		))
	}
	if len(noTDE) == 0 {
		findings = append(findings, pass("az_sql_tde", "All SQL databases have Transparent Data Encryption enabled",
			soc2("CC6.7"), hipaa("164.312(a)(2)(iv)"), cis("4.1.2")))
	} else {
		findings = append(findings, fail(
			"az_sql_tde",
			fmt.Sprintf("%d SQL database(s) without TDE: %v", len(noTDE), truncate(noTDE, 5)),
			engine.SeverityHigh,
			"Enable TDE:\n  az sql db tde set --resource-group RG --server SERVER --database DB --status Enabled",
			soc2("CC6.7"), hipaa("164.312(a)(2)(iv)"), cis("4.1.2"),
		))
	}
	return findings
}

// ── helpers ───────────────────────────────────────────────────────────────────

func nsgPortMatches(p *armnetwork.SecurityRulePropertiesFormat, port int) bool {
	ranges := []string{}
	if p.DestinationPortRange != nil {
		ranges = append(ranges, *p.DestinationPortRange)
	}
	for _, r := range p.DestinationPortRanges {
		if r != nil {
			ranges = append(ranges, *r)
		}
	}
	for _, r := range ranges {
		if r == "*" {
			return true
		}
		parts := strings.SplitN(r, "-", 2)
		if len(parts) == 1 {
			p, _ := strconv.Atoi(parts[0])
			if p == port {
				return true
			}
		} else {
			lo, _ := strconv.Atoi(parts[0])
			hi, _ := strconv.Atoi(parts[1])
			if port >= lo && port <= hi {
				return true
			}
		}
	}
	return false
}

func resourceGroupFromID(id string) string {
	// /subscriptions/{sub}/resourceGroups/{rg}/providers/...
	parts := strings.Split(id, "/")
	for i, p := range parts {
		if strings.EqualFold(p, "resourceGroups") && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

func ptrStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func truncate(items []string, max int) string {
	if len(items) <= max {
		return strings.Join(items, ", ")
	}
	return strings.Join(items[:max], ", ") + fmt.Sprintf(" +%d more", len(items)-max)
}

func pass(id, title string, controls ...engine.ControlRef) engine.Finding {
	return engine.Finding{CheckID: id, Title: title, Status: engine.StatusPass, Integration: "Azure", Controls: controls}
}
func fail(id, title string, severity engine.Severity, remediation string, controls ...engine.ControlRef) engine.Finding {
	return engine.Finding{CheckID: id, Title: title, Status: engine.StatusFail, Severity: severity, Integration: "Azure", Remediation: remediation, Controls: controls}
}
func skip(id, title, detail string) engine.Finding {
	return engine.Finding{CheckID: id, Title: title, Status: engine.StatusSkip, Integration: "Azure", Detail: detail}
}
func soc2(id string) engine.ControlRef  { return engine.ControlRef{Framework: engine.FrameworkSOC2, ID: id} }
func hipaa(id string) engine.ControlRef { return engine.ControlRef{Framework: engine.FrameworkHIPAA, ID: id} }
func cis(id string) engine.ControlRef   { return engine.ControlRef{Framework: engine.FrameworkCIS, ID: id} }
