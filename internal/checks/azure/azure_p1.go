package azure

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/sql/armsql"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/complykit/complykit/internal/engine"
)

// ── Storage infrastructure encryption ────────────────────────────────────────

func (c *Checker) checkStorageInfraEncryption() []engine.Finding {
	client, err := armstorage.NewAccountsClient(c.subscriptionID, c.cred, nil)
	if err != nil {
		return []engine.Finding{skip("az_storage_infra_encryption", "Azure Storage Infrastructure Encryption", err.Error())}
	}
	pager := client.NewListPager(nil)
	var noInfra []string
	hasAny := false

	for pager.More() {
		page, err := pager.NextPage(context.Background())
		if err != nil {
			return []engine.Finding{skip("az_storage_infra_encryption", "Azure Storage Infrastructure Encryption", err.Error())}
		}
		for _, acct := range page.Value {
			hasAny = true
			if acct.Properties == nil ||
				acct.Properties.Encryption == nil ||
				acct.Properties.Encryption.RequireInfrastructureEncryption == nil ||
				!*acct.Properties.Encryption.RequireInfrastructureEncryption {
				noInfra = append(noInfra, ptrStr(acct.Name))
			}
		}
	}

	if !hasAny {
		return nil
	}
	if len(noInfra) == 0 {
		return []engine.Finding{pass("az_storage_infra_encryption", "All storage accounts have infrastructure encryption enabled",
			soc2("CC6.7"), hipaa("164.312(a)(2)(iv)"), cis("3.2"))}
	}
	return []engine.Finding{fail(
		"az_storage_infra_encryption",
		fmt.Sprintf("%d storage account(s) without infrastructure encryption: %v", len(noInfra), truncate(noInfra, 5)),
		engine.SeverityMedium,
		"Infrastructure encryption must be set at account creation. Create a new account with it enabled:\n  az storage account create --name ACCOUNT --resource-group RG --require-infrastructure-encryption",
		soc2("CC6.7"), hipaa("164.312(a)(2)(iv)"), cis("3.2"),
	)}
}

// ── SQL Vulnerability Assessment ─────────────────────────────────────────────

func (c *Checker) checkSQLVulnAssessment() []engine.Finding {
	serverClient, err := armsql.NewServersClient(c.subscriptionID, c.cred, nil)
	if err != nil {
		return []engine.Finding{skip("az_sql_vuln_assessment", "Azure SQL Vulnerability Assessment", err.Error())}
	}
	vaClient, _ := armsql.NewServerVulnerabilityAssessmentsClient(c.subscriptionID, c.cred, nil)
	pager := serverClient.NewListPager(nil)
	var noVA []string

	for pager.More() {
		page, err := pager.NextPage(context.Background())
		if err != nil {
			break
		}
		for _, server := range page.Value {
			name := ptrStr(server.Name)
			rg := resourceGroupFromID(ptrStr(server.ID))
			if vaClient == nil {
				noVA = append(noVA, name)
				continue
			}
			va, err := vaClient.Get(context.Background(), rg, name, armsql.VulnerabilityAssessmentNameDefault, nil)
			if err != nil || va.Properties == nil || va.Properties.StorageContainerPath == nil || *va.Properties.StorageContainerPath == "" {
				noVA = append(noVA, name)
			}
		}
	}

	if len(noVA) == 0 {
		return []engine.Finding{pass("az_sql_vuln_assessment", "All SQL servers have Vulnerability Assessment configured",
			soc2("CC7.1"), hipaa("164.308(a)(5)"), cis("4.2.2"))}
	}
	return []engine.Finding{fail(
		"az_sql_vuln_assessment",
		fmt.Sprintf("%d SQL server(s) without Vulnerability Assessment: %v", len(noVA), truncate(noVA, 5)),
		engine.SeverityMedium,
		"Enable Vulnerability Assessment:\n  az sql server va-setting set --resource-group RG --server SERVER --storage-account STORAGE --recurringscans-interval Weekly",
		soc2("CC7.1"), hipaa("164.308(a)(5)"), cis("4.2.2"),
	)}
}

// ── AKS node OS auto-upgrade ──────────────────────────────────────────────────

func (c *Checker) checkAKSNodeAutoUpgrade() []engine.Finding {
	client, err := armcontainerservice.NewManagedClustersClient(c.subscriptionID, c.cred, nil)
	if err != nil {
		return []engine.Finding{skip("az_aks_node_auto_upgrade", "AKS Node Auto-Upgrade", err.Error())}
	}
	pager := client.NewListPager(nil)
	var noUpgrade []string
	hasAny := false

	for pager.More() {
		page, err := pager.NextPage(context.Background())
		if err != nil {
			return []engine.Finding{skip("az_aks_node_auto_upgrade", "AKS Node Auto-Upgrade", err.Error())}
		}
		for _, cl := range page.Value {
			hasAny = true
			name := ptrStr(cl.Name)
			if cl.Properties == nil ||
				cl.Properties.AutoUpgradeProfile == nil ||
				cl.Properties.AutoUpgradeProfile.UpgradeChannel == nil ||
				*cl.Properties.AutoUpgradeProfile.UpgradeChannel == armcontainerservice.UpgradeChannelNone {
				noUpgrade = append(noUpgrade, name)
			}
		}
	}

	if !hasAny {
		return nil
	}
	if len(noUpgrade) == 0 {
		return []engine.Finding{pass("az_aks_node_auto_upgrade", "All AKS clusters have node OS auto-upgrade configured",
			soc2("CC7.1"), hipaa("164.308(a)(5)"), cis("5.4.2"))}
	}
	return []engine.Finding{fail(
		"az_aks_node_auto_upgrade",
		fmt.Sprintf("%d AKS cluster(s) without node OS auto-upgrade: %v", len(noUpgrade), truncate(noUpgrade, 5)),
		engine.SeverityMedium,
		"Enable node OS auto-upgrade:\n  az aks update --name CLUSTER --resource-group RG --node-os-upgrade-channel NodeImage",
		soc2("CC7.1"), hipaa("164.308(a)(5)"), cis("5.4.2"),
	)}
}
