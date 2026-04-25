package azure

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault"
	"github.com/complykit/complykit/internal/engine"
)

type KeyVaultChecker struct {
	subscriptionID string
	cred           interface {
		GetToken(context.Context, interface{}) (interface{}, error)
	}
}

func (c *Checker) checkKeyVault() []engine.Finding {
	client, err := armkeyvault.NewVaultsClient(c.subscriptionID, c.cred, nil)
	if err != nil {
		return []engine.Finding{skip("az_keyvault", "Azure Key Vault", err.Error())}
	}

	pager := client.NewListBySubscriptionPager(nil)
	var noSoftDelete, noPurgeProtect, expiringKeys []string
	hasAny := false

	keysClient, _ := armkeyvault.NewKeysClient(c.subscriptionID, c.cred, nil)
	now := time.Now()

	for pager.More() {
		page, err := pager.NextPage(context.Background())
		if err != nil {
			return []engine.Finding{skip("az_keyvault", "Azure Key Vault", err.Error())}
		}
		for _, vault := range page.Value {
			hasAny = true
			name := ptrStr(vault.Name)
			rg := resourceGroupFromID(ptrStr(vault.ID))

			// soft delete + purge protection
			if vault.Properties != nil {
				if vault.Properties.EnableSoftDelete == nil || !*vault.Properties.EnableSoftDelete {
					noSoftDelete = append(noSoftDelete, name)
				}
				if vault.Properties.EnablePurgeProtection == nil || !*vault.Properties.EnablePurgeProtection {
					noPurgeProtect = append(noPurgeProtect, name)
				}
			}

			// key expiry
			if keysClient != nil {
				keyPager := keysClient.NewListPager(rg, name, nil)
				for keyPager.More() {
					keyPage, err := keyPager.NextPage(context.Background())
					if err != nil {
						break
					}
					for _, key := range keyPage.Value {
						// get key details
						kv, err := keysClient.Get(context.Background(), rg, name, ptrStr(key.Name), nil)
						if err != nil {
							continue
						}
						if kv.Properties == nil || kv.Properties.Attributes == nil ||
							kv.Properties.Attributes.Expires == nil {
							expiringKeys = append(expiringKeys, fmt.Sprintf("%s/%s (no expiry)", name, ptrStr(key.Name)))
						} else {
							expiryUnix := *kv.Properties.Attributes.Expires
							expiryTime := time.Unix(expiryUnix, 0)
							if expiryTime.Before(now.Add(30 * 24 * time.Hour)) {
								expiringKeys = append(expiringKeys, fmt.Sprintf("%s/%s (expires %s)", name, ptrStr(key.Name), expiryTime.Format("2006-01-02")))
							}
						}
					}
				}
			}
		}
	}

	if !hasAny {
		return []engine.Finding{pass("az_keyvault_soft_delete", "No Key Vaults found",
			soc2("CC6.7"), hipaa("164.312(a)(2)(iv)"), cis("8.4"))}
	}

	var findings []engine.Finding

	if len(noSoftDelete) == 0 {
		findings = append(findings, pass("az_keyvault_soft_delete", "All Key Vaults have soft delete enabled",
			soc2("CC6.7"), hipaa("164.312(a)(2)(iv)"), cis("8.4")))
	} else {
		findings = append(findings, fail(
			"az_keyvault_soft_delete",
			fmt.Sprintf("%d Key Vault(s) without soft delete: %v", len(noSoftDelete), truncate(noSoftDelete, 5)),
			engine.SeverityHigh,
			"Enable soft delete (cannot be disabled once on):\n  az keyvault update --name VAULT --enable-soft-delete true --retention-days 90",
			soc2("CC6.7"), hipaa("164.312(a)(2)(iv)"), cis("8.4"),
		))
	}

	if len(noPurgeProtect) == 0 {
		findings = append(findings, pass("az_keyvault_purge_protection", "All Key Vaults have purge protection enabled",
			soc2("CC6.7"), hipaa("164.312(a)(2)(iv)"), cis("8.4")))
	} else {
		findings = append(findings, fail(
			"az_keyvault_purge_protection",
			fmt.Sprintf("%d Key Vault(s) without purge protection: %v", len(noPurgeProtect), truncate(noPurgeProtect, 5)),
			engine.SeverityHigh,
			"Enable purge protection:\n  az keyvault update --name VAULT --enable-purge-protection true",
			soc2("CC6.7"), hipaa("164.312(a)(2)(iv)"), cis("8.4"),
		))
	}

	if len(expiringKeys) == 0 {
		findings = append(findings, pass("az_keyvault_key_expiry", "All Key Vault keys have expiration dates set",
			soc2("CC6.7"), cis("8.1")))
	} else {
		findings = append(findings, fail(
			"az_keyvault_key_expiry",
			fmt.Sprintf("%d key(s) without expiry or expiring within 30 days: %v", len(expiringKeys), truncate(expiringKeys, 5)),
			engine.SeverityMedium,
			"Set expiration dates on all Key Vault keys:\n  az keyvault key set-attributes --vault-name VAULT --name KEY --expires YYYY-MM-DDThh:mm:ssZ",
			soc2("CC6.7"), cis("8.1"),
		))
	}

	return findings
}
