package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork"
	"github.com/complykit/complykit/internal/engine"
)

// graphGet makes a GET request to Microsoft Graph API using DefaultAzureCredential.
func graphGet(ctx context.Context, cred *azidentity.DefaultAzureCredential, path string, v interface{}) error {
	token, err := cred.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{"https://graph.microsoft.com/.default"},
	})
	if err != nil {
		return fmt.Errorf("graph token: %w", err)
	}
	url := "https://graph.microsoft.com/v1.0" + path
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+token.Token)
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return fmt.Errorf("graph %s → %d: %s", path, resp.StatusCode, string(body))
	}
	return json.Unmarshal(body, v)
}

// ── Conditional Access MFA ────────────────────────────────────────────────────

func (c *Checker) checkConditionalAccessMFA() []engine.Finding {
	var result struct {
		Value []struct {
			ID          string `json:"id"`
			DisplayName string `json:"displayName"`
			State       string `json:"state"`
			GrantControls *struct {
				Operator        string   `json:"operator"`
				BuiltInControls []string `json:"builtInControls"`
			} `json:"grantControls"`
		} `json:"value"`
	}

	err := graphGet(context.Background(), c.cred, "/identity/conditionalAccess/policies", &result)
	if err != nil {
		return []engine.Finding{skip("az_mfa_conditional_access", "Azure AD Conditional Access MFA", err.Error())}
	}

	for _, policy := range result.Value {
		if policy.State != "enabled" {
			continue
		}
		if policy.GrantControls != nil {
			for _, ctrl := range policy.GrantControls.BuiltInControls {
				if ctrl == "mfa" {
					return []engine.Finding{pass("az_mfa_conditional_access",
						fmt.Sprintf("Conditional Access policy requiring MFA found: %q", policy.DisplayName),
						soc2("CC6.1"), hipaa("164.312(d)"), cis("1.2.1"))}
				}
			}
		}
	}

	return []engine.Finding{fail(
		"az_mfa_conditional_access", "No enabled Conditional Access policy requiring MFA found",
		engine.SeverityCritical,
		"Create a Conditional Access policy that requires MFA for all users:\n  Azure Portal → Azure AD → Security → Conditional Access → New policy",
		soc2("CC6.1"), hipaa("164.312(d)"), cis("1.2.1"),
	)}
}

// ── No guest users with admin roles ──────────────────────────────────────────

func (c *Checker) checkNoGuestAdmins() []engine.Finding {
	// Get privileged directory role names
	var rolesResult struct {
		Value []struct {
			ID          string `json:"id"`
			DisplayName string `json:"displayName"`
		} `json:"value"`
	}
	if err := graphGet(context.Background(), c.cred, "/directoryRoles", &rolesResult); err != nil {
		return []engine.Finding{skip("az_no_guest_admin", "Azure AD No Guest Admins", err.Error())}
	}

	privileged := []string{"Global Administrator", "Privileged Role Administrator",
		"User Administrator", "Security Administrator", "Exchange Administrator"}

	var guestAdmins []string
	for _, role := range rolesResult.Value {
		isPriv := false
		for _, p := range privileged {
			if role.DisplayName == p {
				isPriv = true
				break
			}
		}
		if !isPriv {
			continue
		}

		var membersResult struct {
			Value []struct {
				UserPrincipalName string `json:"userPrincipalName"`
				UserType          string `json:"userType"`
			} `json:"value"`
		}
		if err := graphGet(context.Background(), c.cred, "/directoryRoles/"+role.ID+"/members", &membersResult); err != nil {
			continue
		}
		for _, m := range membersResult.Value {
			if m.UserType == "Guest" {
				guestAdmins = append(guestAdmins, fmt.Sprintf("%s (%s)", m.UserPrincipalName, role.DisplayName))
			}
		}
	}

	if len(guestAdmins) == 0 {
		return []engine.Finding{pass("az_no_guest_admin", "No guest users hold privileged administrative roles",
			soc2("CC6.3"), hipaa("164.308(a)(3)"), cis("1.3"))}
	}
	return []engine.Finding{fail(
		"az_no_guest_admin",
		fmt.Sprintf("%d guest user(s) with admin roles: %v", len(guestAdmins), truncate(guestAdmins, 5)),
		engine.SeverityCritical,
		"Remove guest users from privileged roles:\n  Azure Portal → Azure AD → Roles and administrators → Select role → Remove assignment",
		soc2("CC6.3"), hipaa("164.308(a)(3)"), cis("1.3"),
	)}
}

// ── Privileged Identity Management ───────────────────────────────────────────

func (c *Checker) checkPIM() []engine.Finding {
	var result struct {
		Value []struct {
			ID string `json:"id"`
		} `json:"value"`
	}
	err := graphGet(context.Background(), c.cred,
		"/roleManagement/directory/roleEligibilitySchedules?$top=1", &result)
	if err != nil {
		// PIM not available or no license
		if strings.Contains(err.Error(), "403") || strings.Contains(err.Error(), "401") {
			return []engine.Finding{skip("az_pim_enabled", "Azure AD PIM", "Insufficient permissions or PIM not licensed (requires Azure AD P2)")}
		}
		return []engine.Finding{skip("az_pim_enabled", "Azure AD PIM", err.Error())}
	}
	if len(result.Value) > 0 {
		return []engine.Finding{pass("az_pim_enabled", "Azure AD Privileged Identity Management (PIM) is in use",
			soc2("CC6.3"), hipaa("164.308(a)(3)"), cis("1.14"))}
	}
	return []engine.Finding{fail(
		"az_pim_enabled", "No PIM eligible role assignments found — PIM may not be configured",
		engine.SeverityHigh,
		"Enable and configure Azure AD PIM for just-in-time privileged access:\n  Azure Portal → Azure AD → Privileged Identity Management → Azure AD roles → Settings",
		soc2("CC6.3"), hipaa("164.308(a)(3)"), cis("1.14"),
	)}
}

// ── AKS Secrets Store CSI Driver ─────────────────────────────────────────────

func (c *Checker) checkAKSCSISecrets() []engine.Finding {
	client, err := armcontainerservice.NewManagedClustersClient(c.subscriptionID, c.cred, nil)
	if err != nil {
		return []engine.Finding{skip("az_aks_csi_secrets", "AKS Secrets Store CSI Driver", err.Error())}
	}
	pager := client.NewListPager(nil)
	var noCSI []string
	hasAny := false

	for pager.More() {
		page, err := pager.NextPage(context.Background())
		if err != nil {
			return []engine.Finding{skip("az_aks_csi_secrets", "AKS Secrets Store CSI Driver", err.Error())}
		}
		for _, cl := range page.Value {
			hasAny = true
			name := ptrStr(cl.Name)
			hasCSI := false
			if cl.Properties != nil && cl.Properties.AddonProfiles != nil {
				if addon, ok := cl.Properties.AddonProfiles["azureKeyvaultSecretsProvider"]; ok {
					if addon.Enabled != nil && *addon.Enabled {
						hasCSI = true
					}
				}
			}
			if !hasCSI {
				noCSI = append(noCSI, name)
			}
		}
	}
	if !hasAny {
		return nil
	}
	if len(noCSI) == 0 {
		return []engine.Finding{pass("az_aks_csi_secrets", "All AKS clusters use Secrets Store CSI Driver for Key Vault integration",
			soc2("CC6.7"), hipaa("164.312(a)(2)(iv)"), cis("5.1.2"))}
	}
	return []engine.Finding{fail(
		"az_aks_csi_secrets",
		fmt.Sprintf("%d AKS cluster(s) without Secrets Store CSI Driver: %v", len(noCSI), truncate(noCSI, 5)),
		engine.SeverityMedium,
		"Enable Key Vault Secrets Provider addon:\n  az aks enable-addons --addons azure-keyvault-secrets-provider --name CLUSTER --resource-group RG",
		soc2("CC6.7"), hipaa("164.312(a)(2)(iv)"), cis("5.1.2"),
	)}
}

// ── Network Watcher all active regions ───────────────────────────────────────

func (c *Checker) checkNetworkWatcherAllRegions() []engine.Finding {
	// Get regions where VMs exist
	vmRegions := map[string]bool{}
	vmClient, err := armnetwork.NewVirtualNetworksClient(c.subscriptionID, c.cred, nil)
	if err == nil {
		pager := vmClient.NewListAllPager(nil)
		for pager.More() {
			page, _ := pager.NextPage(context.Background())
			if page.Value != nil {
				for _, vnet := range page.Value {
					if vnet.Location != nil {
						vmRegions[*vnet.Location] = true
					}
				}
			}
		}
	}

	if len(vmRegions) == 0 {
		return []engine.Finding{pass("az_network_watcher_all_regions", "No VNets found — Network Watcher not required",
			soc2("CC7.2"), hipaa("164.312(b)"), cis("6.5"))}
	}

	// Get regions where Network Watcher exists
	nwClient, err := armnetwork.NewWatchersClient(c.subscriptionID, c.cred, nil)
	if err != nil {
		return []engine.Finding{skip("az_network_watcher_all_regions", "Network Watcher All Regions", err.Error())}
	}
	nwRegions := map[string]bool{}
	pager := nwClient.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(context.Background())
		if err != nil {
			break
		}
		for _, nw := range page.Value {
			if nw.Location != nil {
				nwRegions[*nw.Location] = true
			}
		}
	}

	var missing []string
	for region := range vmRegions {
		if !nwRegions[region] {
			missing = append(missing, region)
		}
	}

	if len(missing) == 0 {
		return []engine.Finding{pass("az_network_watcher_all_regions", "Network Watcher enabled in all regions with VNets",
			soc2("CC7.2"), hipaa("164.312(b)"), cis("6.5"))}
	}
	return []engine.Finding{fail(
		"az_network_watcher_all_regions",
		fmt.Sprintf("Network Watcher missing in %d region(s) with VNets: %v", len(missing), truncate(missing, 5)),
		engine.SeverityMedium,
		"Enable Network Watcher in each region:\n  az network watcher configure --resource-group NetworkWatcherRG --locations REGION --enabled true",
		soc2("CC7.2"), hipaa("164.312(b)"), cis("6.5"),
	)}
}
