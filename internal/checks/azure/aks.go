package azure

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice"
	"github.com/complykit/complykit/internal/engine"
)

func (c *Checker) checkAKSClusters() []engine.Finding {
	client, err := armcontainerservice.NewManagedClustersClient(c.subscriptionID, c.cred, nil)
	if err != nil {
		return []engine.Finding{skip("az_aks", "Azure AKS Clusters", err.Error())}
	}

	pager := client.NewListPager(nil)
	var findings []engine.Finding
	hasAny := false

	for pager.More() {
		page, err := pager.NextPage(context.Background())
		if err != nil {
			return []engine.Finding{skip("az_aks", "Azure AKS Clusters", err.Error())}
		}
		for _, cl := range page.Value {
			hasAny = true
			findings = append(findings, aksCheckRBAC(cl)...)
			findings = append(findings, aksCheckAAD(cl)...)
			findings = append(findings, aksCheckNetworkPolicy(cl)...)
			findings = append(findings, aksCheckPrivateCluster(cl)...)
		}
	}

	if !hasAny {
		return []engine.Finding{pass("az_aks_no_clusters", "No AKS clusters found",
			soc2("CC6.6"), hipaa("164.312(e)(2)(i)"), cis("5.1.1"))}
	}
	return findings
}

func aksCheckRBAC(cl *armcontainerservice.ManagedCluster) []engine.Finding {
	name := ptrStr(cl.Name)
	if cl.Properties == nil || cl.Properties.EnableRBAC == nil || !*cl.Properties.EnableRBAC {
		return []engine.Finding{fail(
			"az_aks_rbac",
			fmt.Sprintf("AKS cluster %q does not have RBAC enabled", name),
			engine.SeverityCritical,
			"RBAC cannot be enabled after cluster creation. Recreate cluster with RBAC:\n  az aks create --name "+name+" --enable-rbac",
			soc2("CC6.1"), hipaa("164.308(a)(3)(i)"), cis("5.1.1"),
		)}
	}
	return []engine.Finding{pass("az_aks_rbac",
		fmt.Sprintf("AKS cluster %q has RBAC enabled", name),
		soc2("CC6.1"), hipaa("164.308(a)(3)(i)"), cis("5.1.1"))}
}

func aksCheckAAD(cl *armcontainerservice.ManagedCluster) []engine.Finding {
	name := ptrStr(cl.Name)
	if cl.Properties == nil || cl.Properties.AADProfile == nil {
		return []engine.Finding{fail(
			"az_aks_aad",
			fmt.Sprintf("AKS cluster %q does not have Azure AD integration", name),
			engine.SeverityHigh,
			"Enable Azure AD integration:\n  az aks update --name "+name+" --resource-group RG --enable-aad",
			soc2("CC6.1"), hipaa("164.308(a)(3)(i)"), cis("5.2.1"),
		)}
	}
	return []engine.Finding{pass("az_aks_aad",
		fmt.Sprintf("AKS cluster %q has Azure AD integration", name),
		soc2("CC6.1"), hipaa("164.308(a)(3)(i)"), cis("5.2.1"))}
}

func aksCheckNetworkPolicy(cl *armcontainerservice.ManagedCluster) []engine.Finding {
	name := ptrStr(cl.Name)
	hasPolicy := cl.Properties != nil &&
		cl.Properties.NetworkProfile != nil &&
		cl.Properties.NetworkProfile.NetworkPolicy != nil &&
		(*cl.Properties.NetworkProfile.NetworkPolicy == armcontainerservice.NetworkPolicyAzure ||
			*cl.Properties.NetworkProfile.NetworkPolicy == armcontainerservice.NetworkPolicyCalico)
	if !hasPolicy {
		return []engine.Finding{fail(
			"az_aks_network_policy",
			fmt.Sprintf("AKS cluster %q has no network policy configured", name),
			engine.SeverityMedium,
			"Enable network policy at cluster creation:\n  az aks create --name "+name+" --network-policy azure",
			soc2("CC6.6"), hipaa("164.312(e)(2)(i)"), cis("5.3.2"),
		)}
	}
	return []engine.Finding{pass("az_aks_network_policy",
		fmt.Sprintf("AKS cluster %q has network policy configured", name),
		soc2("CC6.6"), hipaa("164.312(e)(2)(i)"), cis("5.3.2"))}
}

func aksCheckPrivateCluster(cl *armcontainerservice.ManagedCluster) []engine.Finding {
	name := ptrStr(cl.Name)
	isPrivate := cl.Properties != nil &&
		cl.Properties.APIServerAccessProfile != nil &&
		cl.Properties.APIServerAccessProfile.EnablePrivateCluster != nil &&
		*cl.Properties.APIServerAccessProfile.EnablePrivateCluster
	if !isPrivate {
		return []engine.Finding{fail(
			"az_aks_private_cluster",
			fmt.Sprintf("AKS cluster %q API server is publicly accessible", name),
			engine.SeverityHigh,
			"Restrict API server access:\n  az aks update --name "+name+" --resource-group RG --api-server-authorized-ip-ranges YOUR_IP/32",
			soc2("CC6.6"), hipaa("164.312(e)(2)(i)"), cis("5.4.1"),
		)}
	}
	return []engine.Finding{pass("az_aks_private_cluster",
		fmt.Sprintf("AKS cluster %q is a private cluster", name),
		soc2("CC6.6"), hipaa("164.312(e)(2)(i)"), cis("5.4.1"))}
}
