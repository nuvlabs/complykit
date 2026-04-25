package gcp

import (
	"context"
	"fmt"
	"strings"

	"google.golang.org/api/container/v1"
	"github.com/complykit/complykit/internal/engine"
)

type GKEChecker struct {
	projectID string
}

func NewGKEChecker(projectID string) *GKEChecker {
	return &GKEChecker{projectID: projectID}
}

func (c *GKEChecker) Integration() string { return "GCP/GKE" }

func (c *GKEChecker) Run() ([]engine.Finding, error) {
	ctx := context.Background()
	svc, err := container.NewService(ctx)
	if err != nil {
		return []engine.Finding{skip("gcp_gke", "GCP GKE Clusters", err.Error())}, nil
	}

	// List clusters across all zones in the project
	resp, err := svc.Projects.Locations.Clusters.List("projects/" + c.projectID + "/locations/-").Do()
	if err != nil {
		return []engine.Finding{skip("gcp_gke", "GCP GKE Clusters", err.Error())}, nil
	}

	if len(resp.Clusters) == 0 {
		return []engine.Finding{pass("gcp_gke_no_clusters", "No GKE clusters found",
			soc2("CC6.6"), hipaa("164.312(e)(2)(i)"), cis("6.1.1"))}, nil
	}

	var findings []engine.Finding
	for _, cl := range resp.Clusters {
		findings = append(findings, checkGKEPrivateCluster(cl)...)
		findings = append(findings, checkGKEWorkloadIdentity(cl)...)
		findings = append(findings, checkGKENetworkPolicy(cl)...)
		findings = append(findings, checkGKEMasterAuthNetworks(cl)...)
		findings = append(findings, checkGKEShieldedNodes(cl)...)
		findings = append(findings, checkGKELegacyMeta(cl)...)
	}
	return findings, nil
}

func checkGKEPrivateCluster(cl *container.Cluster) []engine.Finding {
	label := cl.Name
	if cl.PrivateClusterConfig == nil || !cl.PrivateClusterConfig.EnablePrivateNodes {
		return []engine.Finding{fail(
			"gcp_gke_private_cluster",
			fmt.Sprintf("GKE cluster %q does not use private nodes", label),
			engine.SeverityHigh,
			"Enable private nodes:\n  gcloud container clusters update "+label+" --enable-private-nodes",
			soc2("CC6.6"), hipaa("164.312(e)(2)(i)"), cis("6.6.1"),
		)}
	}
	return []engine.Finding{pass("gcp_gke_private_cluster",
		fmt.Sprintf("GKE cluster %q uses private nodes", label),
		soc2("CC6.6"), hipaa("164.312(e)(2)(i)"), cis("6.6.1"))}
}

func checkGKEWorkloadIdentity(cl *container.Cluster) []engine.Finding {
	label := cl.Name
	if cl.WorkloadIdentityConfig == nil || cl.WorkloadIdentityConfig.WorkloadPool == "" {
		return []engine.Finding{fail(
			"gcp_gke_workload_identity",
			fmt.Sprintf("GKE cluster %q does not have Workload Identity enabled", label),
			engine.SeverityHigh,
			"Enable Workload Identity:\n  gcloud container clusters update "+label+" --workload-pool=PROJECT_ID.svc.id.goog",
			soc2("CC6.1"), hipaa("164.308(a)(3)(ii)(A)"), cis("6.2.1"),
		)}
	}
	return []engine.Finding{pass("gcp_gke_workload_identity",
		fmt.Sprintf("GKE cluster %q has Workload Identity enabled", label),
		soc2("CC6.1"), hipaa("164.308(a)(3)(ii)(A)"), cis("6.2.1"))}
}

func checkGKENetworkPolicy(cl *container.Cluster) []engine.Finding {
	label := cl.Name
	enabled := cl.NetworkPolicy != nil && cl.NetworkPolicy.Enabled
	if !enabled {
		return []engine.Finding{fail(
			"gcp_gke_network_policy",
			fmt.Sprintf("GKE cluster %q does not have network policy enabled", label),
			engine.SeverityMedium,
			"Enable network policy:\n  gcloud container clusters update "+label+" --enable-network-policy",
			soc2("CC6.6"), hipaa("164.312(e)(2)(i)"), cis("6.6.7"),
		)}
	}
	return []engine.Finding{pass("gcp_gke_network_policy",
		fmt.Sprintf("GKE cluster %q has network policy enabled", label),
		soc2("CC6.6"), hipaa("164.312(e)(2)(i)"), cis("6.6.7"))}
}

func checkGKEMasterAuthNetworks(cl *container.Cluster) []engine.Finding {
	label := cl.Name
	if cl.MasterAuthorizedNetworksConfig == nil || !cl.MasterAuthorizedNetworksConfig.Enabled {
		return []engine.Finding{fail(
			"gcp_gke_master_auth_networks",
			fmt.Sprintf("GKE cluster %q does not restrict master API access to authorized networks", label),
			engine.SeverityCritical,
			"Enable master authorized networks:\n  gcloud container clusters update "+label+" --enable-master-authorized-networks --master-authorized-networks=YOUR_IP/32",
			soc2("CC6.6"), hipaa("164.312(e)(2)(i)"), cis("6.6.2"),
		)}
	}
	return []engine.Finding{pass("gcp_gke_master_auth_networks",
		fmt.Sprintf("GKE cluster %q restricts master API to authorized networks", label),
		soc2("CC6.6"), hipaa("164.312(e)(2)(i)"), cis("6.6.2"))}
}

func checkGKEShieldedNodes(cl *container.Cluster) []engine.Finding {
	label := cl.Name
	if cl.ShieldedNodes == nil || !cl.ShieldedNodes.Enabled {
		return []engine.Finding{fail(
			"gcp_gke_shielded_nodes",
			fmt.Sprintf("GKE cluster %q does not have Shielded Nodes enabled", label),
			engine.SeverityMedium,
			"Enable Shielded Nodes:\n  gcloud container clusters update "+label+" --enable-shielded-nodes",
			soc2("CC6.6"), cis("6.5.3"),
		)}
	}
	return []engine.Finding{pass("gcp_gke_shielded_nodes",
		fmt.Sprintf("GKE cluster %q has Shielded Nodes enabled", label),
		soc2("CC6.6"), cis("6.5.3"))}
}

func checkGKELegacyMeta(cl *container.Cluster) []engine.Finding {
	label := cl.Name
	// Check if legacy metadata endpoint is disabled on node pools
	var legacyPools []string
	for _, np := range cl.NodePools {
		if np.Config != nil && np.Config.Metadata != nil {
			if v, ok := np.Config.Metadata["disable-legacy-endpoints"]; !ok || !strings.EqualFold(v, "true") {
				legacyPools = append(legacyPools, np.Name)
			}
		}
	}
	if len(legacyPools) == 0 {
		return []engine.Finding{pass("gcp_gke_legacy_metadata",
			fmt.Sprintf("GKE cluster %q has legacy metadata endpoints disabled on all node pools", label),
			soc2("CC6.6"), cis("6.4.1"))}
	}
	return []engine.Finding{fail(
		"gcp_gke_legacy_metadata",
		fmt.Sprintf("GKE cluster %q has legacy metadata endpoints enabled on node pools: %v", label, legacyPools),
		engine.SeverityMedium,
		"Disable legacy metadata endpoint on node pools (set metadata disable-legacy-endpoints=true in node config)",
		soc2("CC6.6"), cis("6.4.1"),
	)}
}
