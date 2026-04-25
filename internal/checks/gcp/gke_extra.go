package gcp

import (
	"context"
	"fmt"

	"google.golang.org/api/container/v1"
	"github.com/complykit/complykit/internal/engine"
)

type GKEExtraChecker struct {
	projectID string
}

func NewGKEExtraChecker(projectID string) *GKEExtraChecker {
	return &GKEExtraChecker{projectID: projectID}
}

func (c *GKEExtraChecker) Integration() string { return "GCP/GKE" }

func (c *GKEExtraChecker) Run() ([]engine.Finding, error) {
	ctx := context.Background()
	svc, err := container.NewService(ctx)
	if err != nil {
		return []engine.Finding{skip("gcp_gke_extra", "GCP GKE Extra Checks", err.Error())}, nil
	}
	resp, err := svc.Projects.Locations.Clusters.List("projects/" + c.projectID + "/locations/-").Do()
	if err != nil {
		return []engine.Finding{skip("gcp_gke_extra", "GCP GKE Extra Checks", err.Error())}, nil
	}
	if len(resp.Clusters) == 0 {
		return nil, nil
	}

	var findings []engine.Finding
	for _, cl := range resp.Clusters {
		findings = append(findings, gkeCheckAutoUpgrade(cl)...)
		findings = append(findings, gkeCheckBinaryAuth(cl)...)
		findings = append(findings, gkeCheckIntranodeVisibility(cl)...)
		findings = append(findings, gkeCheckReleaseChannel(cl)...)
	}
	return findings, nil
}

func gkeCheckAutoUpgrade(cl *container.Cluster) []engine.Finding {
	name := cl.Name
	allEnabled := true
	for _, np := range cl.NodePools {
		if np.Management == nil || !np.Management.AutoUpgrade {
			allEnabled = false
			break
		}
	}
	if allEnabled && len(cl.NodePools) > 0 {
		return []engine.Finding{pass("gcp_gke_auto_upgrade",
			fmt.Sprintf("GKE cluster %q has auto-upgrade enabled on all node pools", name),
			soc2("CC7.1"), hipaa("164.308(a)(5)"), cis("6.5.2"))}
	}
	return []engine.Finding{fail(
		"gcp_gke_auto_upgrade",
		fmt.Sprintf("GKE cluster %q has node pools without auto-upgrade enabled", name),
		engine.SeverityMedium,
		"Enable auto-upgrade on node pools:\n  gcloud container node-pools update NODE_POOL --cluster="+name+" --enable-autoupgrade",
		soc2("CC7.1"), hipaa("164.308(a)(5)"), cis("6.5.2"),
	)}
}

func gkeCheckBinaryAuth(cl *container.Cluster) []engine.Finding {
	name := cl.Name
	if cl.BinaryAuthorization != nil && cl.BinaryAuthorization.Enabled {
		return []engine.Finding{pass("gcp_gke_binary_auth",
			fmt.Sprintf("GKE cluster %q has Binary Authorization enabled", name),
			soc2("CC7.1"), cis("6.10.1"))}
	}
	return []engine.Finding{fail(
		"gcp_gke_binary_auth",
		fmt.Sprintf("GKE cluster %q does not have Binary Authorization enabled", name),
		engine.SeverityMedium,
		"Enable Binary Authorization:\n  gcloud container clusters update "+name+" --binauthz-evaluation-mode=PROJECT_SINGLETON_POLICY_ENFORCE",
		soc2("CC7.1"), cis("6.10.1"),
	)}
}

func gkeCheckIntranodeVisibility(cl *container.Cluster) []engine.Finding {
	name := cl.Name
	if cl.NetworkConfig != nil && cl.NetworkConfig.EnableIntraNodeVisibility {
		return []engine.Finding{pass("gcp_gke_intranode_visibility",
			fmt.Sprintf("GKE cluster %q has intranode visibility enabled", name),
			soc2("CC6.6"), cis("6.6.5"))}
	}
	return []engine.Finding{fail(
		"gcp_gke_intranode_visibility",
		fmt.Sprintf("GKE cluster %q does not have intranode visibility enabled", name),
		engine.SeverityLow,
		"Enable intranode visibility:\n  gcloud container clusters update "+name+" --enable-intra-node-visibility",
		soc2("CC6.6"), cis("6.6.5"),
	)}
}

func gkeCheckReleaseChannel(cl *container.Cluster) []engine.Finding {
	name := cl.Name
	if cl.ReleaseChannel != nil && cl.ReleaseChannel.Channel != "" && cl.ReleaseChannel.Channel != "UNSPECIFIED" {
		return []engine.Finding{pass("gcp_gke_release_channel",
			fmt.Sprintf("GKE cluster %q is enrolled in release channel: %s", name, cl.ReleaseChannel.Channel),
			soc2("CC7.1"), cis("6.5.1"))}
	}
	return []engine.Finding{fail(
		"gcp_gke_release_channel",
		fmt.Sprintf("GKE cluster %q is not enrolled in a release channel", name),
		engine.SeverityMedium,
		"Enroll in a release channel:\n  gcloud container clusters update "+name+" --release-channel=regular",
		soc2("CC7.1"), cis("6.5.1"),
	)}
}
