package gcp

import (
	"context"
	"fmt"

	"google.golang.org/api/dns/v1"
	"github.com/complykit/complykit/internal/engine"
)

type NetworkExtraChecker struct {
	projectID string
}

func NewNetworkExtraChecker(projectID string) *NetworkExtraChecker {
	return &NetworkExtraChecker{projectID: projectID}
}

func (c *NetworkExtraChecker) Integration() string { return "GCP/DNS" }

func (c *NetworkExtraChecker) Run() ([]engine.Finding, error) {
	return c.checkDNSLogging(), nil
}

func (c *NetworkExtraChecker) checkDNSLogging() []engine.Finding {
	ctx := context.Background()
	svc, err := dns.NewService(ctx)
	if err != nil {
		return []engine.Finding{skip("gcp_dns_logging", "GCP DNS Logging", err.Error())}
	}

	zones, err := svc.ManagedZones.List(c.projectID).Do()
	if err != nil {
		return []engine.Finding{skip("gcp_dns_logging", "GCP DNS Logging", err.Error())}
	}

	if len(zones.ManagedZones) == 0 {
		return []engine.Finding{pass("gcp_dns_logging", "No DNS managed zones found",
			soc2("CC7.2"), hipaa("164.312(b)"), cis("3.7"))}
	}

	var noLogging []string
	for _, zone := range zones.ManagedZones {
		if zone.Visibility != "private" {
			continue // DNS logging applies to private zones
		}
		if zone.CloudLoggingConfig == nil || !zone.CloudLoggingConfig.EnableLogging {
			noLogging = append(noLogging, zone.Name)
		}
	}

	if len(noLogging) == 0 {
		return []engine.Finding{pass("gcp_dns_logging", "All private DNS zones have logging enabled",
			soc2("CC7.2"), hipaa("164.312(b)"), cis("3.7"))}
	}
	return []engine.Finding{fail(
		"gcp_dns_logging",
		fmt.Sprintf("%d private DNS zone(s) without logging: %v", len(noLogging), truncate(noLogging, 5)),
		engine.SeverityMedium,
		"Enable DNS logging on private zones:\n  gcloud dns managed-zones update ZONE_NAME --enable-logging",
		soc2("CC7.2"), hipaa("164.312(b)"), cis("3.7"),
	)}
}
