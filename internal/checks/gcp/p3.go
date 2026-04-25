package gcp

import (
	"context"
	"fmt"

	"google.golang.org/api/securitycenter/v1"
	"github.com/complykit/complykit/internal/engine"
)

type GCPP3Checker struct {
	projectID string
}

func NewGCPP3Checker(projectID string) *GCPP3Checker {
	return &GCPP3Checker{projectID: projectID}
}

func (c *GCPP3Checker) Integration() string { return "GCP/SecurityCenter" }

func (c *GCPP3Checker) Run() ([]engine.Finding, error) {
	return c.checkSCC(), nil
}

func (c *GCPP3Checker) checkSCC() []engine.Finding {
	ctx := context.Background()
	svc, err := securitycenter.NewService(ctx)
	if err != nil {
		return []engine.Finding{skip("gcp_scc_enabled", "GCP Security Command Center", err.Error())}
	}

	// List sources — if SCC is enabled, built-in sources exist
	parent := fmt.Sprintf("projects/%s", c.projectID)
	resp, err := svc.Projects.Sources.List(parent).Do()
	if err != nil {
		return []engine.Finding{skip("gcp_scc_enabled", "GCP Security Command Center", err.Error())}
	}
	if len(resp.Sources) > 0 {
		return []engine.Finding{pass("gcp_scc_enabled",
			fmt.Sprintf("Security Command Center is enabled (%d source(s))", len(resp.Sources)),
			soc2("CC6.8"), hipaa("164.308(a)(1)(ii)(D)"))}
	}
	return []engine.Finding{fail(
		"gcp_scc_enabled", "Security Command Center has no sources — may not be enabled",
		engine.SeverityHigh,
		"Enable Security Command Center:\n  gcloud services enable securitycenter.googleapis.com\n  Then activate SCC in the Cloud Console → Security → Security Command Center",
		soc2("CC6.8"), hipaa("164.308(a)(1)(ii)(D)"),
	)}
}
