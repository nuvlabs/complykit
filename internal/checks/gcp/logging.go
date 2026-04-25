package gcp

import (
	"context"
	"fmt"

	"google.golang.org/api/logging/v2"
	"github.com/complykit/complykit/internal/engine"
)

type LoggingChecker struct {
	projectID string
}

func NewLoggingChecker(projectID string) *LoggingChecker {
	return &LoggingChecker{projectID: projectID}
}

func (c *LoggingChecker) Integration() string { return "GCP/Logging" }

func (c *LoggingChecker) Run() ([]engine.Finding, error) {
	var findings []engine.Finding
	findings = append(findings, c.checkLogSink()...)
	findings = append(findings, c.checkLogMetrics()...)
	return findings, nil
}

func (c *LoggingChecker) checkLogSink() []engine.Finding {
	ctx := context.Background()
	svc, err := logging.NewService(ctx)
	if err != nil {
		return []engine.Finding{skip("gcp_log_sink", "GCP Log Sink", err.Error())}
	}
	resp, err := svc.Projects.Sinks.List("projects/" + c.projectID).Do()
	if err != nil {
		return []engine.Finding{skip("gcp_log_sink", "GCP Log Sink", err.Error())}
	}
	// Check there's at least one sink that exports all logs (empty filter = all logs)
	for _, sink := range resp.Sinks {
		if sink.Filter == "" || sink.Filter == "logName:cloudaudit.googleapis.com" {
			return []engine.Finding{pass("gcp_log_sink", "GCP log sink configured to export all log entries",
				soc2("CC7.2"), hipaa("164.312(b)"), cis("2.2"))}
		}
	}
	if len(resp.Sinks) > 0 {
		return []engine.Finding{pass("gcp_log_sink", fmt.Sprintf("GCP log sink(s) configured (%d sinks)", len(resp.Sinks)),
			soc2("CC7.2"), hipaa("164.312(b)"), cis("2.2"))}
	}
	return []engine.Finding{fail(
		"gcp_log_sink", "No GCP log sinks configured — logs are not exported",
		engine.SeverityHigh,
		"Create a log sink to export logs to Cloud Storage or BigQuery:\n  gcloud logging sinks create AllLogs storage.googleapis.com/LOG_BUCKET --log-filter=''",
		soc2("CC7.2"), hipaa("164.312(b)"), cis("2.2"),
	)}
}

var requiredLogMetrics = []struct {
	id, title, filter, cis string
}{
	{"gcp_log_metric_ownership", "Log metric: project ownership changes",
		`(protoPayload.serviceName="cloudresourcemanager.googleapis.com") AND (ProjectOwnership OR projectOwnerInvitee) OR (protoPayload.serviceData.policyDelta.bindingDeltas.action="REMOVE" AND protoPayload.serviceData.policyDelta.bindingDeltas.role="roles/owner") OR (protoPayload.serviceData.policyDelta.bindingDeltas.action="ADD" AND protoPayload.serviceData.policyDelta.bindingDeltas.role="roles/owner")`, "2.4"},
	{"gcp_log_metric_audit_config", "Log metric: audit config changes",
		`protoPayload.methodName="SetIamPolicy" AND protoPayload.serviceData.policyDelta.auditConfigDeltas:*`, "2.5"},
	{"gcp_log_metric_custom_role", "Log metric: custom role changes",
		`resource.type="iam_role" AND protoPayload.methodName="google.iam.admin.v1.CreateRole" OR protoPayload.methodName="google.iam.admin.v1.DeleteRole" OR protoPayload.methodName="google.iam.admin.v1.UpdateRole"`, "2.6"},
}

func (c *LoggingChecker) checkLogMetrics() []engine.Finding {
	ctx := context.Background()
	svc, err := logging.NewService(ctx)
	if err != nil {
		return []engine.Finding{skip("gcp_log_metrics", "GCP Log Metrics", err.Error())}
	}
	resp, err := svc.Projects.Metrics.List("projects/" + c.projectID).Do()
	if err != nil {
		return []engine.Finding{skip("gcp_log_metrics", "GCP Log Metrics", err.Error())}
	}

	var findings []engine.Finding
	for _, req := range requiredLogMetrics {
		found := false
		for _, m := range resp.Metrics {
			if m.Filter == req.filter {
				found = true
				break
			}
		}
		if found {
			findings = append(findings, pass(req.id, req.title+" is configured",
				soc2("CC7.2"), hipaa("164.312(b)"), cis(req.cis)))
		} else {
			findings = append(findings, fail(
				req.id, req.title+" is not configured",
				engine.SeverityMedium,
				fmt.Sprintf("Create log metric:\n  gcloud logging metrics create METRIC_NAME --description='%s' --log-filter='%s'", req.title, req.filter),
				soc2("CC7.2"), hipaa("164.312(b)"), cis(req.cis),
			))
		}
	}
	return findings
}
