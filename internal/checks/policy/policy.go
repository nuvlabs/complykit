// Package policy implements cross-cutting compliance checks that span multiple
// cloud providers: backup evidence, incident response, pen tests, data classification.
package policy

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi"
	taggingtypes "github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi/types"
	"github.com/complykit/complykit/internal/engine"
)

// Checker runs cross-cutting policy checks.
// Evidence files are looked up relative to EvidenceDir (default: .complykit-evidence/policy/).
type Checker struct {
	evidenceDir string
	awsCfg      *aws.Config
}

func New(evidenceDir string, awsCfg *aws.Config) *Checker {
	if evidenceDir == "" {
		evidenceDir = ".complykit-evidence/policy"
	}
	return &Checker{evidenceDir: evidenceDir, awsCfg: awsCfg}
}

func (c *Checker) Integration() string { return "Policy" }

func (c *Checker) Run() ([]engine.Finding, error) {
	var findings []engine.Finding
	findings = append(findings, c.checkBackupRestoreTest()...)
	findings = append(findings, c.checkPenTestEvidence()...)
	findings = append(findings, c.checkIncidentResponseRunbook()...)
	findings = append(findings, c.checkDataClassification()...)
	findings = append(findings, c.checkVendorRisk()...)
	return findings, nil
}

// ── Backup restore test evidence ──────────────────────────────────────────────

func (c *Checker) checkBackupRestoreTest() []engine.Finding {
	patterns := []string{"backup-restore*", "restore-test*", "dr-test*", "disaster-recovery*", "backup_restore*"}
	file, age := findEvidenceFile(c.evidenceDir, patterns)
	if file != "" {
		if age <= 365*24*time.Hour {
			return []engine.Finding{pass("cross_backup_restore_test",
				fmt.Sprintf("Backup restore test evidence found: %s (%.0f days old)", filepath.Base(file), age.Hours()/24),
				soc2("CC9.1"), hipaa("164.308(a)(7)(ii)(D)"))}
		}
		return []engine.Finding{fail(
			"cross_backup_restore_test",
			fmt.Sprintf("Backup restore test evidence is older than 1 year: %s (%.0f days)", filepath.Base(file), age.Hours()/24),
			"Policy", "evidence", engine.SeverityHigh,
			"Upload current year's restore test results to: "+c.evidenceDir+"/backup-restore-YYYY.pdf",
			soc2("CC9.1"), hipaa("164.308(a)(7)(ii)(D)"),
		)}
	}
	return []engine.Finding{fail(
		"cross_backup_restore_test", "No backup restore test evidence found",
		"Policy", "evidence", engine.SeverityHigh,
		fmt.Sprintf("Document annual backup restore tests in %s/ with filename starting 'backup-restore' or 'restore-test'.\n  Accepted formats: .pdf, .md, .txt, .json", c.evidenceDir),
		soc2("CC9.1"), hipaa("164.308(a)(7)(ii)(D)"),
	)}
}

// ── Pen test evidence ─────────────────────────────────────────────────────────

func (c *Checker) checkPenTestEvidence() []engine.Finding {
	patterns := []string{"pentest*", "penetration*", "pen_test*", "pen-test*"}
	file, age := findEvidenceFile(c.evidenceDir, patterns)
	if file != "" {
		if age <= 365*24*time.Hour {
			return []engine.Finding{pass("cross_pen_test",
				fmt.Sprintf("Annual penetration test evidence found: %s (%.0f days old)", filepath.Base(file), age.Hours()/24),
				soc2("CC4.1"), hipaa("164.308(a)(8)"))}
		}
		return []engine.Finding{fail(
			"cross_pen_test",
			fmt.Sprintf("Penetration test evidence is older than 1 year: %s (%.0f days)", filepath.Base(file), age.Hours()/24),
			"Policy", "evidence", engine.SeverityHigh,
			"Upload current year's pen test report to: "+c.evidenceDir+"/pentest-YYYY.pdf",
			soc2("CC4.1"), hipaa("164.308(a)(8)"),
		)}
	}
	return []engine.Finding{fail(
		"cross_pen_test", "No penetration test evidence found",
		"Policy", "evidence", engine.SeverityHigh,
		fmt.Sprintf("Upload annual pen test report to %s/ with filename starting 'pentest'.\n  Accepted formats: .pdf, .md, .txt, .json", c.evidenceDir),
		soc2("CC4.1"), hipaa("164.308(a)(8)"),
	)}
}

// ── Incident response runbook ─────────────────────────────────────────────────

func (c *Checker) checkIncidentResponseRunbook() []engine.Finding {
	patterns := []string{"incident*", "ir-*", "runbook*", "playbook*"}
	file, _ := findEvidenceFile(c.evidenceDir, patterns)
	if file != "" {
		return []engine.Finding{pass("cross_incident_response",
			fmt.Sprintf("Incident response runbook found: %s", filepath.Base(file)),
			soc2("CC7.3"), hipaa("164.308(a)(6)"))}
	}
	return []engine.Finding{fail(
		"cross_incident_response", "No incident response runbook found",
		"Policy", "evidence", engine.SeverityHigh,
		fmt.Sprintf("Create an incident response runbook and save it to %s/ with filename starting 'incident' or 'runbook'.", c.evidenceDir),
		soc2("CC7.3"), hipaa("164.308(a)(6)"),
	)}
}

// ── Data classification via AWS resource tags ─────────────────────────────────

func (c *Checker) checkDataClassification() []engine.Finding {
	if c.awsCfg == nil {
		return []engine.Finding{skip("cross_data_classification", "Data Classification Tags",
			"AWS credentials not configured — skipping tag check")}
	}
	client := resourcegroupstaggingapi.NewFromConfig(*c.awsCfg)
	// Check if any resources have data classification tags
	out, err := client.GetResources(context.Background(), &resourcegroupstaggingapi.GetResourcesInput{
		TagFilters: []taggingtypes.TagFilter{
			{Key: aws.String("DataClassification")},
		},
		ResourcesPerPage: aws.Int32(1),
	})
	if err != nil {
		return []engine.Finding{skip("cross_data_classification", "Data Classification Tags", err.Error())}
	}
	if len(out.ResourceTagMappingList) > 0 {
		return []engine.Finding{pass("cross_data_classification",
			"At least one resource has a DataClassification tag — verify all PII/PHI resources are tagged",
			soc2("CC6.7"), hipaa("164.312(a)(2)(iv)"))}
	}
	return []engine.Finding{fail(
		"cross_data_classification",
		"No AWS resources have a DataClassification tag",
		"Policy", "tagging", engine.SeverityMedium,
		"Tag all resources containing PII or PHI with DataClassification:\n  aws resourcegroupstaggingapi tag-resources --resource-arn-list ARN --tags DataClassification=PHI",
		soc2("CC6.7"), hipaa("164.312(a)(2)(iv)"),
	)}
}

// ── Vendor risk register ──────────────────────────────────────────────────────

func (c *Checker) checkVendorRisk() []engine.Finding {
	patterns := []string{"vendor*", "third-party*", "saas*", "supplier*"}
	file, _ := findEvidenceFile(c.evidenceDir, patterns)
	if file != "" {
		return []engine.Finding{pass("cross_vendor_risk",
			fmt.Sprintf("Vendor risk register found: %s", filepath.Base(file)),
			soc2("CC9.2"), hipaa("164.308(b)"))}
	}
	return []engine.Finding{fail(
		"cross_vendor_risk", "No vendor risk register found",
		"Policy", "evidence", engine.SeverityMedium,
		fmt.Sprintf("Create a vendor risk register and save to %s/ with filename starting 'vendor' or 'third-party'.", c.evidenceDir),
		soc2("CC9.2"), hipaa("164.308(b)"),
	)}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func findEvidenceFile(dir string, patterns []string) (string, time.Duration) {
	for _, pattern := range patterns {
		for _, ext := range []string{"*.pdf", "*.md", "*.txt", "*.json", "*.docx"} {
			glob := filepath.Join(dir, strings.TrimSuffix(pattern, "*")+"*"+strings.TrimPrefix(ext, "*"))
			matches, _ := filepath.Glob(filepath.Join(dir, pattern+strings.TrimPrefix(ext, "*")))
			if len(matches) == 0 {
				matches, _ = filepath.Glob(glob)
			}
			for _, m := range matches {
				info, err := os.Stat(m)
				if err == nil {
					return m, time.Since(info.ModTime())
				}
			}
		}
	}
	return "", 0
}

func pass(id, title string, controls ...engine.ControlRef) engine.Finding {
	return engine.Finding{CheckID: id, Title: title, Status: engine.StatusPass, Integration: "Policy", Controls: controls}
}
func fail(id, title, integration, resource string, severity engine.Severity, remediation string, controls ...engine.ControlRef) engine.Finding {
	return engine.Finding{CheckID: id, Title: title, Status: engine.StatusFail, Severity: severity, Integration: integration, Resource: resource, Remediation: remediation, Controls: controls}
}
func skip(id, title, detail string) engine.Finding {
	return engine.Finding{CheckID: id, Title: title, Status: engine.StatusSkip, Integration: "Policy", Detail: detail}
}
func soc2(id string) engine.ControlRef  { return engine.ControlRef{Framework: engine.FrameworkSOC2, ID: id} }
func hipaa(id string) engine.ControlRef { return engine.ControlRef{Framework: engine.FrameworkHIPAA, ID: id} }
