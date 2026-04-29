package terraform

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/complykit/complykit/internal/engine"
)

type Checker struct {
	dir string
}

func New(dir string) *Checker {
	if dir == "" {
		dir = "."
	}
	return &Checker{dir: dir}
}

func (c *Checker) Integration() string { return "Terraform" }

func (c *Checker) Run() ([]engine.Finding, error) {
	files, err := findTFFiles(c.dir)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, nil // no .tf files — skip silently
	}

	// Read all content once
	content := readAll(files)

	var findings []engine.Finding
	add := func(f engine.Finding) { findings = append(findings, f) }

	// ── S3 ──────────────────────────────────────────────────────────────────
	checkS3PublicACL(content, add)
	checkS3PublicBlock(content, add)
	checkS3Encryption(content, add)
	checkS3Versioning(content, add)

	// ── Security Groups ─────────────────────────────────────────────────────
	checkSGOpenSSH(content, add)
	checkSGOpenRDP(content, add)
	checkSGOpenAll(content, add)

	// ── RDS ─────────────────────────────────────────────────────────────────
	checkRDSPublic(content, add)
	checkRDSEncryption(content, add)
	checkRDSDeletionProtection(content, add)
	checkRDSSSLMode(content, add)

	// ── EC2 ─────────────────────────────────────────────────────────────────
	checkIMDSv1(content, add)

	// ── State & Backend ─────────────────────────────────────────────────────
	checkNoBackend(content, add)

	// ── Secrets ─────────────────────────────────────────────────────────────
	checkHardcodedSecrets(content, add)
	checkRDSHardcodedPassword(content, add)

	return findings, nil
}

// ── helpers ──────────────────────────────────────────────────────────────────

func findTFFiles(dir string) ([]string, error) {
	var files []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() && (info.Name() == ".terraform" || info.Name() == ".git") {
			return filepath.SkipDir
		}
		if !info.IsDir() && strings.HasSuffix(path, ".tf") {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}

func readAll(files []string) string {
	var sb strings.Builder
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err == nil {
			sb.WriteString(fmt.Sprintf("\n# file: %s\n", f))
			sb.Write(b)
		}
	}
	return sb.String()
}

func hasResource(content, resourceType string) bool {
	return regexp.MustCompile(`resource\s+"` + regexp.QuoteMeta(resourceType) + `"`).MatchString(content)
}

func hasMatch(content, pattern string) bool {
	return regexp.MustCompile(pattern).MatchString(content)
}

func soc2(id string) engine.ControlRef {
	return engine.ControlRef{Framework: "soc2", ID: id}
}

func pci(id string) engine.ControlRef {
	return engine.ControlRef{Framework: "pci", ID: id}
}

func iso(id string) engine.ControlRef {
	return engine.ControlRef{Framework: "iso", ID: id}
}

func finding(id, title string, status engine.Status, sev engine.Severity, remediation string, controls ...engine.ControlRef) engine.Finding {
	return engine.Finding{
		CheckID:     id,
		Title:       title,
		Status:      status,
		Severity:    sev,
		Integration: "Terraform",
		Remediation: remediation,
		Controls:    controls,
	}
}

// ── S3 checks ────────────────────────────────────────────────────────────────

func checkS3PublicACL(content string, add func(engine.Finding)) {
	if !hasResource(content, "aws_s3_bucket") {
		return
	}
	publicACL := regexp.MustCompile(`acl\s*=\s*"(public-read|public-read-write)"`)
	status := engine.StatusPass
	rem := ""
	if publicACL.MatchString(content) {
		status = engine.StatusFail
		rem = `Remove or replace the ACL:\n  acl = "private"\nOr use aws_s3_bucket_acl resource.`
	}
	add(finding("tf_s3_no_public_acl", "S3 bucket does not use public ACL", status, engine.SeverityCritical, rem,
		soc2("CC6.1"), engine.ControlRef{Framework: "cis", ID: "2.1.5"}))
}

func checkS3PublicBlock(content string, add func(engine.Finding)) {
	if !hasResource(content, "aws_s3_bucket") {
		return
	}
	hasBlock := hasResource(content, "aws_s3_bucket_public_access_block")
	allBlocked := hasMatch(content, `block_public_acls\s*=\s*true`) &&
		hasMatch(content, `block_public_policy\s*=\s*true`) &&
		hasMatch(content, `ignore_public_acls\s*=\s*true`) &&
		hasMatch(content, `restrict_public_buckets\s*=\s*true`)

	status := engine.StatusPass
	rem := ""
	if !hasBlock || !allBlocked {
		status = engine.StatusFail
		rem = "Add aws_s3_bucket_public_access_block with all four settings set to true."
	}
	add(finding("tf_s3_public_access_block", "S3 bucket public access block configured", status, engine.SeverityHigh, rem,
		soc2("CC6.1")))
}

func checkS3Encryption(content string, add func(engine.Finding)) {
	if !hasResource(content, "aws_s3_bucket") {
		return
	}
	hasEnc := hasResource(content, "aws_s3_bucket_server_side_encryption_configuration")
	status := engine.StatusPass
	rem := ""
	if !hasEnc {
		status = engine.StatusFail
		rem = "Add aws_s3_bucket_server_side_encryption_configuration with AES256 or aws:kms."
	}
	add(finding("tf_s3_encryption", "S3 bucket server-side encryption enabled", status, engine.SeverityHigh, rem,
		soc2("CC6.1")))
}

func checkS3Versioning(content string, add func(engine.Finding)) {
	if !hasResource(content, "aws_s3_bucket") {
		return
	}
	hasVer := hasResource(content, "aws_s3_bucket_versioning") &&
		hasMatch(content, `status\s*=\s*"Enabled"`)
	status := engine.StatusPass
	rem := ""
	if !hasVer {
		status = engine.StatusFail
		rem = `Add aws_s3_bucket_versioning:\n  versioning_configuration { status = "Enabled" }`
	}
	add(finding("tf_s3_versioning", "S3 bucket versioning enabled", status, engine.SeverityMedium, rem,
		soc2("CC7.2")))
}

// ── Security Group checks ─────────────────────────────────────────────────────

func checkSGOpenSSH(content string, add func(engine.Finding)) {
	if !hasResource(content, "aws_security_group") {
		return
	}
	open := hasMatch(content, `(?s)ingress[^}]*from_port\s*=\s*22[^}]*cidr_blocks\s*=\s*\["0\.0\.0\.0/0"\]`) ||
		hasMatch(content, `(?s)ingress[^}]*cidr_blocks\s*=\s*\["0\.0\.0\.0/0"\][^}]*from_port\s*=\s*22`)
	status := engine.StatusPass
	rem := ""
	if open {
		status = engine.StatusFail
		rem = "Restrict SSH (port 22) to specific IP ranges. Replace 0.0.0.0/0 with your office/VPN CIDR."
	}
	add(finding("tf_sg_ssh_restricted", "SSH not open to the world (0.0.0.0/0)", status, engine.SeverityCritical, rem,
		soc2("CC6.6"), engine.ControlRef{Framework: "cis", ID: "5.2"}))
}

func checkSGOpenRDP(content string, add func(engine.Finding)) {
	if !hasResource(content, "aws_security_group") {
		return
	}
	open := hasMatch(content, `(?s)ingress[^}]*from_port\s*=\s*3389[^}]*cidr_blocks\s*=\s*\["0\.0\.0\.0/0"\]`) ||
		hasMatch(content, `(?s)ingress[^}]*cidr_blocks\s*=\s*\["0\.0\.0\.0/0"\][^}]*from_port\s*=\s*3389`)
	status := engine.StatusPass
	rem := ""
	if open {
		status = engine.StatusFail
		rem = "Restrict RDP (port 3389) to specific IP ranges. Never expose RDP to 0.0.0.0/0."
	}
	add(finding("tf_sg_rdp_restricted", "RDP not open to the world (0.0.0.0/0)", status, engine.SeverityCritical, rem,
		soc2("CC6.6")))
}

func checkSGOpenAll(content string, add func(engine.Finding)) {
	if !hasResource(content, "aws_security_group") {
		return
	}
	open := hasMatch(content, `(?s)ingress[^}]*from_port\s*=\s*0[^}]*to_port\s*=\s*0[^}]*cidr_blocks\s*=\s*\["0\.0\.0\.0/0"\]`)
	status := engine.StatusPass
	rem := ""
	if open {
		status = engine.StatusFail
		rem = "Remove catch-all ingress rules. Apply least-privilege: only open required ports to required CIDRs."
	}
	add(finding("tf_sg_no_open_all", "Security group does not allow all traffic from internet", status, engine.SeverityCritical, rem,
		soc2("CC6.6")))
}

// ── RDS checks ───────────────────────────────────────────────────────────────

func checkRDSPublic(content string, add func(engine.Finding)) {
	if !hasResource(content, "aws_db_instance") {
		return
	}
	public := hasMatch(content, `publicly_accessible\s*=\s*true`)
	status := engine.StatusPass
	rem := ""
	if public {
		status = engine.StatusFail
		rem = `Set publicly_accessible = false on all aws_db_instance resources.`
	}
	add(finding("tf_rds_not_public", "RDS instance not publicly accessible", status, engine.SeverityCritical, rem,
		soc2("CC6.1"), engine.ControlRef{Framework: "cis", ID: "2.3.2"}))
}

func checkRDSEncryption(content string, add func(engine.Finding)) {
	if !hasResource(content, "aws_db_instance") {
		return
	}
	noEnc := hasMatch(content, `storage_encrypted\s*=\s*false`) ||
		!hasMatch(content, `storage_encrypted\s*=\s*true`)
	status := engine.StatusPass
	rem := ""
	if noEnc {
		status = engine.StatusFail
		rem = `Add storage_encrypted = true to all aws_db_instance resources.`
	}
	add(finding("tf_rds_encrypted", "RDS storage encryption enabled", status, engine.SeverityHigh, rem,
		soc2("CC6.1"), engine.ControlRef{Framework: "hipaa", ID: "164.312(a)(2)(iv)"}))
}

func checkRDSSSLMode(content string, add func(engine.Finding)) {
	hasRDS := hasResource(content, "aws_db_instance") || hasResource(content, "aws_rds_cluster")
	if !hasRDS {
		return
	}
	hasCustomPG := hasResource(content, "aws_db_parameter_group")
	hasSSLParam := hasMatch(content, `rds\.force_ssl`) || hasMatch(content, `require_secure_transport`)
	if !hasCustomPG || !hasSSLParam {
		add(finding("tf_rds_ssl_mode", "RDS parameter group enforces SSL/TLS", engine.StatusFail, engine.SeverityHigh,
			"Create an aws_db_parameter_group with SSL enforcement and associate it with your DB instance:\n  PostgreSQL: rds.force_ssl = 1\n  MySQL/MariaDB: require_secure_transport = ON",
			soc2("CC6.7"), engine.ControlRef{Framework: "hipaa", ID: "164.312(e)(1)"}))
		return
	}
	add(finding("tf_rds_ssl_mode", "RDS parameter group enforces SSL/TLS", engine.StatusPass, engine.SeverityHigh, "",
		soc2("CC6.7"), engine.ControlRef{Framework: "hipaa", ID: "164.312(e)(1)"}))
}

func checkRDSDeletionProtection(content string, add func(engine.Finding)) {
	if !hasResource(content, "aws_db_instance") {
		return
	}
	noProtection := !hasMatch(content, `deletion_protection\s*=\s*true`)
	status := engine.StatusPass
	rem := ""
	if noProtection {
		status = engine.StatusFail
		rem = `Add deletion_protection = true to prevent accidental database deletion.`
	}
	add(finding("tf_rds_deletion_protection", "RDS deletion protection enabled", status, engine.SeverityMedium, rem,
		soc2("CC7.2")))
}

// ── EC2 checks ───────────────────────────────────────────────────────────────

func checkIMDSv1(content string, add func(engine.Finding)) {
	if !hasResource(content, "aws_instance") {
		return
	}
	v2Enforced := hasMatch(content, `http_tokens\s*=\s*"required"`)
	status := engine.StatusPass
	rem := ""
	if !v2Enforced {
		status = engine.StatusFail
		rem = "Add metadata_options block:\n  metadata_options {\n    http_tokens = \"required\"\n  }"
	}
	add(finding("tf_ec2_imdsv2", "EC2 instance enforces IMDSv2", status, engine.SeverityHigh, rem,
		soc2("CC6.6"), engine.ControlRef{Framework: "cis", ID: "5.6"}))
}

// ── Backend ──────────────────────────────────────────────────────────────────

func checkNoBackend(content string, add func(engine.Finding)) {
	hasBackend := hasMatch(content, `terraform\s*\{[^}]*backend\s+"`)
	status := engine.StatusPass
	rem := ""
	if !hasBackend {
		status = engine.StatusFail
		rem = "Configure a remote backend (S3+DynamoDB, Terraform Cloud) to encrypt and lock state.\n  terraform {\n    backend \"s3\" { ... }\n  }"
	}
	add(finding("tf_remote_backend", "Terraform remote backend configured", status, engine.SeverityHigh, rem,
		soc2("CC6.1")))
}

// ── Secrets ──────────────────────────────────────────────────────────────────

func checkRDSHardcodedPassword(content string, add func(engine.Finding)) {
	hasRDS := hasResource(content, "aws_db_instance") || hasResource(content, "aws_rds_cluster")
	if !hasRDS {
		return
	}
	// Match password = "literal" that is not a variable reference (no ${ or var.)
	hardcoded := hasMatch(content, `password\s*=\s*"[^"$][^"]{2,}"`) &&
		!hasMatch(content, `password\s*=\s*".*\$\{`) &&
		!hasMatch(content, `password\s*=\s*var\.`)
	if hardcoded {
		add(finding("tf_db_hardcoded_password", "No hardcoded passwords in RDS resources",
			engine.StatusFail, engine.SeverityCritical,
			"Replace the hardcoded password with a Secrets Manager or SSM reference:\n"+
				"  password = aws_secretsmanager_secret_version.db.secret_string\n"+
				"  Or use var.db_password marked sensitive = true",
			soc2("CC6.1"), engine.ControlRef{Framework: "hipaa", ID: "164.312(a)(2)(iv)"}))
		return
	}
	add(finding("tf_db_hardcoded_password", "No hardcoded passwords in RDS resources",
		engine.StatusPass, engine.SeverityCritical, "",
		soc2("CC6.1")))
}

func checkHardcodedSecrets(content string, add func(engine.Finding)) {
	secretPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)(password|secret|token|api_key|access_key)\s*=\s*"[A-Za-z0-9+/]{8,}"`),
		regexp.MustCompile(`AKIA[0-9A-Z]{16}`), // AWS access key
		regexp.MustCompile(`(?i)secret_access_key\s*=\s*"[^"]{10,}"`),
	}
	for _, p := range secretPatterns {
		if p.MatchString(content) {
			add(finding("tf_no_hardcoded_secrets", "No hardcoded secrets in Terraform files",
				engine.StatusFail, engine.SeverityCritical,
				"Move secrets to variables with sensitive=true, use aws_secretsmanager_secret, or Vault.",
				soc2("CC6.1"), engine.ControlRef{Framework: "hipaa", ID: "164.312(a)(2)(iv)"}))
			return
		}
	}
	add(finding("tf_no_hardcoded_secrets", "No hardcoded secrets in Terraform files",
		engine.StatusPass, engine.SeverityCritical, "", soc2("CC6.1")))
}
