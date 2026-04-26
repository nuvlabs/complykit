// Package custom loads user-defined compliance controls from complykit.yaml.
//
// Example complykit.yaml:
//
//	version: 1
//	controls:
//	  - id: my_backup_check
//	    title: "Daily backups enabled"
//	    severity: high
//	    frameworks:
//	      soc2: CC7.2
//	      hipaa: "164.312(a)(2)(iv)"
//	    check:
//	      type: shell
//	      command: "aws rds describe-db-instances | jq '.DBInstances[].BackupRetentionPeriod > 0'"
//	      expect: "true"
//	    remediation: "Enable automated backups on your RDS instance."
package custom

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/complykit/complykit/internal/engine"
)

type controlDef struct {
	ID          string            `yaml:"id"`
	Title       string            `yaml:"title"`
	Severity    string            `yaml:"severity"`
	Frameworks  map[string]string `yaml:"frameworks"`
	Remediation string            `yaml:"remediation"`
	Check       struct {
		Type    string `yaml:"type"`    // shell | file | http
		Command string `yaml:"command"` // for shell
		Path    string `yaml:"path"`    // for file
		URL     string `yaml:"url"`     // for http
		Expect  string `yaml:"expect"`  // expected output / status
	} `yaml:"check"`
}

type configFile struct {
	Version  int          `yaml:"version"`
	Controls []controlDef `yaml:"controls"`
}

type Checker struct {
	configPath string
}

func New(configPath string) *Checker {
	if configPath == "" {
		configPath = "complykit.yaml"
	}
	return &Checker{configPath: configPath}
}

func (c *Checker) Integration() string { return "Custom" }

func (c *Checker) Run() ([]engine.Finding, error) {
	data, err := os.ReadFile(c.configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // no custom controls file — skip
		}
		return nil, fmt.Errorf("read %s: %w", c.configPath, err)
	}

	var cfg configFile
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", c.configPath, err)
	}

	var findings []engine.Finding
	for _, ctrl := range cfg.Controls {
		f := runControl(ctrl)
		findings = append(findings, f)
	}
	return findings, nil
}

func runControl(ctrl controlDef) engine.Finding {
	var controls []engine.ControlRef
	for fw, id := range ctrl.Frameworks {
		controls = append(controls, engine.ControlRef{Framework: engine.Framework(fw), ID: id})
	}

	sev := parseSeverity(ctrl.Severity)
	status := engine.StatusFail
	detail := ""

	switch ctrl.Check.Type {
	case "shell":
		status, detail = runShellCheck(ctrl.Check.Command, ctrl.Check.Expect)
	case "file":
		status, detail = runFileCheck(ctrl.Check.Path, ctrl.Check.Expect)
	default:
		status = engine.StatusSkip
		detail = fmt.Sprintf("unsupported check type: %s", ctrl.Check.Type)
	}

	return engine.Finding{
		CheckID:     ctrl.ID,
		Title:       ctrl.Title,
		Status:      status,
		Severity:    sev,
		Integration: "Custom",
		Detail:      detail,
		Remediation: ctrl.Remediation,
		Controls:    controls,
	}
}

func runShellCheck(command, expect string) (engine.Status, string) {
	cmd := exec.Command("sh", "-c", command)
	cmd.Env = os.Environ()

	// Timeout after 30s
	done := make(chan struct{})
	var out []byte
	var err error

	go func() {
		out, err = cmd.Output()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		cmd.Process.Kill()
		return engine.StatusSkip, "check timed out after 30s"
	}

	if err != nil && expect == "" {
		return engine.StatusFail, fmt.Sprintf("command failed: %v", err)
	}

	output := strings.TrimSpace(string(out))

	if expect == "" {
		// No expected output — pass if exit code 0
		if err == nil {
			return engine.StatusPass, ""
		}
		return engine.StatusFail, fmt.Sprintf("exit error: %v", err)
	}

	if strings.Contains(output, expect) {
		return engine.StatusPass, ""
	}
	return engine.StatusFail, fmt.Sprintf("expected %q, got %q", expect, output)
}

func runFileCheck(path, expect string) (engine.Status, string) {
	switch expect {
	case "exists", "":
		if _, err := os.Stat(path); err == nil {
			return engine.StatusPass, ""
		}
		return engine.StatusFail, fmt.Sprintf("file not found: %s", path)
	case "not_exists":
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return engine.StatusPass, ""
		}
		return engine.StatusFail, fmt.Sprintf("file should not exist: %s", path)
	default:
		data, err := os.ReadFile(path)
		if err != nil {
			return engine.StatusFail, fmt.Sprintf("cannot read %s: %v", path, err)
		}
		if strings.Contains(string(data), expect) {
			return engine.StatusPass, ""
		}
		return engine.StatusFail, fmt.Sprintf("file %s does not contain %q", path, expect)
	}
}

func parseSeverity(s string) engine.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return engine.SeverityCritical
	case "high":
		return engine.SeverityHigh
	case "medium":
		return engine.SeverityMedium
	default:
		return engine.SeverityLow
	}
}
