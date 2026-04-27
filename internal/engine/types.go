package engine

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

type Status string

const (
	StatusPass Status = "pass"
	StatusFail Status = "fail"
	StatusSkip Status = "skip"
)

type Framework string

const (
	FrameworkSOC2     Framework = "soc2"
	FrameworkHIPAA    Framework = "hipaa"
	FrameworkCIS      Framework = "cis"
	FrameworkISO27001 Framework = "iso27001"
	FrameworkPCIDSS   Framework = "pcidss"
)

type ControlRef struct {
	Framework Framework `json:"framework"`
	ID        string    `json:"id"`
}

type Finding struct {
	CheckID     string       `json:"id"`
	Title       string       `json:"title"`
	Status      Status       `json:"status"`
	Severity    Severity     `json:"severity"`
	Integration string       `json:"integration"`
	Resource    string       `json:"resource"`
	Detail      string       `json:"detail"`
	Remediation string       `json:"remediation"`
	Controls    []ControlRef `json:"controls"`
}

type ScanResult struct {
	Findings  []Finding
	Passed    int
	Failed    int
	Skipped   int
	Score     int
}

func (r *ScanResult) Add(f Finding) {
	r.Findings = append(r.Findings, f)
	switch f.Status {
	case StatusPass:
		r.Passed++
	case StatusFail:
		r.Failed++
	case StatusSkip:
		r.Skipped++
	}
	total := r.Passed + r.Failed
	if total > 0 {
		r.Score = (r.Passed * 100) / total
	}
}

type Checker interface {
	Run() ([]Finding, error)
	Integration() string
}
