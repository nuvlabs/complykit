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
	FrameworkSOC2  Framework = "soc2"
	FrameworkHIPAA Framework = "hipaa"
	FrameworkCIS   Framework = "cis"
)

type ControlRef struct {
	Framework Framework
	ID        string
}

type Finding struct {
	CheckID     string
	Title       string
	Status      Status
	Severity    Severity
	Integration string
	Resource    string
	Detail      string
	Remediation string
	Controls    []ControlRef
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
