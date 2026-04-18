package alert

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/smtp"
	"strings"
	"time"

	"github.com/complykit/complykit/internal/engine"
)

type Config struct {
	SlackWebhook string
	EmailTo      string
	EmailFrom    string
	SMTPHost     string
	SMTPPort     int
	SMTPUser     string
	SMTPPass     string
}

type Regression struct {
	CheckID     string
	Title       string
	Severity    engine.Severity
	Integration string
}

func Notify(cfg Config, regressions []Regression, score int, prevScore int) error {
	var errs []string

	if cfg.SlackWebhook != "" {
		if err := sendSlack(cfg.SlackWebhook, regressions, score, prevScore); err != nil {
			errs = append(errs, fmt.Sprintf("slack: %v", err))
		}
	}

	if cfg.EmailTo != "" && cfg.SMTPHost != "" {
		if err := sendEmail(cfg, regressions, score, prevScore); err != nil {
			errs = append(errs, fmt.Sprintf("email: %v", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("alert errors: %s", strings.Join(errs, "; "))
	}
	return nil
}

// ── Slack ───────────────────────────────────────────────────────────────────

type slackPayload struct {
	Blocks []slackBlock `json:"blocks"`
}

type slackBlock struct {
	Type string      `json:"type"`
	Text *slackText  `json:"text,omitempty"`
	Fields []slackText `json:"fields,omitempty"`
}

type slackText struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

func sendSlack(webhookURL string, regressions []Regression, score, prevScore int) error {
	delta := score - prevScore
	deltaStr := fmt.Sprintf("%+d", delta)

	header := fmt.Sprintf(":warning: *ComplyKit — %d regression(s) detected*\nScore: *%d/100* (%s) · %s",
		len(regressions), score, deltaStr, time.Now().Format("2006-01-02 15:04 UTC"))

	var lines []string
	for _, r := range regressions {
		lines = append(lines, fmt.Sprintf("• `%s` [%s] — *%s*", r.CheckID, strings.ToUpper(string(r.Severity)), r.Title))
	}

	payload := slackPayload{
		Blocks: []slackBlock{
			{Type: "section", Text: &slackText{Type: "mrkdwn", Text: header}},
			{Type: "divider"},
			{Type: "section", Text: &slackText{Type: "mrkdwn", Text: strings.Join(lines, "\n")}},
			{Type: "section", Text: &slackText{Type: "mrkdwn", Text: "Run `comply fix` to see remediation steps."}},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	resp, err := http.Post(webhookURL, "application/json", bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("slack returned status %d", resp.StatusCode)
	}
	return nil
}

// ── Email ───────────────────────────────────────────────────────────────────

func sendEmail(cfg Config, regressions []Regression, score, prevScore int) error {
	delta := score - prevScore
	subject := fmt.Sprintf("ComplyKit Alert: %d compliance regression(s) detected", len(regressions))

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("ComplyKit Compliance Alert\n"))
	sb.WriteString(fmt.Sprintf("==========================\n\n"))
	sb.WriteString(fmt.Sprintf("Score: %d/100 (%+d from last scan)\n", score, delta))
	sb.WriteString(fmt.Sprintf("Time: %s\n\n", time.Now().Format("2006-01-02 15:04:05 UTC")))
	sb.WriteString(fmt.Sprintf("%d Regression(s) Detected:\n\n", len(regressions)))

	for i, r := range regressions {
		sb.WriteString(fmt.Sprintf("%d. [%s] %s\n", i+1, strings.ToUpper(string(r.Severity)), r.Title))
		sb.WriteString(fmt.Sprintf("   Check ID: %s | Integration: %s\n\n", r.CheckID, r.Integration))
	}

	sb.WriteString("Run `comply fix` on your terminal to see step-by-step remediation.\n")

	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s",
		cfg.EmailFrom, cfg.EmailTo, subject, sb.String())

	addr := fmt.Sprintf("%s:%d", cfg.SMTPHost, cfg.SMTPPort)
	auth := smtp.PlainAuth("", cfg.SMTPUser, cfg.SMTPPass, cfg.SMTPHost)

	return smtp.SendMail(addr, auth, cfg.EmailFrom, []string{cfg.EmailTo}, []byte(msg))
}
