package report

import (
	"fmt"
	"strings"
	"time"

	"github.com/go-pdf/fpdf"
	"github.com/complykit/complykit/internal/engine"
)

const (
	colorPass    = "#22c55e"
	colorFail    = "#ef4444"
	colorSkip    = "#f59e0b"
	colorCrit    = "#dc2626"
	colorHigh    = "#ea580c"
	colorMedium  = "#ca8a04"
	colorBg      = "#f8fafc"
	colorBorder  = "#e2e8f0"
	colorText    = "#1e293b"
	colorMuted   = "#64748b"
	colorBrand   = "#6366f1"
)

func hexToRGB(hex string) (r, g, b int) {
	hex = strings.TrimPrefix(hex, "#")
	fmt.Sscanf(hex[0:2], "%x", &r)
	fmt.Sscanf(hex[2:4], "%x", &g)
	fmt.Sscanf(hex[4:6], "%x", &b)
	return
}

func setFillHex(pdf *fpdf.Fpdf, hex string) {
	r, g, b := hexToRGB(hex)
	pdf.SetFillColor(r, g, b)
}

func setTextHex(pdf *fpdf.Fpdf, hex string) {
	r, g, b := hexToRGB(hex)
	pdf.SetTextColor(r, g, b)
}

func setDrawHex(pdf *fpdf.Fpdf, hex string) {
	r, g, b := hexToRGB(hex)
	pdf.SetDrawColor(r, g, b)
}

func WritePDF(result *engine.ScanResult, framework, path string) error {
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(20, 20, 20)
	pdf.SetAutoPageBreak(true, 20)
	pdf.AddPage()

	// ── Header ──────────────────────────────────────────────────────
	setFillHex(pdf, colorBrand)
	pdf.Rect(0, 0, 210, 38, "F")

	pdf.SetFont("Helvetica", "B", 22)
	setTextHex(pdf, "#ffffff")
	pdf.SetXY(20, 10)
	pdf.Cell(0, 10, "ComplyKit")

	pdf.SetFont("Helvetica", "", 11)
	pdf.SetXY(20, 22)
	pdf.Cell(0, 8, fmt.Sprintf("%s Compliance Report", strings.ToUpper(framework)))

	pdf.SetFont("Helvetica", "", 9)
	pdf.SetXY(20, 30)
	pdf.Cell(0, 6, fmt.Sprintf("Generated: %s", time.Now().UTC().Format("2006-01-02 15:04 UTC")))

	pdf.SetXY(0, 44)

	// ── Score card ──────────────────────────────────────────────────
	setFillHex(pdf, colorBg)
	setDrawHex(pdf, colorBorder)
	pdf.RoundedRect(20, 46, 170, 28, 3, "1234", "FD")

	scoreColor := colorPass
	if result.Score < 50 {
		scoreColor = colorCrit
	} else if result.Score < 80 {
		scoreColor = colorMedium
	}

	pdf.SetFont("Helvetica", "B", 28)
	setTextHex(pdf, scoreColor)
	pdf.SetXY(24, 50)
	pdf.Cell(30, 12, fmt.Sprintf("%d", result.Score))

	pdf.SetFont("Helvetica", "", 10)
	setTextHex(pdf, colorMuted)
	pdf.SetXY(24, 62)
	pdf.Cell(30, 6, "/ 100")

	statLabels := []struct{ label, value, color string }{
		{"Passed", fmt.Sprintf("%d", result.Passed), colorPass},
		{"Failed", fmt.Sprintf("%d", result.Failed), colorFail},
		{"Skipped", fmt.Sprintf("%d", result.Skipped), colorSkip},
		{"Total", fmt.Sprintf("%d", result.Passed+result.Failed+result.Skipped), colorText},
	}
	xPos := 80.0
	for _, s := range statLabels {
		pdf.SetFont("Helvetica", "B", 14)
		setTextHex(pdf, s.color)
		pdf.SetXY(xPos, 50)
		pdf.Cell(22, 8, s.value)

		pdf.SetFont("Helvetica", "", 8)
		setTextHex(pdf, colorMuted)
		pdf.SetXY(xPos, 60)
		pdf.Cell(22, 6, s.label)
		xPos += 26
	}

	pdf.SetXY(20, 80)

	// ── Findings ────────────────────────────────────────────────────
	pdf.SetFont("Helvetica", "B", 13)
	setTextHex(pdf, colorText)
	pdf.SetXY(20, 82)
	pdf.Cell(0, 8, "Findings")
	pdf.SetXY(20, 90)

	currentIntegration := ""
	for _, f := range result.Findings {
		if pdf.GetY() > 250 {
			pdf.AddPage()
			pdf.SetXY(20, 20)
		}

		if f.Integration != currentIntegration {
			currentIntegration = f.Integration
			pdf.SetFont("Helvetica", "B", 10)
			setTextHex(pdf, colorBrand)
			pdf.SetXY(20, pdf.GetY()+4)
			pdf.Cell(0, 6, fmt.Sprintf("▸ %s", currentIntegration))
			pdf.SetXY(20, pdf.GetY()+7)
		}

		y := pdf.GetY()

		// status pill
		pillColor := colorPass
		pillText := "PASS"
		if f.Status == engine.StatusFail {
			pillColor = colorFail
			pillText = "FAIL"
		} else if f.Status == engine.StatusSkip {
			pillColor = colorSkip
			pillText = "SKIP"
		}

		setFillHex(pdf, pillColor)
		pdf.RoundedRect(20, y, 12, 5, 1, "1234", "F")
		pdf.SetFont("Helvetica", "B", 6)
		setTextHex(pdf, "#ffffff")
		pdf.SetXY(20, y+0.5)
		pdf.CellFormat(12, 4, pillText, "", 0, "C", false, 0, "")

		// severity badge for failures
		if f.Status == engine.StatusFail && f.Severity != "" {
			sevColor := colorMedium
			if f.Severity == engine.SeverityCritical {
				sevColor = colorCrit
			} else if f.Severity == engine.SeverityHigh {
				sevColor = colorHigh
			}
			setFillHex(pdf, sevColor)
			pdf.RoundedRect(34, y, 16, 5, 1, "1234", "F")
			pdf.SetFont("Helvetica", "B", 6)
			setTextHex(pdf, "#ffffff")
			pdf.SetXY(34, y+0.5)
			pdf.CellFormat(16, 4, strings.ToUpper(string(f.Severity)), "", 0, "C", false, 0, "")
		}

		// title
		pdf.SetFont("Helvetica", "", 9)
		setTextHex(pdf, colorText)
		pdf.SetXY(54, y+0.5)
		pdf.CellFormat(136, 4, truncatePDF(f.Title, 80), "", 0, "L", false, 0, "")

		// control refs
		if len(f.Controls) > 0 {
			refs := []string{}
			for _, c := range f.Controls {
				refs = append(refs, fmt.Sprintf("%s %s", strings.ToUpper(string(c.Framework)), c.ID))
			}
			pdf.SetFont("Helvetica", "", 7)
			setTextHex(pdf, colorMuted)
			pdf.SetXY(54, y+5)
			pdf.Cell(0, 4, strings.Join(refs, "  ·  "))
			pdf.SetXY(20, y+10)
		} else {
			pdf.SetXY(20, y+7)
		}
	}

	// ── Remediation section ─────────────────────────────────────────
	hasFixes := false
	for _, f := range result.Findings {
		if f.Status == engine.StatusFail && f.Remediation != "" {
			hasFixes = true
			break
		}
	}

	if hasFixes {
		pdf.AddPage()
		pdf.SetFont("Helvetica", "B", 13)
		setTextHex(pdf, colorText)
		pdf.SetXY(20, 20)
		pdf.Cell(0, 8, "Remediation Steps")
		pdf.SetXY(20, 30)

		i := 1
		for _, f := range result.Findings {
			if f.Status != engine.StatusFail || f.Remediation == "" {
				continue
			}
			if pdf.GetY() > 240 {
				pdf.AddPage()
				pdf.SetXY(20, 20)
			}

			y := pdf.GetY()

			// number circle
			setFillHex(pdf, colorBrand)
			pdf.Circle(24, y+4, 3.5, "F")
			pdf.SetFont("Helvetica", "B", 8)
			setTextHex(pdf, "#ffffff")
			pdf.SetXY(20.5, y+1.5)
			pdf.CellFormat(7, 5, fmt.Sprintf("%d", i), "", 0, "C", false, 0, "")

			// title
			pdf.SetFont("Helvetica", "B", 9)
			setTextHex(pdf, colorText)
			pdf.SetXY(30, y+1)
			pdf.Cell(0, 5, truncatePDF(f.Title, 90))

			// remediation steps
			pdf.SetFont("Courier", "", 7.5)
			setTextHex(pdf, colorMuted)
			pdf.SetXY(30, y+7)
			for _, line := range strings.Split(f.Remediation, "\n") {
				if pdf.GetY() > 270 {
					pdf.AddPage()
					pdf.SetXY(30, 20)
				}
				pdf.Cell(0, 4, line)
				pdf.SetXY(30, pdf.GetY()+4)
			}

			pdf.SetXY(20, pdf.GetY()+4)
			i++
		}
	}

	// ── Footer on all pages ─────────────────────────────────────────
	pdf.SetFooterFunc(func() {
		pdf.SetY(-15)
		pdf.SetFont("Helvetica", "I", 8)
		setTextHex(pdf, colorMuted)
		pdf.CellFormat(0, 10, fmt.Sprintf("ComplyKit  ·  %s  ·  Page %d", strings.ToUpper(framework), pdf.PageNo()), "", 0, "C", false, 0, "")
	})

	return pdf.OutputFileAndClose(path)
}

func truncatePDF(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
