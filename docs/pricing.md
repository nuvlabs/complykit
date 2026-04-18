# ComplyKit Pricing

## Free CLI (Open Source)

> For individual engineers and small teams who want to understand their compliance
> posture without paying for a platform.

**What you get:**

| Feature | Details |
|---------|---------|
| `comply scan` | Unlimited scans — AWS, GCP, GitHub |
| Frameworks | SOC2, HIPAA, CIS (all three) |
| Terminal output | Color-coded pass/fail with severity |
| `comply fix` | Step-by-step remediation for every failure |
| JSON report | `--output report.json` |
| PDF report | `--output report.pdf` (auditor-ready) |
| `comply policy generate` | 5 SOC2 policy document templates |
| Local evidence vault | Auto-saved scan history on your machine |
| `comply evidence list/show` | Browse past scans locally |
| `comply watch` | Re-scan on a schedule, print regressions |
| Local web dashboard | `comply serve` on localhost only |
| Single user | One machine, one engineer |
| Open source | Apache 2.0 — fork, modify, self-host |

**What you don't get:**
- Hosted dashboard (accessible from anywhere, not just your laptop)
- Auditor share links
- Slack / email alerts on regressions
- Team access (multiple engineers)
- Cloud evidence vault (survives laptop loss)
- Priority support

**Who it's for:**
- Solo founders or CTOs doing a first compliance pass
- Engineers evaluating before buying
- Teams that want to self-host everything

---

## Pro — $299/month

> For startups actively preparing for SOC2 audit, with an auditor to report to
> and a team to keep accountable.

**Everything in Free CLI, plus:**

| Feature | Details |
|---------|---------|
| **Hosted dashboard** | Accessible from any browser — not just localhost |
| **Auditor share links** | `comply share` — JWT-signed, read-only, auto-expiring links you send to your auditor |
| **Cloud evidence vault** | Scan records stored securely in the cloud — survives machine changes, accessible by whole team |
| **Slack alerts** | Instant notification when a passing check regresses |
| **Email alerts** | Daily/weekly digest + immediate regression alerts |
| **Team seats** | Up to 5 engineers — all see the same dashboard and evidence vault |
| **Continuous watch** | `comply watch` runs as a hosted service — no need to keep your laptop open |
| **Audit export** | One-click export of all evidence + reports in auditor-ready format |
| **Priority support** | Response within 1 business day |

**Who it's for:**
- Startups that have received a SOC2 request from a customer
- CTOs who need to share progress with an auditor
- Teams where more than one engineer owns compliance

---

## Team — $799/month

> For companies in active SOC2 Type 2 observation window or managing multiple
> frameworks simultaneously.

**Everything in Pro, plus:**

| Feature | Details |
|---------|---------|
| **Unlimited team seats** | Whole engineering team |
| **Multiple frameworks** | SOC2 + HIPAA + CIS simultaneously, separate scores |
| **Multiple AWS accounts** | Scan all your accounts in one dashboard |
| **Custom controls** | Add your own checks specific to your stack |
| **Policy management** | Track policy document versions and review cycles |
| **Access review tracking** | Quarterly access reviews with reminders and sign-off |
| **Audit firm integration** | Direct evidence sharing portal for your auditor |
| **SLA** | 99.9% uptime, 4-hour support response |

---

## Comparison

| | Free CLI | Pro ($299/mo) | Team ($799/mo) |
|---|---|---|---|
| Scan: AWS / GCP / GitHub | ✓ | ✓ | ✓ |
| Frameworks (SOC2, HIPAA, CIS) | ✓ | ✓ | ✓ |
| Terminal + JSON + PDF output | ✓ | ✓ | ✓ |
| Policy document templates | ✓ | ✓ | ✓ |
| `comply fix` remediation | ✓ | ✓ | ✓ |
| Local evidence vault | ✓ | ✓ | ✓ |
| Local dashboard (`localhost`) | ✓ | ✓ | ✓ |
| **Hosted dashboard (any browser)** | — | ✓ | ✓ |
| **Auditor share links** | — | ✓ | ✓ |
| **Cloud evidence vault** | — | ✓ | ✓ |
| **Slack / email alerts** | — | ✓ | ✓ |
| **Hosted `comply watch`** | — | ✓ | ✓ |
| **Team seats** | 1 | 5 | Unlimited |
| **Multiple AWS accounts** | — | — | ✓ |
| **Multiple frameworks simultaneously** | — | — | ✓ |
| **Custom controls** | — | — | ✓ |
| **Audit firm portal** | — | — | ✓ |
| Support | GitHub issues | 1 business day | 4 hours |

---

## FAQ

**Can I self-host the Pro features?**
Yes. ComplyKit is Apache 2.0. You can run `comply serve` on your own server and
get the hosted dashboard for free. Pro is for teams who don't want to manage
infrastructure.

**Do I need Pro to get a SOC2 audit?**
No. The Free CLI generates PDF reports and policy documents that auditors accept.
Pro makes the process faster and less manual — especially for sharing evidence
with your auditor and keeping your team aligned.

**When should I upgrade from Free to Pro?**
When an auditor or enterprise customer asks for evidence and you need to share
it with them — that's the moment. `comply share` alone is worth $299/mo if it
unblocks a $50k deal.

**Is there an annual discount?**
Yes — 2 months free on annual plans:
- Pro annual: $2,990/year (save $598)
- Team annual: $7,990/year (save $1,598)
