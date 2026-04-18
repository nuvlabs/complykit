# ComplyKit — Idea & Vision

## The Problem

Startups hit a deal-blocker wall — an enterprise customer sends a security questionnaire
or demands a SOC2 report. The startup has two options:

1. Pay $30–80k + 6 months for a traditional audit firm
2. Lose the deal

Existing tools (Vanta, Drata, Secureframe) cost $15–30k/year and are built for companies
that already have a dedicated compliance team. Small teams (5–50 people) are completely
underserved.

---

## The Solution

**ComplyKit** is a code-first compliance tool for small engineering teams.

Instead of a checkbox-heavy UI, it meets engineers where they are — the terminal.
A single CLI command scans your infra and maps findings to SOC2/HIPAA/ISO controls,
giving you a prioritized remediation list and an audit-ready evidence vault.

---

## Differentiation

| Feature                  | Vanta / Drata       | ComplyKit             |
|--------------------------|---------------------|-----------------------|
| Price                    | $15–30k/year        | $3–10k/year           |
| Target audience          | 50–500 person teams | 5–50 person startups  |
| Onboarding               | Weeks               | Minutes (CLI scan)    |
| Engineer-friendly        | No                  | Yes (CLI + IaC)       |
| Open source scanner      | No                  | Yes                   |

---

## Core Value Proposition

> "Run one command. Know exactly what's blocking your SOC2 audit. Fix it in days, not months."

---

## The Moat

The real defensible asset is the **control mapping library**:

- Maps infra findings → SOC2 / HIPAA / ISO 27001 controls
- Example: "S3 bucket public access block disabled" → SOC2 CC6.1, CC6.6 + HIPAA §164.312(a)
- Tedious to build, hard to replicate, grows more valuable over time

---

## Target Customer

- Seed to Series B startups
- Engineering-led companies (no dedicated compliance team)
- Pursuing SOC2 Type 1 or Type 2 for the first time
- Blocked on a deal because of missing compliance certification

---

## Revenue Potential

- 100 customers at avg $5k/year = **$500k ARR**
- 500 customers at avg $5k/year = **$2.5M ARR**
- TAM: ~50,000 startups pursuing SOC2 in the US annually
