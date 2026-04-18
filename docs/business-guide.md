# ComplyKit Business Guide
### For a developer who has never run a business before

---

## Start Here — The One Thing to Understand

As a developer, your instinct is:
> "If my code is public, anyone can use it for free, so how do I make money?"

This instinct is wrong for software businesses. Here is the correct mental model:

> **People don't pay for code. They pay for outcomes.**

Nobody buys Microsoft Word because they want the `.exe` file.
They buy it because they want to write documents without learning LaTeX.

Nobody will pay you for the Go files in your GitHub repo.
They will pay you because **you save them 3 months of work and $25,000 in audit fees**.

That is what you are selling. Not code.

---

## Part 1 — What is the Open-Core Model?

"Open-core" means: **some features are free and open source, some features are paid**.

Think of it like a gym:

```
Free (Open Source)              Paid (Pro Membership)
──────────────────              ──────────────────────
You can exercise outside        Air conditioning
You can do push-ups at home     Equipment
You can run on the street       Showers
                                Personal trainer
                                Classes
                                24/7 access
```

The gym doesn't worry that you can exercise for free outside.
Because the people who pay are the ones who want **convenience, reliability, and results**.

For ComplyKit it works exactly the same way:

```
Free CLI (Open Source)          Pro Plan ($299/mo)
──────────────────────          ──────────────────
Runs on your laptop             Runs on our servers
You manage it yourself          We manage it for you
Only you can see it             Your whole team + auditor can see it
Manual sharing                  Automatic alerts + share links
No guarantee of uptime          Always on, always scanning
```

---

## Part 2 — Why Making the Code Public HELPS You Make Money

This feels backwards. Let me prove it with a story.

### The Story of Sentry

Sentry is a company that catches software errors. Their entire code is on GitHub.
Anyone can download it, run it on their own server, for free, forever.

**Result:** Sentry makes $200 million per year.

How? Because:

1. **Engineers found it on GitHub** → trusted it → brought it to their company
2. **Companies don't want to run their own server** → they pay Sentry to host it
3. **Competitors copied the code** → but couldn't copy the brand, trust, or customer relationships

### How This Applies to ComplyKit

Right now, if you keep the repo private:
- Engineers cannot find ComplyKit on Google or GitHub
- Engineers cannot evaluate it before buying
- Engineers cannot trust it (black box handling their AWS credentials)
- Homebrew installation does not work
- You have to spend money on ads to get anyone to hear about you

If you make it public:
- Engineers find it by searching "SOC2 CLI" or "compliance scanner"
- They star it, try it on their own laptop, trust it
- They go to their CTO and say "I found this tool, we should use the Pro version"
- You get customers without spending a rupee on marketing

**The code is your marketing. The hosted service is your product.**

---

## Part 3 — What Exactly Are You Selling?

You have three things to sell. Each one solves a different pain.

---

### Thing 1 — Free CLI
**Price:** Free
**Who uses it:** Solo engineers, students, people evaluating

**What it does:**
- Scans their AWS/GCP/GitHub on their own laptop
- Shows them what is failing
- Tells them how to fix it
- Generates a PDF report locally

**Why it is free:**
- It is your advertisement
- It runs on THEIR computer, costs YOU nothing
- Every person who uses it is a potential paying customer

**What it cannot do:**
- It stops working when their laptop is closed
- Only they can see the results
- They cannot share it with their auditor easily
- Their teammates cannot see it

This is the moment they need to upgrade.

---

### Thing 2 — Pro Plan ($299/month)
**Price:** $299/month (~₹25,000/month)
**Who buys it:** Startups preparing for SOC2, CTOs who need to share results with auditors

**What it does that the free CLI cannot:**

**A) Hosted Dashboard**
The free CLI runs `comply serve` only on localhost — meaning only they can see it on their own computer. Pro hosts the dashboard on your servers, so they can open it from any browser, anywhere, share the URL with their team.

**B) Auditor Share Links**
When an auditor says "show me your compliance status", with the free CLI they have to email a PDF. With Pro, they run `comply share` and get a link like:
```
https://app.complykit.io/share/eyJhbGciO...
```
They send this to the auditor. The auditor opens it in their browser. It shows the scan results, the evidence, the score. Read-only, auto-expires in 30 days. Professional. No email attachments.

**C) Cloud Evidence Vault**
Free CLI saves evidence on their laptop. If the laptop dies, evidence is gone. Pro saves evidence on your servers — accessible by the whole team, safe forever.

**D) Slack/Email Alerts**
Free CLI shows results when you run a command. Pro sends a Slack message the moment something fails:
```
⚠️ ComplyKit Alert: 2 regressions detected
Score: 68/100 (-4)
• aws_iam_console_mfa [high] — 3 users lost MFA
• github_branch_protection [high] — new repo missing protection
Run `comply fix` for remediation steps.
```

**E) Hosted Watch Mode**
Free CLI `comply watch` only runs while their laptop is open. Pro runs it on your servers 24/7 — they don't need to keep anything running.

**Why $299/month?**
- Vanta charges $2,000/month for similar features
- If ComplyKit helps them close ONE enterprise deal worth $50,000/year, $299/month costs them $3,588/year — a 14x return
- If it saves them 10 hours of manual compliance work per month, at $100/hour that is $1,000 saved for $299 spent

---

### Thing 3 — Team Plan ($799/month)
**Price:** $799/month (~₹66,000/month)
**Who buys it:** Startups in active SOC2 Type 2 audit window, companies with compliance teams

**Additional features:**
- Unlimited team members (Pro is limited to 5)
- Scan multiple AWS accounts at once
- Multiple frameworks simultaneously (SOC2 + HIPAA at the same time)
- Custom compliance controls
- Access review tracking with sign-off workflow
- Direct audit firm integration portal

---

## Part 4 — Who Are Your Customers?

You are not selling to everyone. You are selling to a very specific person.

### The Ideal Customer

**Company type:** B2B SaaS startup
**Size:** 10–100 employees
**Stage:** Seed to Series B (just raised money, $1M–$20M in the bank)
**Problem:** An enterprise customer said "we need your SOC2 report before we can sign"
**Urgency:** HIGH — a real deal is blocked right now

**The person who buys:**
- Title: CTO, VP Engineering, or Head of Security
- Age: 28–40
- Background: Developer who became a manager
- Pain: They have never done SOC2 before, they are scared of it, they do not know where to start

**What they are thinking:**
> "We have a $100k deal that requires SOC2. Vanta costs $20k/year. We cannot afford that. But we need SOMETHING to show the customer. We are a small team, I cannot spend 3 months on this."

That person is your customer. ComplyKit at $299/month is the obvious answer for them.

---

## Part 5 — How Do You Find Customers?

As a developer, selling feels uncomfortable. Here is the good news: you do not need to "sell" in the traditional sense. You need to be findable by the people who already have the problem.

### Channel 1 — GitHub (Free, Powerful)

When you make the repo public, people searching for "SOC2 CLI" or "compliance scanner golang" will find it.

**What to do:**
- Add topics to the repo: `soc2`, `compliance`, `security`, `hipaa`, `aws`, `golang`, `devtools`
- Write a great README (already done)
- Respond to every issue and PR within 24 hours
- Star count builds trust — 100 stars = credible, 1000 stars = serious

**How it converts:**
Engineer finds repo → tries free CLI → likes it → tells CTO → CTO signs up for Pro.

---

### Channel 2 — Hacker News (Free, High Impact)

Hacker News (news.ycombinator.com) is read by every startup CTO and developer.
A successful "Show HN" post can bring 500–2,000 visitors in one day.

**What to post:**
```
Show HN: ComplyKit — SOC2 compliance scanning in one CLI command

We built an open-source CLI that scans your AWS, GCP, and GitHub
against SOC2/HIPAA/CIS controls and tells you exactly what to fix.

comply scan --framework soc2

[link to github]
```

**When to post:** Tuesday or Wednesday, 9am–12pm US Eastern time.

**What happens if it works:** Hundreds of engineers try it, some become paying customers, you get feedback to improve the product.

---

### Channel 3 — Dev Communities (Free, Consistent)

Post in communities where your customers hang out:

| Community | What to share |
|-----------|--------------|
| r/devops | "Built a free SOC2 scanner CLI" |
| r/aws | "Open source AWS compliance checker" |
| r/netsec | "SOC2/CIS scanning tool for startups" |
| Dev.to | Write a tutorial: "How to prepare for SOC2 in 30 days" |
| LinkedIn | Post your compliance score improving week over week |

---

### Channel 4 — Content / SEO (Free, Long-term)

People Google things like:
- "how to get SOC2 certification"
- "SOC2 checklist for startups"
- "AWS SOC2 requirements"
- "how much does SOC2 cost"

If you write detailed articles answering these questions (and link to ComplyKit), you get free traffic from Google forever.

**Article ideas:**
- "SOC2 for Startups: Complete Guide (2026)"
- "AWS SOC2 Checklist: 40 Controls Explained"
- "How We Got SOC2 Type 1 in 60 Days"
- "Vanta vs DIY: Which SOC2 Approach is Right for You?"

You can publish these on your website, Dev.to, or Medium.

---

### Channel 5 — Cold Outreach (Requires effort, high conversion)

Find startups that:
- Just raised a Seed or Series A round (search Crunchbase, TechCrunch)
- Are B2B SaaS (need SOC2 to sell to enterprises)
- Have 10–50 engineers

Send a short, honest email to the CTO:

```
Subject: SOC2 blocking deals?

Hi [Name],

Saw that [Company] just raised [amount] — congrats.

Common next step for B2B SaaS at your stage is SOC2.
Vanta/Drata are $20k+/year, which is a lot when you're 
still finding product-market fit.

We built ComplyKit — open source CLI that scans your AWS/GitHub 
for SOC2 gaps and tells you exactly what to fix.
Free to try, Pro is $299/mo.

[GitHub link]

Worth 10 minutes?

Jagdish
```

Short. Honest. No pressure. You are offering to solve a real problem they definitely have.

---

## Part 6 — How Does Money Actually Flow?

Here is exactly how revenue works, step by step.

### Step 1 — They discover ComplyKit
GitHub, Hacker News, Google, a friend told them.

### Step 2 — They try the free CLI
```bash
brew install nuvlabs/tap/complykit
comply scan --framework soc2
```
Takes 5 minutes. They see their compliance score. They see what is failing.

### Step 3 — They hit the wall
They want to:
- Share results with their auditor
- Set up alerts for their team
- Keep it running while their laptop is closed

The CLI says: "This feature is available in ComplyKit Pro."

### Step 4 — They visit your website
They go to `complykit.io` (your future website).
They see the Pro features. They see $299/month.
They compare this to the $25,000 Vanta quote they got last week.
They click "Start Free Trial."

### Step 5 — They enter their credit card
Stripe (payment processor) handles this. You set up a Stripe account.
Money goes from their card → Stripe → your bank account.
Stripe takes ~2.9% + $0.30 per transaction.

### Step 6 — They get access to Pro
Your backend (which we will build) sees the payment confirmed → activates their Pro account → they can now access the hosted dashboard, share links, alerts.

### Step 7 — They stay every month
As long as they are preparing for or maintaining SOC2, they need ComplyKit.
SOC2 Type 2 requires ongoing monitoring for 6–12 months.
One customer = $299 × 12 = $3,588 per year minimum.

---

## Part 7 — The Numbers: What Does Success Look Like?

### Month 1–3 (Early days)
- Goal: 5 paying customers
- Revenue: 5 × $299 = $1,495/month (~₹1.25 lakh/month)
- Focus: Talk to every customer, understand their problems, improve the product

### Month 4–6
- Goal: 20 paying customers
- Revenue: 20 × $299 = $5,980/month (~₹5 lakh/month)
- Focus: Fix what customers complain about, start content marketing

### Month 7–12
- Goal: 50 paying customers (mix of Pro and Team)
- Revenue: 40 × $299 + 10 × $799 = $11,960 + $7,990 = ~$20,000/month (~₹16.5 lakh/month)
- This is $240,000/year ARR — enough to quit your job comfortably

### Year 2
- Goal: 150 paying customers
- Revenue: ~$60,000/month (~$720,000/year ARR)
- This is the point where you hire your first employee

### What makes these numbers realistic?
- There are ~50,000 startups pursuing SOC2 in the US every year
- You only need 150 of them (0.3%) to hit $720k ARR
- Vanta has thousands of customers — the market exists and is large

---

## Part 8 — What You Need to Build for Pro

The free CLI is done. Here is what the Pro backend needs:

### Infrastructure (what runs on your server)

**1. Authentication system**
- Users sign up with email + password or Google/GitHub OAuth
- Each user belongs to a team
- Teams have a plan (Free, Pro, Team)

**2. Hosted dashboard server**
- The same `comply serve` but running on YOUR server, not their laptop
- Connected to cloud evidence vault instead of local files
- Accessible at `app.complykit.io`

**3. Cloud evidence vault**
- PostgreSQL database storing scan records
- Files stored in S3 or similar
- Each team's data is isolated from others

**4. Share link service**
- Already built in the CLI (JWT tokens)
- Backend just needs to validate the token and serve the record

**5. Alert service**
- Background job that runs `comply scan` on a schedule for each Pro team
- Compares results to previous scan
- Sends Slack/email on regression

**6. Billing (Stripe)**
- Stripe Checkout for payment
- Stripe webhooks to activate/deactivate accounts
- Billing portal for customers to manage their subscription

### Technology choices (simple is better)
- **Backend:** Go (same as CLI) or Python/FastAPI
- **Database:** PostgreSQL (simple, reliable)
- **File storage:** AWS S3 or Cloudflare R2
- **Payments:** Stripe (industry standard, easy to integrate)
- **Hosting:** Railway, Render, or Fly.io (cheap, low maintenance)
- **Domain:** complykit.io (check availability)

---

## Part 9 — Timeline: What to Do and When

### Right Now (This Week)
- [ ] Make `nuvlabs/complykit` repo public on GitHub
- [ ] Register `complykit.io` domain (or `getcomplykit.com`)
- [ ] Create a Stripe account at stripe.com
- [ ] Post "Show HN" on Hacker News

### Month 1
- [ ] Build a simple landing page at your domain (even one page is enough)
- [ ] Post in r/devops and r/aws
- [ ] Write one blog post: "SOC2 for Startups: What You Actually Need"
- [ ] Talk to 10 potential customers (email CTOs of recently funded startups)
- [ ] Goal: 3 paying customers, even if you onboard them manually

### Month 2–3
- [ ] Build the Pro backend (hosted dashboard + billing)
- [ ] Set up automated Stripe checkout
- [ ] Launch Pro publicly
- [ ] Goal: 10 paying customers

### Month 4–6
- [ ] Add Slack/email alerts to Pro backend
- [ ] Write more content for SEO
- [ ] Respond to GitHub issues quickly (builds community trust)
- [ ] Goal: 25 paying customers

---

## Part 10 — The One Thing That Kills Developer Businesses

Most developers who try to build a business fail for ONE reason:

> **They build features instead of talking to customers.**

It feels natural. Building is what you know. Talking to strangers is uncomfortable.

But if you spend 3 months building features nobody asked for, you will run out of motivation and money.

**The right approach in month 1:**

Do not build the Pro backend yet. Instead:
1. Find 5 people who have the problem (SOC2 requirement blocking a deal)
2. Give them access to the free CLI
3. Ask: "What would make you pay $299/month?"
4. Listen. Do not pitch. Just listen.
5. Build ONLY what they ask for, nothing else

If 3 out of 5 say "I would pay $299/month if you built [X]", build X.
If they say "I would not pay $299/month for anything", you need to rethink pricing or features.

This saves you months of building the wrong thing.

---

## Summary: The Simple Version

1. **Make the repo public** — it is your advertisement, not your product
2. **The product is the hosted service** — dashboard, alerts, share links, team features
3. **Charge $299/month for Pro** — it pays for itself if it unblocks one deal
4. **Find customers by being findable** — GitHub, Hacker News, SEO, cold email
5. **Talk to customers before building** — build what they ask for, nothing else
6. **You only need 50 customers to make a good living** — the market has millions

The code is already built. The hard part is not the code.
The hard part is finding the first 10 customers who pay you money.
Everything else follows from that.
