# ComplyKit — Code Deep Dive
### For someone new to Go, explaining every piece line by line

---

## How to Read This Document

Every section follows this pattern:
1. Show the actual code
2. Explain what it means in plain English
3. Explain the Go concept being used

If you are completely new to Go, read Part 0 first.
If you know basic programming but not Go, skip to Part 1.

---

## Part 0 — Go Basics You Need to Know First

Before reading the code, understand these 6 Go concepts.
Everything in the project uses only these ideas.

---

### Concept 1 — Package

Every Go file starts with `package something`.
A package is just a folder of related code.

```go
package engine
```

This means: "this file belongs to the engine package".
Other files can use this code by importing it.

Think of packages like drawers in a cabinet.
- `engine` drawer → core data types
- `aws` drawer → AWS scanning code
- `cmd` drawer → CLI command code

---

### Concept 2 — Struct (like a class in other languages)

A struct is a container that holds related data together.

```go
type Finding struct {
    CheckID  string   // text
    Title    string   // text
    Status   Status   // pass/fail/skip
    Severity Severity // critical/high/medium/low
}
```

Think of a struct like a form with fields.
A `Finding` is like a filled-in inspection form:
- CheckID: "aws_iam_root_mfa"
- Title: "Root account MFA not enabled"
- Status: "fail"
- Severity: "critical"

---

### Concept 3 — Function

```go
func greet(name string) string {
    return "Hello " + name
}
```

`func` = start of a function
`greet` = name of the function
`name string` = input: a text variable called name
`string` (after the parentheses) = output type: returns text
`return` = send this value back to whoever called the function

---

### Concept 4 — Method (a function attached to a struct)

```go
func (r *ScanResult) Add(f Finding) {
    r.Findings = append(r.Findings, f)
}
```

This is a function BUT it belongs to `ScanResult`.
The `(r *ScanResult)` part means "this function is attached to ScanResult".
You call it like: `result.Add(myFinding)`

The `*` means you are working with a pointer (the real object, not a copy).
Without `*`, changes inside the function would not affect the original.

---

### Concept 5 — Interface (a contract/promise)

```go
type Checker interface {
    Run() ([]Finding, error)
    Integration() string
}
```

An interface says: "any type that has these methods is a Checker".

It does NOT contain any code. It is just a promise.
Any struct that has both `Run()` and `Integration()` methods
automatically becomes a Checker — no extra work needed.

This lets you write one piece of code that works with
AWS checkers, GCP checkers, and GitHub checkers
all in the same way, even though they are completely different.

---

### Concept 6 — Error handling

In Go, functions return errors as a second value:

```go
result, err := doSomething()
if err != nil {
    // something went wrong
    return err
}
// if we reach here, err is nil = no error
```

`nil` means "nothing" / "empty" / "no error".
You check `if err != nil` after every operation that could fail.
This is Go's way of handling errors — very explicit, no surprises.

---

## Part 1 — The Entry Point: `main.go`

```go
package main

import "github.com/complykit/complykit/cmd"

func main() {
    cmd.Execute()
}
```

**What this does:**
This is the first thing Go runs when you type `comply scan`.
It has exactly 3 lines of real code.

**Line by line:**

`package main` — This tells Go "this is the starting package".
Go always looks for a file with `package main` and a `func main()` to start.

`import "github.com/..."` — This loads the `cmd` package (our CLI commands).
The URL-looking string is just the package's unique name — it is not a website.

`cmd.Execute()` — Calls the Execute function from the cmd package.
That function reads what you typed (`comply scan`, `comply fix`, etc.)
and runs the right code.

**Think of it like:**
`main.go` is the front door of the building.
When you walk in, it immediately sends you to `cmd.Execute()`
which figures out which room (command) you need.

---

## Part 2 — The Core Data Types: `internal/engine/types.go`

This file defines the "language" the entire project speaks.
Every other file uses these types.

---

### Section A — Custom string types

```go
type Severity string

const (
    SeverityCritical Severity = "critical"
    SeverityHigh     Severity = "high"
    SeverityMedium   Severity = "medium"
    SeverityLow      Severity = "low"
)
```

**What this does:**
`Severity` is a new type that is BASED on string but is its own thing.

Why not just use plain strings?
Because if you use plain strings, someone could accidentally write:
```go
finding.Severity = "CRITICAL"  // wrong capitalisation
finding.Severity = "high risk" // wrong format
```

With a custom type, Go catches this mistake at compile time:
```go
finding.Severity = SeverityCritical  // correct — Go is happy
finding.Severity = "critical"        // Go shows error — use the constant
```

Same pattern is used for `Status` (pass/fail/skip) and `Framework` (soc2/hipaa/cis).

---

### Section B — ControlRef struct

```go
type ControlRef struct {
    Framework Framework
    ID        string
}
```

**What this does:**
This is a small container that holds one compliance control reference.
Example: SOC2 control CC6.1, or HIPAA section 164.312(d).

Used like:
```go
ControlRef{Framework: FrameworkSOC2, ID: "CC6.1"}
```

In human terms: "this finding relates to SOC2 control CC6.1".

---

### Section C — The Finding struct

```go
type Finding struct {
    CheckID     string      // "aws_iam_root_mfa"
    Title       string      // "Root account MFA not enabled"
    Status      Status      // pass / fail / skip
    Severity    Severity    // critical / high / medium / low
    Integration string      // "AWS/IAM"
    Resource    string      // "root" or "3 buckets"
    Detail      string      // extra info (used for skip reason)
    Remediation string      // how to fix it
    Controls    []ControlRef // which SOC2/HIPAA controls this maps to
}
```

**What this does:**
A `Finding` is the result of ONE check.
When we check "is root MFA enabled?", the answer becomes a Finding.

`[]ControlRef` means "a list of ControlRef".
The `[]` in front of any type means "slice" (Go's word for a list/array).

**Think of it like:**
A Finding is one row in an audit report:
```
| CHECK ID          | TITLE                        | STATUS | SEVERITY |
| aws_iam_root_mfa  | Root account MFA not enabled | fail   | critical |
```

---

### Section D — The ScanResult struct

```go
type ScanResult struct {
    Findings []Finding  // list of all findings
    Passed   int        // count of passing checks
    Failed   int        // count of failing checks
    Skipped  int        // count of skipped checks
    Score    int        // 0-100 score
}
```

**What this does:**
After running ALL checks, all the individual Findings are collected
into one ScanResult. This is what gets printed to terminal,
saved as JSON, saved as PDF, and stored in the evidence vault.

---

### Section E — The Add method

```go
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
```

**What this does:**
Every time a checker produces a Finding, we call `result.Add(finding)`.
This function does three things:

1. Adds the finding to the list: `append(r.Findings, f)`
   `append` adds an item to a slice (list). It returns the new list.

2. Increments the right counter using `switch`:
   `switch` is like if/else but cleaner for multiple cases.
   `r.Passed++` means "add 1 to Passed". Same as `r.Passed = r.Passed + 1`.

3. Recalculates the score:
   Score = (passed ÷ total) × 100
   Note: skipped checks do NOT count in the total.
   So if 9 pass, 4 fail, 1 skip → score = (9 ÷ 13) × 100 = 69

---

### Section F — The Checker interface

```go
type Checker interface {
    Run() ([]Finding, error)
    Integration() string
}
```

**What this does:**
This is the most important design decision in the project.

ANY struct that has these two methods becomes a Checker:
- `Run()` — does the actual scan, returns findings
- `Integration()` — returns the name like "AWS/IAM" or "GitHub"

The AWS checker, GCP checker, and GitHub checker are all
completely different code, but they all satisfy this interface.

**Why this matters:**
In `scan.go`, we can write ONE loop that works for all of them:

```go
checkers := []engine.Checker{
    awschecks.NewIAMChecker(cfg),   // AWS checker
    awschecks.NewS3Checker(cfg),    // also AWS checker
    ghchecks.NewChecker(token, org), // GitHub checker
}

for _, checker := range checkers {
    findings, err := checker.Run()  // same call for all
    ...
}
```

Without the interface, we would need separate code for each.
With the interface, adding a new cloud provider (Azure, etc.)
just means creating a new struct with Run() and Integration() — nothing else changes.

---

## Part 3 — An AWS Checker: `internal/checks/aws/iam.go`

This file scans AWS IAM (Identity and Access Management).

---

### Section A — The struct and constructor

```go
type IAMChecker struct {
    client *iam.Client
}

func NewIAMChecker(cfg aws.Config) *IAMChecker {
    return &IAMChecker{client: iam.NewFromConfig(cfg)}
}
```

**What this does:**

`IAMChecker` is a struct that holds ONE thing: an AWS IAM client.
The client is the object that knows how to talk to AWS's API.

`NewIAMChecker` is a constructor function — it builds and returns
a new IAMChecker. In Go, constructors are just regular functions
that start with `New`.

`iam.NewFromConfig(cfg)` creates the AWS client using your credentials.
The `cfg` (configuration) came from your `~/.aws/credentials` file
or environment variables like `AWS_ACCESS_KEY_ID`.

`&IAMChecker{...}` — the `&` means "give me a pointer to this".
A pointer is like a street address — instead of copying the whole house,
you just pass the address so everyone works with the same house.

---

### Section B — The Run method

```go
func (c *IAMChecker) Run() ([]engine.Finding, error) {
    var findings []engine.Finding

    findings = append(findings, c.checkRootMFA()...)
    findings = append(findings, c.checkPasswordPolicy()...)
    findings = append(findings, c.checkUnusedCredentials()...)
    findings = append(findings, c.checkConsoleMFA()...)

    return findings, nil
}
```

**What this does:**
This is the main entry point. It calls all the individual check functions
and collects their findings into one list.

`var findings []engine.Finding` — creates an empty list of findings.
`var` declares a variable. `[]engine.Finding` means "list of Finding".

`c.checkRootMFA()...` — calls the checkRootMFA function.
The `...` at the end means "spread this list into individual items".
It is needed because `checkRootMFA` returns a list, and `append`
needs individual items, not a list inside a list.

`return findings, nil` — returns the collected findings + no error.
`nil` means "no error happened".

---

### Section C — A real check function

```go
func (c *IAMChecker) checkRootMFA() []engine.Finding {
    out, err := c.client.GetAccountSummary(context.Background(),
        &iam.GetAccountSummaryInput{})

    if err != nil {
        return []engine.Finding{skip("aws_iam_root_mfa", "Root MFA Enabled", err.Error())}
    }

    mfaActive := out.SummaryMap["AccountMFAEnabled"]
    if mfaActive == 1 {
        return []engine.Finding{pass("aws_iam_root_mfa", "Root account MFA enabled",
            "AWS/IAM", "root", soc2("CC6.1"), cis("1.5"))}
    }

    return []engine.Finding{fail(
        "aws_iam_root_mfa",
        "Root account MFA not enabled",
        "AWS/IAM", "root",
        SeverityCritical,
        "Enable MFA on the AWS root account...",
        soc2("CC6.1"), hipaa("164.312(d)"), cis("1.5"),
    )}
}
```

**What this does, step by step:**

**Step 1 — Call the AWS API:**
```go
out, err := c.client.GetAccountSummary(context.Background(), &iam.GetAccountSummaryInput{})
```
`c.client.GetAccountSummary` calls the real AWS API.
It asks AWS: "give me a summary of this account".
AWS responds with data stored in `out`, or an error stored in `err`.

`context.Background()` is Go's way of saying "no special timeout or cancellation".
Think of it as a mandatory form you have to fill in — most of the time it is blank.

`&iam.GetAccountSummaryInput{}` is an empty input struct.
This particular API call needs no extra parameters, so we send an empty struct.

**Step 2 — Handle the error:**
```go
if err != nil {
    return []engine.Finding{skip(...)}
}
```
If the API call failed (wrong credentials, no network, etc.),
we return a "skip" finding instead of crashing.
We never crash — we always return something useful.

**Step 3 — Read the result:**
```go
mfaActive := out.SummaryMap["AccountMFAEnabled"]
```
`SummaryMap` is a map (dictionary) returned by AWS.
`["AccountMFAEnabled"]` looks up the value for that key.
AWS returns `1` if MFA is enabled, `0` if not.

**Step 4 — Return pass or fail:**
```go
if mfaActive == 1 {
    return []engine.Finding{pass(...)}
}
return []engine.Finding{fail(...)}
```
Based on the value, we return either a pass or fail finding.

---

### Section D — Helper functions

```go
func pass(id, title, integration, resource string,
    controls ...engine.ControlRef) engine.Finding {
    return engine.Finding{
        CheckID:     id,
        Title:       title,
        Status:      engine.StatusPass,
        Integration: integration,
        Resource:    resource,
        Controls:    controls,
    }
}
```

**What this does:**
Instead of building a `Finding` struct manually every time,
these helpers (`pass`, `fail`, `skip`) do it for you.

`controls ...engine.ControlRef` — the `...` here means "variadic".
This function accepts zero OR many ControlRef values:
```go
pass("id", "title", "AWS", "root")                    // no controls
pass("id", "title", "AWS", "root", soc2("CC6.1"))     // one control
pass("id", "title", "AWS", "root", soc2("CC6.1"), cis("1.5")) // two controls
```

`soc2("CC6.1")` is a shortcut that creates a ControlRef:
```go
func soc2(id string) engine.ControlRef {
    return engine.ControlRef{Framework: engine.FrameworkSOC2, ID: id}
}
```

---

## Part 4 — The Scan Command: `cmd/scan.go`

This is the brain that runs when you type `comply scan`.

---

### Section A — Variables and command definition

```go
var (
    flagFramework string
    flagProfile   string
    flagRegion    string
    flagOutput    string
    flagPDF       string
    flagGHToken   string
    flagGHOwner   string
)

var scanCmd = &cobra.Command{
    Use:   "scan",
    Short: "Scan your infrastructure for compliance issues",
    RunE:  runScan,
}
```

**What this does:**

`var (...)` declares multiple variables at once.
These are "flag" variables — they store what the user typed.
For example: `comply scan --framework hipaa` sets `flagFramework = "hipaa"`.

`cobra.Command` is from the Cobra library — a popular Go library for building CLIs.
- `Use` — the command name
- `Short` — description shown in `--help`
- `RunE` — which function to call when this command runs

`RunE` (not `Run`) means the function can return an error.
If it returns an error, Cobra prints it and exits with code 1.

---

### Section B — The init function

```go
func init() {
    scanCmd.Flags().StringVarP(&flagFramework, "framework", "f", "soc2",
        "Compliance framework: soc2, hipaa, cis")
    scanCmd.Flags().StringVar(&flagProfile, "profile", "",
        "AWS profile...")
    rootCmd.AddCommand(scanCmd)
}
```

**What this does:**
`init()` is a special Go function. Go calls it automatically
before `main()` runs. We use it to register flags and commands.

`StringVarP(&flagFramework, "framework", "f", "soc2", "description")`
- `&flagFramework` — store the value in this variable
- `"framework"` — long flag name: `--framework`
- `"f"` — short flag name: `-f`
- `"soc2"` — default value if user does not specify
- `"description"` — shown in `--help`

`rootCmd.AddCommand(scanCmd)` — registers `scan` as a subcommand
of the root command (the `comply` command).

---

### Section C — The runScan function

```go
func runScan(cmd *cobra.Command, args []string) error {
    result := &engine.ScanResult{}

    cfg, err := config.LoadDefaultConfig(context.Background(), opts...)
    if err != nil {
        fmt.Fprintf(os.Stderr, "  warning: AWS credentials not found\n")
    } else {
        awsCheckers := []engine.Checker{
            awschecks.NewIAMChecker(cfg),
            awschecks.NewS3Checker(cfg),
            awschecks.NewCloudTrailChecker(cfg),
            awschecks.NewSecurityGroupChecker(cfg),
        }
        for _, checker := range awsCheckers {
            findings, err := checker.Run()
            for _, f := range findings {
                result.Add(f)
            }
        }
    }
    ...
}
```

**What this does, step by step:**

**Step 1:** `result := &engine.ScanResult{}`
Creates an empty ScanResult that we will fill up.
`{}` means "empty — use zero values for all fields".

**Step 2:** `config.LoadDefaultConfig(...)`
Loads your AWS credentials from:
1. `~/.aws/credentials` file
2. Environment variables (`AWS_ACCESS_KEY_ID`, etc.)
3. IAM role (if running on EC2)

**Step 3:** `[]engine.Checker{...}`
Creates a list (slice) of all AWS checkers.
All four items are Checkers because they all have `Run()` and `Integration()`.

**Step 4:** `for _, checker := range awsCheckers`
This is a Go for loop. `range` iterates over a list.
`_` means "I don't need the index (0, 1, 2...), just the value".
`checker` is the current item in the loop.

**Step 5:** `findings, err := checker.Run()`
Calls the checker. AWS API calls happen here.
Results come back as a list of findings.

**Step 6:** Inner loop adds each finding to result:
```go
for _, f := range findings {
    result.Add(f)
}
```

After all checkers run, `result` contains all findings from all integrations.

---

## Part 5 — The Evidence Vault: `internal/evidence/store.go`

This file saves every scan to your local disk as a JSON file.

---

### Section A — The Record struct with JSON tags

```go
type Record struct {
    ID          string           `json:"id"`
    CollectedAt time.Time        `json:"collected_at"`
    Framework   string           `json:"framework"`
    Score       int              `json:"score"`
    Findings    []engine.Finding `json:"findings"`
}
```

**What this does:**
A `Record` is one saved scan.

The `json:"id"` parts are called struct tags.
They tell Go: "when converting this to JSON, use this name".

Without tags, Go would use the field name exactly:
```json
{ "ID": "...", "CollectedAt": "..." }
```

With tags:
```json
{ "id": "...", "collected_at": "..." }
```

Lowercase snake_case is the standard for JSON. Tags let you
use Go's PascalCase naming internally while outputting proper JSON.

---

### Section B — The Save function

```go
func (s *Store) Save(result *engine.ScanResult, framework string) (string, error) {
    if err := os.MkdirAll(s.dir, 0700); err != nil {
        return "", fmt.Errorf("cannot create evidence dir: %w", err)
    }

    now := time.Now().UTC()
    id := fmt.Sprintf("%s-%04d", now.Format("20060102-150405"), rand.Intn(10000))

    record := Record{...}

    data, err := json.MarshalIndent(record, "", "  ")
    filename := filepath.Join(s.dir, fmt.Sprintf("scan-%s.json", id))
    os.WriteFile(filename, data, 0600)
    return filename, nil
}
```

**What this does, step by step:**

`os.MkdirAll(s.dir, 0700)` — creates the directory if it doesn't exist.
`0700` is a Unix file permission: owner can read/write/execute, others cannot.

`time.Now().UTC()` — gets the current time in UTC.

`now.Format("20060102-150405")` — formats the time as a string.
Go uses a VERY unusual system for time formatting.
Instead of `YYYY-MM-DD`, Go uses the reference time `Jan 2 15:04:05 2006`.
So `"20060102-150405"` becomes something like `"20260418-091532"`.
This is a quirk of Go that confuses everyone at first.

`rand.Intn(10000)` — random number 0–9999 to avoid name collisions
when two scans happen in the same second.

`fmt.Sprintf("%s-%04d", ...)` — builds a string.
`%s` = insert string, `%04d` = insert integer padded to 4 digits.
Result: `"20260418-091532-4821"`

`json.MarshalIndent(record, "", "  ")` — converts the struct to JSON.
`MarshalIndent` adds indentation (spaces) to make it human-readable.
Result is a `[]byte` (raw bytes).

`os.WriteFile(filename, data, 0600)` — writes bytes to disk.
`0600` = only the owner can read and write this file (security).

---

### Section C — The List function

```go
func (s *Store) List() ([]Record, error) {
    entries, err := filepath.Glob(filepath.Join(s.dir, "scan-*.json"))

    sort.Sort(sort.Reverse(sort.StringSlice(entries)))

    var records []Record
    for _, path := range entries {
        data, err := os.ReadFile(path)
        var r Record
        json.Unmarshal(data, &r)
        records = append(records, r)
    }
    return records, nil
}
```

**What this does:**

`filepath.Glob("scan-*.json")` — finds all files matching the pattern.
`*` is a wildcard, so this finds all files starting with "scan-" ending in ".json".
Returns a list of file paths.

`sort.Sort(sort.Reverse(sort.StringSlice(entries)))` — sorts filenames
in reverse alphabetical order (newest first, because filenames start with timestamp).

`os.ReadFile(path)` — reads the file contents as raw bytes.

`json.Unmarshal(data, &r)` — converts JSON bytes back into a Record struct.
This is the reverse of `json.MarshalIndent`.
`&r` means "put the result into this variable".

---

## Part 6 — How Everything Connects

Here is the full journey of `comply scan`:

```
You type: comply scan --framework soc2
                │
                ▼
        main.go: cmd.Execute()
                │
                ▼
        cmd/scan.go: runScan()
         │
         ├── Load AWS config (credentials)
         │
         ├── Create checkers:
         │    ├── IAMChecker  ─────► talks to AWS IAM API
         │    ├── S3Checker   ─────► talks to AWS S3 API
         │    ├── CloudTrailChecker → talks to AWS CloudTrail API
         │    └── SecurityGroupChecker → talks to AWS EC2 API
         │
         ├── For each checker:
         │    └── checker.Run()
         │          └── calls AWS API
         │          └── returns []Finding (list of results)
         │          └── each Finding: pass/fail/skip + remediation
         │
         ├── result.Add(finding) for each finding
         │    └── updates Passed/Failed/Skipped counters
         │    └── recalculates Score
         │
         ├── report.PrintResult(result)
         │    └── prints colored terminal output
         │
         ├── evidence.Store.Save(result)
         │    └── converts result to JSON
         │    └── writes to .complykit-evidence/scan-20260418-....json
         │
         └── report.WritePDF(result) (if --pdf flag)
              └── generates PDF file
```

---

## Part 7 — Go Concepts Summary

| Concept | Where used | What it does |
|---------|-----------|--------------|
| `struct` | Finding, ScanResult, IAMChecker | Groups related data |
| `interface` | Checker | Defines a contract any type can fulfill |
| `func (x *T) method()` | ScanResult.Add, Store.Save | Method attached to a struct |
| `[]Type` | `[]Finding`, `[]string` | A list (slice) of any type |
| `*Type` | `*ScanResult`, `*IAMChecker` | Pointer to a struct (work with original, not copy) |
| `err != nil` | everywhere | Check if something went wrong |
| `json:"name"` | Record struct | Control JSON field names |
| `range` | all loops | Iterate over a list |
| `append` | collecting findings | Add item to a list |
| `fmt.Sprintf` | everywhere | Build formatted strings |
| `init()` | cmd/scan.go | Auto-runs before main, used for setup |
| `package` | every file | Organise code into folders |
| `import` | every file | Use code from another package |

---

## Part 8 — How to Make Your First Change

The safest first change: add a message to the scan output.

Open `cmd/scan.go`, find the `runScan` function, and add:

```go
bold.Printf("\n  ComplyKit — %s Scan\n\n", flagFramework)
bold.Println("  Powered by Nuvlabs")  // ← add this line
```

Then rebuild:
```bash
go build -o comply .
./comply scan
```

You will see "Powered by Nuvlabs" appear in the output.

**Next change to try:** Add a new field to the `Finding` struct,
then print it in `internal/report/printer.go`.

**Next-next change:** Add a new check method in `internal/checks/aws/iam.go`
following the exact same pattern as `checkRootMFA`.

That is all you need to extend this project.
Every feature follows the same pattern — struct, method, interface, loop.
