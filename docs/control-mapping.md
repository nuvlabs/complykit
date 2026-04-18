# Control Mapping Reference

This document defines how infrastructure findings map to compliance framework controls.
This is ComplyKit's core moat — the more complete this mapping, the more valuable the product.

---

## SOC2 Trust Service Criteria (TSC)

### CC6 — Logical and Physical Access Controls

| Control | Title                          | AWS Checks                              | GitHub Checks                   |
|---------|--------------------------------|-----------------------------------------|---------------------------------|
| CC6.1   | Logical access security        | root_mfa, iam_password_policy           | —                               |
| CC6.2   | Prior to issuing credentials   | iam_user_unused_credentials             | —                               |
| CC6.3   | Access removal                 | iam_user_unused_credentials_90days      | —                               |
| CC6.6   | External threats               | s3_public_access_block, sg_no_open_ssh  | repo_not_public                 |
| CC6.7   | Transmission of data           | s3_encryption, rds_encryption           | —                               |
| CC6.8   | Malware protection             | guardduty_enabled                       | dependabot_enabled              |

### CC7 — System Operations

| Control | Title                          | AWS Checks                              |
|---------|--------------------------------|-----------------------------------------|
| CC7.1   | Vulnerability detection        | inspector_enabled, guardduty_enabled    |
| CC7.2   | Anomaly monitoring             | cloudtrail_enabled, cloudwatch_alarms   |
| CC7.3   | Incident evaluation            | cloudtrail_enabled                      |

### CC8 — Change Management

| Control | Title                          | GitHub Checks                           |
|---------|--------------------------------|-----------------------------------------|
| CC8.1   | Change management process      | branch_protection, required_reviews     |

### CC9 — Risk Mitigation

| Control | Title                          | AWS Checks                              |
|---------|--------------------------------|-----------------------------------------|
| CC9.1   | Risk identification            | config_enabled                          |
| CC9.2   | Vendor risk                    | (manual check — policy required)        |

---

## HIPAA Security Rule

### Technical Safeguards (§164.312)

| Section        | Title                          | AWS Checks                              |
|----------------|--------------------------------|-----------------------------------------|
| 164.312(a)(1)  | Access control                 | root_mfa, iam_password_policy           |
| 164.312(a)(2)  | Unique user identification     | iam_no_shared_credentials              |
| 164.312(b)     | Audit controls                 | cloudtrail_enabled                      |
| 164.312(c)(1)  | Integrity controls             | s3_versioning_enabled                   |
| 164.312(d)     | Person authentication          | root_mfa, console_mfa_all_users         |
| 164.312(e)(1)  | Transmission security          | elb_https_only, s3_encryption           |

---

## CIS AWS Foundations Benchmark (v1.4)

| CIS ID | Title                                    | Severity |
|--------|------------------------------------------|----------|
| 1.1    | Avoid use of root account                | Critical |
| 1.5    | Ensure MFA enabled for root              | Critical |
| 1.10   | Ensure MFA enabled for IAM users         | High     |
| 1.14   | Ensure hardware MFA for root             | Medium   |
| 2.1.1  | S3 bucket server-side encryption         | High     |
| 2.1.2  | S3 bucket public access block            | Critical |
| 2.2    | EBS volume encryption                    | High     |
| 2.3    | RDS encryption at rest                   | High     |
| 3.1    | CloudTrail enabled in all regions        | Critical |
| 3.2    | CloudTrail log file validation           | Medium   |
| 4.1    | No unrestricted SSH (0.0.0.0/0:22)       | Critical |
| 4.2    | No unrestricted RDP (0.0.0.0/0:3389)     | Critical |

---

## Check Definition Format

Each check is defined as a YAML file under `controls/checks/`:

```yaml
id: aws_s3_public_access_block
title: "S3 Bucket Public Access Block"
description: "All S3 buckets should have public access block enabled"
severity: critical
integration: aws
resource_type: s3_bucket
remediation: |
  1. Go to AWS S3 Console
  2. Select each bucket → Permissions → Block public access
  3. Enable all four block public access settings
  4. Or via CLI: aws s3api put-public-access-block --bucket BUCKET_NAME \
       --public-access-block-configuration \
       "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
maps_to:
  - framework: soc2
    controls: [CC6.6, CC6.7]
  - framework: hipaa
    controls: ["164.312(a)(1)"]
  - framework: cis
    controls: ["2.1.2"]
```
