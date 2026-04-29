#!/bin/bash

# ComplyKit Instagram Video - Terminal Demo Script
# This script creates realistic terminal output for video recording

echo "🎬 ComplyKit Instagram Video Demo Script"
echo "========================================="
echo ""

# Function to simulate typing
type_command() {
    local cmd="$1"
    local delay="${2:-0.1}"
    
    for (( i=0; i<${#cmd}; i++ )); do
        echo -n "${cmd:$i:1}"
        sleep $delay
    done
    echo ""
}

# Function to add dramatic pause
pause() {
    local duration="${1:-1}"
    sleep $duration
}

# Scene 2: Installation and Setup
echo "💻 Scene 2: Installation Demo"
echo "------------------------------"
type_command "brew install complykit" 0.08
pause 0.5
echo "🍺  Installing ComplyKit..."
echo "✅ ComplyKit v1.0.3 installed successfully!"
echo ""
pause 1

type_command "comply init" 0.08
pause 0.5
echo "🚀 Initializing ComplyKit workspace..."
echo "📁 Created compliance directory"
echo "📋 Generated default policies"
echo "⚙️  Configured integrations"
echo "✅ Setup complete! Ready to scan."
echo ""
pause 2

# Scene 3: AWS Scanning Demo
echo "⚡ Scene 3: AWS Scanning Demo"
echo "-----------------------------"
type_command "comply scan aws" 0.08
pause 0.5
echo "🔍 Scanning AWS infrastructure..."
echo ""

# Simulate real-time scanning output
checks=(
    "IAM Password Policy" 
    "S3 Bucket Encryption"
    "CloudTrail Logging"
    "VPC Security Groups"
    "EC2 Instance Patching"
    "RDS Encryption"
    "KMS Key Rotation"
    "GuardDuty Detection"
)

for check in "${checks[@]}"; do
    echo -n "  Checking $check... "
    sleep 0.3
    if [[ $RANDOM -gt 8000 ]]; then
        echo "❌ FAILED"
    else
        echo "✅ PASSED"
    fi
done

echo ""
echo "📊 Scan Results:"
echo "  ✅ 47 checks passed"
echo "  ❌ 3 issues found"
echo "  ⚠️  2 warnings"
echo "  🔧 Auto-fix available for 2 issues"
echo ""
echo "🎯 Compliance Score: 94% (SOC 2 Type II)"
pause 2

# Scene 4: Evidence Collection
echo "🤖 Scene 4: Automated Evidence Collection"
echo "------------------------------------------"
type_command "comply evidence collect" 0.08
pause 0.5
echo "📁 Collecting compliance evidence..."
echo ""

evidence_types=(
    "AWS CloudTrail logs"
    "IAM access reviews" 
    "Security group configurations"
    "Encryption certificates"
    "Backup verification"
    "Vulnerability scan reports"
)

for evidence in "${evidence_types[@]}"; do
    echo "  📄 Generating $evidence..."
    sleep 0.4
done

echo ""
echo "✅ Evidence collection complete!"
echo "📂 Saved to: ~/.complykit/evidence/"
echo "📊 Generated 47 evidence artifacts"
echo "🔒 All evidence encrypted and timestamped"
pause 2

# Scene 5: Multi-Cloud Demo
echo "🌍 Scene 5: Multi-Cloud Support"
echo "-------------------------------"

type_command "comply scan azure" 0.08
pause 0.3
echo "☁️  Scanning Microsoft Azure..."
echo "✅ 23 checks passed, 1 issue found"
echo ""

type_command "comply scan gcp" 0.08
pause 0.3
echo "☁️  Scanning Google Cloud Platform..."
echo "✅ 31 checks passed, 0 issues found"
echo ""

type_command "comply scan kubernetes" 0.08
pause 0.3
echo "⚙️  Scanning Kubernetes cluster..."
echo "✅ 19 checks passed, 2 issues found"
echo ""

echo "🎯 Multi-Cloud Compliance Summary:"
echo "  AWS:        94% compliant"
echo "  Azure:      96% compliant"
echo "  GCP:        100% compliant"
echo "  Kubernetes: 89% compliant"
echo ""
echo "🏆 Overall Score: 95% - AUDIT READY!"
pause 2

# Scene 6: Report Generation
echo "📊 Scene 6: Report Generation"
echo "-----------------------------"
type_command "comply report generate --format=pdf" 0.08
pause 0.5
echo "📋 Generating compliance report..."
echo ""

report_sections=(
    "Executive Summary"
    "Control Implementation"
    "Evidence Artifacts"
    "Risk Assessment"
    "Remediation Plan"
    "Audit Trail"
)

for section in "${report_sections[@]}"; do
    echo "  📄 Building $section..."
    sleep 0.3
done

echo ""
echo "✅ Report generated successfully!"
echo "📁 Saved: compliance-report-$(date +%Y%m%d).pdf"
echo "📊 Ready for SOC 2 audit submission"
echo ""
echo "🚀 Time saved: 4-6 weeks → 15 minutes"
echo "💰 Cost reduction: $50,000 → $0"
pause 2

echo ""
echo "🎉 ComplyKit Demo Complete!"
echo "=========================="
echo "Ready for your SOC 2 audit in minutes, not months!"
echo ""
echo "Try ComplyKit free: https://complykit.com"
echo "⭐ Star us on GitHub: https://github.com/nuvlabs/complykit"
