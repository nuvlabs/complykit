#!/bin/bash

# ComplyKit Instagram Video Recording Script
# This script helps you record each scene with perfect timing

# Colors for better output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Function to wait for user input
wait_for_user() {
    echo -e "${YELLOW}Press ENTER when ready to continue...${NC}"
    read
}

# Function to countdown
countdown() {
    local seconds=$1
    for i in $(seq $seconds -1 1); do
        echo -ne "\rStarting in $i seconds..."
        sleep 1
    done
    echo -ne "\r                    \r"
}

echo -e "${BLUE}🎬 ComplyKit Instagram Video Recording Helper${NC}"
echo "=============================================="
echo ""
echo -e "${GREEN}This script will guide you through recording each scene.${NC}"
echo -e "${GREEN}Make sure OBS Studio is running and configured for 1080x1920.${NC}"
echo ""

# Scene Selection Menu
while true; do
    echo -e "${BLUE}Select which scene to record:${NC}"
    echo "1. Scene 1 (0-8s): The Problem Hook"
    echo "2. Scene 2 (8-15s): ComplyKit Installation"  
    echo "3. Scene 3 (15-25s): AWS Scanning Demo"
    echo "4. Scene 4 (25-35s): Dashboard Demo"
    echo "5. Scene 5 (35-45s): Multi-Cloud Support"
    echo "6. Scene 6 (45-60s): Results & CTA"
    echo "7. Run Full Demo (All scenes back-to-back)"
    echo "8. Exit"
    echo ""
    echo -n "Enter your choice [1-8]: "
    read choice

    case $choice in
        1)
            echo -e "\n${YELLOW}🎬 Scene 1: The Problem Hook (0-8 seconds)${NC}"
            echo "Show frustrated developer with compliance spreadsheets"
            echo "Text overlay: 'SOC 2 taking forever? 😩'"
            wait_for_user
            echo -e "${RED}Record this manually - show compliance pain points!${NC}"
            ;;
        2)
            echo -e "\n${YELLOW}🎬 Scene 2: ComplyKit Installation (8-15 seconds)${NC}"
            echo "Text overlay: 'Meet ComplyKit ⚡'"
            wait_for_user
            countdown 3
            clear
            echo "$ brew install complykit"
            sleep 2
            echo "🍺  Installing ComplyKit..."
            sleep 1
            echo "✅ ComplyKit v1.0.3 installed successfully!"
            sleep 1
            echo ""
            echo "$ comply init"
            sleep 1
            echo "🚀 Initializing ComplyKit workspace..."
            echo "📁 Created compliance directory"
            echo "📋 Generated default policies" 
            echo "⚙️  Configured integrations"
            echo "✅ Setup complete! Ready to scan."
            sleep 2
            ;;
        3)
            echo -e "\n${YELLOW}🎬 Scene 3: AWS Scanning Demo (15-25 seconds)${NC}"
            echo "Text overlay: 'From Months to Minutes'"
            wait_for_user
            countdown 3
            clear
            echo "$ comply scan aws"
            sleep 1
            echo "🔍 Scanning AWS infrastructure..."
            echo ""
            
            # Simulate real-time scanning
            checks=("IAM Password Policy" "S3 Bucket Encryption" "CloudTrail Logging" "VPC Security Groups" "EC2 Instance Patching")
            for check in "${checks[@]}"; do
                echo -n "  Checking $check... "
                sleep 0.5
                if [[ $RANDOM -gt 16000 ]]; then
                    echo "❌ FAILED"
                else
                    echo "✅ PASSED"
                fi
            done
            
            echo ""
            echo "📊 Scan Results:"
            echo "  ✅ 47 checks passed"
            echo "  ❌ 3 issues found"
            echo "  🔧 Auto-fix available for 2 issues"
            echo ""
            echo "🎯 Compliance Score: 94% (SOC 2 Type II)"
            sleep 2
            ;;
        4)
            echo -e "\n${YELLOW}🎬 Scene 4: Dashboard Demo (25-35 seconds)${NC}"
            echo "Text overlay: 'Automated Evidence Collection 🤖'"
            echo -e "${GREEN}Starting ComplyKit dashboard...${NC}"
            wait_for_user
            
            # Start the server in background if not running
            if ! pgrep -f "comply serve" > /dev/null; then
                echo "Starting ComplyKit server..."
                comply serve --port 8080 > /dev/null 2>&1 &
                sleep 3
            fi
            
            echo "Opening dashboard at http://localhost:8080"
            open http://localhost:8080
            
            countdown 3
            echo "$ comply evidence collect"
            sleep 1
            echo "📁 Collecting compliance evidence..."
            echo ""
            
            evidence_types=("AWS CloudTrail logs" "IAM access reviews" "Security group configurations" "Encryption certificates")
            for evidence in "${evidence_types[@]}"; do
                echo "  📄 Generating $evidence..."
                sleep 0.7
            done
            
            echo ""
            echo "✅ Evidence collection complete!"
            echo "📂 Saved to: ~/.complykit/evidence/"
            echo "📊 Generated 47 evidence artifacts"
            sleep 2
            ;;
        5)
            echo -e "\n${YELLOW}🎬 Scene 5: Multi-Cloud Support (35-45 seconds)${NC}"
            echo "Text overlay: 'Works Everywhere 🌍'"
            wait_for_user
            countdown 3
            clear
            
            echo "$ comply scan azure"
            sleep 1
            echo "☁️  Scanning Microsoft Azure..."
            echo "✅ 23 checks passed, 1 issue found"
            sleep 1
            echo ""
            
            echo "$ comply scan gcp"
            sleep 1
            echo "☁️  Scanning Google Cloud Platform..."
            echo "✅ 31 checks passed, 0 issues found"
            sleep 1
            echo ""
            
            echo "$ comply scan kubernetes"
            sleep 1
            echo "⚙️  Scanning Kubernetes cluster..."
            echo "✅ 19 checks passed, 2 issues found"
            sleep 2
            ;;
        6)
            echo -e "\n${YELLOW}🎬 Scene 6: Results & CTA (45-60 seconds)${NC}"
            echo "Text overlay: 'Join 1000+ Teams Already Compliant ✨'"
            wait_for_user
            countdown 3
            clear
            
            echo "🎯 Multi-Cloud Compliance Summary:"
            echo "  AWS:        94% compliant"
            echo "  Azure:      96% compliant"
            echo "  GCP:        100% compliant" 
            echo "  Kubernetes: 89% compliant"
            echo ""
            echo "🏆 Overall Score: 95% - AUDIT READY!"
            echo ""
            echo "🚀 Time saved: 4-6 weeks → 15 minutes"
            echo "💰 Cost reduction: $50,000 → $0"
            echo ""
            echo -e "${GREEN}✨ Try ComplyKit Free → complykit.com ✨${NC}"
            sleep 3
            ;;
        7)
            echo -e "\n${YELLOW}🎬 Full Demo - All Scenes${NC}"
            echo "This will run all terminal scenes back-to-back"
            echo "Perfect for getting continuous footage!"
            wait_for_user
            countdown 5
            
            # Run scenes 2-6 continuously
            for scene in {2..6}; do
                echo -e "\n${BLUE}--- Scene $scene ---${NC}"
                case $scene in
                    2) bash $0 <<< "2" ;;
                    3) bash $0 <<< "3" ;;
                    4) bash $0 <<< "4" ;;
                    5) bash $0 <<< "5" ;;
                    6) bash $0 <<< "6" ;;
                esac
                sleep 1
            done
            ;;
        8)
            echo -e "${GREEN}Happy video making! 🎬${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid option. Please choose 1-8.${NC}"
            ;;
    esac
    
    echo ""
    echo -e "${BLUE}Recording complete for this scene!${NC}"
    echo ""
done
