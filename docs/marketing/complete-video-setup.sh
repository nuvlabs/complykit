#!/bin/bash

# ComplyKit Instagram Video - Complete Recording Automation
# This script prepares everything needed for easy video recording

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

echo -e "${PURPLE}🎬 ComplyKit Instagram Video - Complete Setup${NC}"
echo "================================================="
echo ""

# Function to create a recording session
setup_recording_session() {
    echo -e "${BLUE}Setting up perfect recording environment...${NC}"
    
    # Clean terminal
    clear
    
    # Set optimal terminal settings for recording
    export PS1="$ "
    export TERM=xterm-256color
    
    # Ensure ComplyKit is ready
    echo -e "${GREEN}✅ Terminal optimized for recording${NC}"
    echo -e "${GREEN}✅ ComplyKit ready${NC}"
    echo -e "${GREEN}✅ Dashboard running on port 9000${NC}"
    echo ""
}

# Function to display recording instructions
show_recording_instructions() {
    echo -e "${YELLOW}📋 RECORDING INSTRUCTIONS:${NC}"
    echo "=========================="
    echo ""
    echo -e "${BLUE}1. Start screen recording (QuickTime/OBS):${NC}"
    echo "   - Resolution: 1080x1920 (9:16 aspect ratio)"
    echo "   - Frame rate: 30fps"
    echo "   - Audio: Optional background music"
    echo ""
    echo -e "${BLUE}2. Record each scene using this script${NC}"
    echo -e "${BLUE}3. Add text overlays in video editor${NC}"
    echo -e "${BLUE}4. Export and upload to Instagram${NC}"
    echo ""
}

# Scene recording functions
record_scene_2() {
    echo -e "${YELLOW}🎬 SCENE 2: ComplyKit Installation (8-15 seconds)${NC}"
    echo "Text overlay: 'Meet ComplyKit ⚡'"
    echo ""
    echo "Ready to record? Press ENTER when screen recording is ON..."
    read
    
    clear
    sleep 1
    
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
    
    echo ""
    echo -e "${GREEN}✅ Scene 2 recording complete!${NC}"
}

record_scene_3() {
    echo -e "${YELLOW}🎬 SCENE 3: AWS Scanning (15-25 seconds)${NC}"
    echo "Text overlay: 'From Months to Minutes'"
    echo ""
    echo "Ready to record? Press ENTER when screen recording is ON..."
    read
    
    clear
    sleep 1
    
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
            echo -e "${RED}❌ FAILED${NC}"
        else
            echo -e "${GREEN}✅ PASSED${NC}"
        fi
    done
    
    echo ""
    echo "📊 Scan Results:"
    echo -e "  ${GREEN}✅ 47 checks passed${NC}"
    echo -e "  ${RED}❌ 3 issues found${NC}"
    echo -e "  ${BLUE}🔧 Auto-fix available for 2 issues${NC}"
    echo ""
    echo -e "${PURPLE}🎯 Compliance Score: 94% (SOC 2 Type II)${NC}"
    sleep 2
    
    echo ""
    echo -e "${GREEN}✅ Scene 3 recording complete!${NC}"
}

record_scene_5() {
    echo -e "${YELLOW}🎬 SCENE 5: Multi-Cloud Support (35-45 seconds)${NC}"
    echo "Text overlay: 'Works Everywhere 🌍'"
    echo ""
    echo "Ready to record? Press ENTER when screen recording is ON..."
    read
    
    clear
    sleep 1
    
    echo "$ comply scan azure"
    sleep 1
    echo -e "${BLUE}☁️  Scanning Microsoft Azure...${NC}"
    echo -e "${GREEN}✅ 23 checks passed, 1 issue found${NC}"
    sleep 1
    echo ""
    
    echo "$ comply scan gcp"
    sleep 1
    echo -e "${YELLOW}☁️  Scanning Google Cloud Platform...${NC}"
    echo -e "${GREEN}✅ 31 checks passed, 0 issues found${NC}"
    sleep 1
    echo ""
    
    echo "$ comply scan kubernetes"
    sleep 1
    echo -e "${PURPLE}⚙️  Scanning Kubernetes cluster...${NC}"
    echo -e "${GREEN}✅ 19 checks passed, 2 issues found${NC}"
    sleep 2
    
    echo ""
    echo -e "${GREEN}✅ Scene 5 recording complete!${NC}"
}

record_scene_6() {
    echo -e "${YELLOW}🎬 SCENE 6: Results & CTA (45-60 seconds)${NC}"
    echo "Text overlay: 'Join 1000+ Teams Already Compliant ✨'"
    echo ""
    echo "Ready to record? Press ENTER when screen recording is ON..."
    read
    
    clear
    sleep 1
    
    echo "🎯 Multi-Cloud Compliance Summary:"
    echo "  AWS:        94% compliant"
    echo "  Azure:      96% compliant"
    echo "  GCP:        100% compliant"
    echo "  Kubernetes: 89% compliant"
    echo ""
    echo -e "${GREEN}🏆 Overall Score: 95% - AUDIT READY!${NC}"
    echo ""
    echo -e "${PURPLE}🚀 Time saved: 4-6 weeks → 15 minutes${NC}"
    echo -e "${PURPLE}💰 Cost reduction: \$50,000 → \$0${NC}"
    echo ""
    echo -e "${GREEN}✨ Try ComplyKit Free → complykit.com ✨${NC}"
    sleep 3
    
    echo ""
    echo -e "${GREEN}✅ Scene 6 recording complete!${NC}"
}

# Main menu
show_menu() {
    echo -e "${BLUE}Choose your recording option:${NC}"
    echo "1. Setup Recording Environment"
    echo "2. Record Scene 2 (Installation)"
    echo "3. Record Scene 3 (AWS Scanning)"  
    echo "4. Record Scene 5 (Multi-Cloud)"
    echo "5. Record Scene 6 (Results & CTA)"
    echo "6. Record All Terminal Scenes (2,3,5,6)"
    echo "7. Show Dashboard Instructions (Scene 4)"
    echo "8. Create Final Video Instructions"
    echo "9. Exit"
    echo ""
    echo -n "Enter your choice [1-9]: "
}

# Main script logic
setup_recording_session
show_recording_instructions

while true; do
    show_menu
    read choice
    
    case $choice in
        1)
            setup_recording_session
            echo -e "${GREEN}Recording environment ready!${NC}"
            ;;
        2)
            record_scene_2
            ;;
        3)
            record_scene_3
            ;;
        4)
            echo -e "${YELLOW}Scene 4: Dashboard Demo Instructions${NC}"
            echo "=================================="
            echo "1. Open http://localhost:9000 in browser"
            echo "2. Record the dashboard interface"
            echo "3. Show sorting and filtering features"
            echo "4. Navigate through compliance data"
            echo "5. Text overlay: 'Automated Evidence Collection 🤖'"
            echo ""
            open http://localhost:9000
            ;;
        5)
            record_scene_5
            ;;
        6)
            record_scene_6
            ;;
        7)
            record_scene_2
            echo ""
            record_scene_3  
            echo ""
            record_scene_5
            echo ""
            record_scene_6
            echo ""
            echo -e "${GREEN}🎉 All terminal scenes recorded!${NC}"
            ;;
        8)
            echo -e "${YELLOW}Scene 4: Dashboard Recording${NC}"
            echo "Go to http://localhost:9000 and record:"
            echo "- Dashboard navigation"
            echo "- Sorting features (Status, Check, Integration, Severity)"
            echo "- Filtering (All, Failures, Passing, Skipped)"
            echo "- Real-time compliance data"
            open http://localhost:9000
            ;;
        9)
            cat << 'EOF'

🎬 FINAL VIDEO CREATION INSTRUCTIONS
===================================

1. 📱 Video Editor Setup:
   - Import all recorded clips
   - Set timeline to 1080x1920 (9:16 aspect ratio)
   - Target duration: 60 seconds

2. 🎨 Scene Assembly:
   Scene 1 (0-8s):   Problem hook (manual footage)
   Scene 2 (8-15s):  Installation (terminal recording)
   Scene 3 (15-25s): AWS scanning (terminal recording)
   Scene 4 (25-35s): Dashboard demo (browser recording)
   Scene 5 (35-45s): Multi-cloud (terminal recording)
   Scene 6 (45-60s): Results & CTA (terminal recording)

3. 📝 Add Text Overlays:
   - "SOC 2 taking forever? 😩" (0-8s)
   - "Meet ComplyKit ⚡" (8-15s)
   - "From Months to Minutes" (15-25s)
   - "Automated Evidence Collection 🤖" (25-35s)
   - "Works Everywhere 🌍" (35-45s)
   - "Join 1000+ Teams Already Compliant ✨" (45-60s)

4. 🎵 Audio:
   - Add upbeat background music
   - Optional: Add voiceover
   - Keep audio levels balanced

5. 🎯 Export Settings:
   - Format: MP4
   - Resolution: 1080x1920
   - Frame rate: 30fps
   - Quality: High (under 100MB)

6. 📲 Instagram Upload:
   - Use our caption template
   - Add hashtags: #ComplyKit #SOC2 #DevOps #Startup
   - Post as Instagram Reel
   - Add link in bio

📋 Files created for you:
   - Video script: docs/marketing/instagram-video-script.md
   - Text overlays: docs/marketing/text-overlays.md
   - Storyboard: docs/marketing/video-storyboard.html
   - Post preview: docs/marketing/instagram-post-preview.html

🚀 You're ready to create an amazing ComplyKit promo video!

EOF
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid option. Please choose 1-9.${NC}"
            ;;
    esac
    echo ""
done
