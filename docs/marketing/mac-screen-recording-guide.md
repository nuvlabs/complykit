# 🎬 Mac Screen Recording Guide for ComplyKit Instagram Video

## 📱 Method 1: QuickTime Player (Built-in, Free)

### Step-by-Step Setup:
1. **Open QuickTime Player**
   ```bash
   # Open from Applications or use Spotlight
   open -a "QuickTime Player"
   ```

2. **Start New Screen Recording**
   - Go to **File → New Screen Recording**
   - Or press **Control + Command + N**

3. **Configure Recording Settings**
   - Click the **dropdown arrow** next to the record button
   - **Microphone**: Choose your microphone if you want voiceover
   - **Quality**: Select **High** for best results
   - **Show Mouse Clicks**: Enable if you want to show clicks

4. **Set Recording Area**
   - **For Instagram (9:16 ratio)**: Click and drag to select a vertical rectangle
   - **Recommended size**: 540x960 pixels (will scale to 1080x1920)
   - **Position**: Center the selection on your terminal/browser

5. **Start Recording**
   - Click the **Record** button
   - Click anywhere to record entire screen, or drag to select area

### QuickTime Recording Commands:
```bash
# Quick start recording
osascript -e 'tell application "QuickTime Player" to activate'
osascript -e 'tell application "QuickTime Player" to new screen recording'
```

---

## 📱 Method 2: Built-in Screenshot Tool (macOS Mojave+)

### Keyboard Shortcuts:
- **Shift + Command + 5** = Open screenshot/recording controls
- **Shift + Command + 3** = Full screen screenshot  
- **Shift + Command + 4** = Select area screenshot
- **Shift + Command + 6** = Record selected portion

### For Instagram Video Recording:
1. Press **Shift + Command + 5**
2. Click **"Record Selected Portion"**
3. Drag to select vertical area (9:16 ratio)
4. Click **"Record"** in the menu bar
5. Click **"Stop"** when finished

---

## 🎥 Method 3: OBS Studio (Professional, Free)

### Installation:
```bash
# Install OBS Studio using Homebrew
brew install --cask obs

# Or download from: https://obsproject.com/
```

### OBS Setup for Instagram:
1. **Create New Scene**
2. **Add Display Capture Source**
3. **Set Canvas Size**: 1080x1920 (9:16)
4. **Configure Output**:
   - Format: MP4
   - Encoder: Hardware (H.264)
   - Quality: High

### OBS Recording Settings:
```
Canvas (Base) Resolution: 1080x1920
Output (Scaled) Resolution: 1080x1920
FPS: 30
```

---

## 🚀 Ready-to-Use Recording Script

Let me create an automated script that will help you record each scene:

```bash
#!/bin/bash

echo "🎬 ComplyKit Instagram Video Recording"
echo "======================================"
echo ""
echo "📱 IMPORTANT: Set up screen recording first!"
echo ""
echo "For QuickTime:"
echo "1. Open QuickTime Player"
echo "2. File → New Screen Recording" 
echo "3. Select VERTICAL area (9:16 ratio)"
echo "4. Position over terminal window"
echo ""
echo "For Built-in tool:"
echo "1. Press Shift+Cmd+5"
echo "2. Select 'Record Selected Portion'"
echo "3. Drag vertical rectangle over terminal"
echo "4. Click Record"
echo ""
echo "📺 Recommended recording area: 540x960 pixels"
echo "📍 Position: Center over terminal/browser"
echo ""

read -p "✅ Screen recording ready? Press ENTER to start scene recording..."

echo ""
echo "🎬 Starting ComplyKit demo in 3 seconds..."
echo "3..."
sleep 1
echo "2..."
sleep 1  
echo "1..."
sleep 1
echo "🎬 ACTION!"
```

---

## 📐 Perfect Instagram Recording Dimensions

### Screen Recording Area:
- **Width**: 540 pixels
- **Height**: 960 pixels  
- **Ratio**: 9:16 (Instagram standard)
- **Position**: Centered on your terminal

### How to Measure:
```bash
# Install a screen ruler app
brew install --cask free-ruler

# Or use built-in Digital Color Meter
open -a "Digital Color Meter"
```

---

## 🎯 Quick Recording Setup for Each Scene

### Scene 1: Problem Hook (Manual)
```
📱 Record: Frustrated developer with compliance docs
📐 Area: Full screen or documents
⏱️ Duration: 8 seconds
🎬 Action: Show pain points, spreadsheets
```

### Scene 2-6: Terminal Scenes
```bash
# Prepare terminal
cd /Users/jagdishprasad/complykit
export PS1="$ "  # Clean prompt
clear

# Set optimal terminal size
printf '\e[8;24;80t'  # 24 rows, 80 columns

# Increase font size for mobile viewing
# Cmd+Plus to zoom in terminal font
```

---

## 🎬 Recording Workflow

### Pre-Recording Checklist:
- [ ] ComplyKit server running on port 9000
- [ ] Terminal set to optimal size
- [ ] Font size increased for mobile viewing
- [ ] Clean desktop background
- [ ] Notifications disabled
- [ ] Recording area selected (540x960)

### During Recording:
- [ ] Start screen recording
- [ ] Run scene scripts one by one
- [ ] Keep steady timing (8-10 seconds per scene)
- [ ] Stop recording after each scene or record continuously

### Post-Recording:
- [ ] Save videos with descriptive names:
  - `scene1-problem-hook.mov`
  - `scene2-installation.mov` 
  - `scene3-scanning.mov`
  - `scene4-dashboard.mov`
  - `scene5-multicloud.mov`
  - `scene6-success.mov`

---

## 🔧 Troubleshooting

### Common Issues:

**Recording area too small/large:**
```bash
# Check screen resolution
system_profiler SPDisplaysDataType | grep Resolution
```

**Audio not recording:**
- Go to System Preferences → Security & Privacy → Privacy
- Enable microphone access for QuickTime/OBS

**Video quality poor:**
- Use highest quality settings
- Record at native resolution
- Increase terminal font size

**Wrong aspect ratio:**
- Always measure 9:16 ratio (height = width × 1.78)
- Use 540×960 for recording, scales to 1080×1920

---

## 🚀 Let's Start Recording!

Ready to record your first scene? Here's the exact process:

1. **Choose recording method** (QuickTime recommended for simplicity)
2. **Set vertical recording area** (540×960 centered on terminal)
3. **Start recording**
4. **Run the scene script**
5. **Stop recording**
6. **Repeat for each scene**

**Ready to begin? Press ENTER when your screen recording is set up!**
