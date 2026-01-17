#!/usr/bin/bash
#
# Setup Ollama on Raspberry Pi for IoTSentinel
#
# This script installs Ollama and downloads the phi3.5:mini model
# optimized for Raspberry Pi 4GB RAM.
#
# Usage: bash setup_ollama_pi.sh
#

set -e  # Exit on error

echo "================================================"
echo "IoTSentinel - Ollama Setup for Raspberry Pi"
echo "================================================"
echo ""

# Check if running on Pi
if [[ ! $(uname -m) =~ "arm" ]] && [[ ! $(uname -m) =~ "aarch64" ]]; then
    echo "⚠️  Warning: This doesn't appear to be a Raspberry Pi (ARM architecture)"
    echo "   Detected architecture: $(uname -m)"
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Check available RAM
total_ram=$(free -m | awk 'NR==2{print $2}')
echo "📊 Detected RAM: ${total_ram}MB"

if [ "$total_ram" -lt 3500 ]; then
    echo "⚠️  Warning: Less than 4GB RAM detected"
    echo "   Ollama phi3.5:mini needs ~1.5GB RAM"
    echo "   Your system may run slow with other services"
fi

echo ""

# 1. Install Ollama
echo "🔧 Step 1: Installing Ollama..."
if command -v ollama &> /dev/null; then
    echo "✅ Ollama already installed: $(ollama --version)"
else
    echo "Downloading and installing Ollama..."
    curl -fsSL https://ollama.com/install.sh | sh
    echo "✅ Ollama installed successfully"
fi

echo ""

# 2. Start Ollama service
echo "🚀 Step 2: Starting Ollama service..."
if systemctl is-active --quiet ollama; then
    echo "✅ Ollama service already running"
else
    sudo systemctl start ollama
    sudo systemctl enable ollama
    echo "✅ Ollama service started and enabled"
fi

echo ""

# Wait for Ollama to be ready
echo "⏳ Waiting for Ollama API to be ready..."
for i in {1..10}; do
    if curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
        echo "✅ Ollama API is ready"
        break
    fi
    sleep 2
    echo "   Attempt $i/10..."
done

echo ""

# 3. Download phi3.5:mini model
echo "📥 Step 3: Downloading phi3.5:mini model (optimized for Pi)..."
echo "   Model size: ~2.7GB (this may take 5-15 minutes)"
echo ""

if ollama list | grep -q "phi3.5:mini"; then
    echo "✅ phi3.5:mini already downloaded"
else
    ollama pull phi3.5:mini
    echo "✅ phi3.5:mini downloaded successfully"
fi

echo ""

# 4. Test the model
echo "🧪 Step 4: Testing phi3.5:mini..."
echo "   Asking: 'What is network security in one sentence?'"
echo ""

response=$(ollama run phi3.5:mini "What is network security in one sentence?" --verbose=false 2>/dev/null || echo "Test failed")

if [[ "$response" != "Test failed" ]]; then
    echo "✅ Model test successful!"
    echo "   Response: $response"
else
    echo "⚠️  Model test failed - check logs with: sudo journalctl -u ollama -n 50"
fi

echo ""
echo "================================================"
echo "✅ Setup Complete!"
echo "================================================"
echo ""
echo "📋 Summary:"
echo "   • Ollama installed: ✅"
echo "   • Service running: ✅"
echo "   • Model downloaded: phi3.5:mini (2.7GB)"
echo "   • API endpoint: http://localhost:11434"
echo ""
echo "🎯 Next Steps:"
echo "   1. Update IoTSentinel config:"
echo "      OLLAMA_API_URL=http://localhost:11434/api/generate"
echo "      OLLAMA_MODEL=phi3.5:mini"
echo ""
echo "   2. (Optional) Add Groq API key to .env:"
echo "      GROQ_API_KEY=your_key_here"
echo "      Get free key at: https://console.groq.com"
echo ""
echo "   3. Restart IoTSentinel dashboard"
echo ""
echo "💡 Tips:"
echo "   • Check Ollama status: sudo systemctl status ollama"
echo "   • View logs: sudo journalctl -u ollama -f"
echo "   • List models: ollama list"
echo "   • Test model: ollama run phi3.5:mini"
echo ""
echo "📊 Expected Performance:"
echo "   • RAM usage: ~1.5GB during inference"
echo "   • Response time: 5-10 seconds on Pi 4"
echo "   • Concurrent users: 1-2"
echo ""
echo "🔍 Troubleshooting:"
echo "   • If out of memory: Reduce dashboard complexity"
echo "   • If too slow: Use Groq API (free tier) instead"
echo "   • If model won't load: Try smaller gemma2:2b"
echo ""
