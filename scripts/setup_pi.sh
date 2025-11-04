#!/bin/bash
# Complete setup script for Raspberry Pi

set -e

echo "================================================="
echo "   IoTSentinel Setup for Raspberry Pi"
echo "================================================="
echo ""

# Check if running as root
if [ "$EUID" -eq 0 ]; then 
    echo "Please do NOT run as root"
    exit 1
fi

PROJECT_DIR="$HOME/iotsentinel"

# 1. Create directory structure
echo "Creating directories..."
mkdir -p $PROJECT_DIR/data/{baseline,models,database,logs}
mkdir -p $PROJECT_DIR/{capture,ml,database,dashboard,config,scripts,services}

cd $PROJECT_DIR

# 2. Check Zeek
echo "Checking Zeek installation..."
if ! command -v /opt/zeek/bin/zeek &> /dev/null; then
    echo "❌ Zeek not found!"
    echo "Install Zeek first: https://zeek.org/get-zeek/"
    exit 1
fi
echo "✓ Zeek found: $(/opt/zeek/bin/zeek --version | head -1)"

# 3. Create virtual environment
if [ ! -d "venv" ]; then
    echo "Creating Python virtual environment..."
    python3 -m venv venv
fi

# 4. Install dependencies
echo "Installing Python packages..."
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements-pi.txt

# 5. Initialize database
echo "Initializing database..."
python3 config/init_database.py

# 6. System optimizations
echo "Applying system optimizations..."
sudo bash config/optimize_pi.sh 2>/dev/null || echo "⚠️  Could not apply optimizations"

# 7. Install cron jobs
echo "Setting up monitoring cron jobs..."
(crontab -l 2>/dev/null; echo "*/5 * * * * $PROJECT_DIR/config/zeek_monitor.sh") | crontab - 2>/dev/null || true
(crontab -l 2>/dev/null; echo "0 3 * * * $PROJECT_DIR/config/zeek_cleanup.sh") | crontab - 2>/dev/null || true

echo ""
echo "================================================="
echo "   ✓ Setup Complete!"
echo "================================================="
echo ""
echo "Next steps:"
echo "  1. Start baseline: python3 scripts/baseline_collector.py start"
echo "  2. After 7 days: python3 scripts/baseline_collector.py stop"
echo "  3. Train models: python3 ml/train_autoencoder.py"
echo "  4. Start monitoring: python3 ml/inference_engine.py --continuous"
echo ""