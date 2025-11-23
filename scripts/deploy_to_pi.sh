#!/bin/bash
# Professional deployment script for IoTSentinel (Zeek-based)

set -e

# Configuration
PI_USER="sentinel"
PI_HOST="iotsentinel.local"  # or use IP: "192.168.1.111"
PI_PATH="/home/sentinel/iotsentinel"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${GREEN}=================================================${NC}"
echo -e "${GREEN}   IoTSentinel Deployment (Zeek Architecture)${NC}"
echo -e "${GREEN}=================================================${NC}"
echo ""

# Check Pi connectivity
echo -e "${YELLOW}Checking Pi connectivity...${NC}"
if ! ping -c 1 $PI_HOST > /dev/null 2>&1; then
    echo -e "${RED}Error: Cannot reach $PI_HOST${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Pi is reachable${NC}"
echo ""

# Sync code to Pi
echo -e "${YELLOW}Syncing code to Pi...${NC}"
rsync -avz --progress \
    --exclude 'venv/' \
    --exclude '.git/' \
    --exclude '__pycache__/' \
    --exclude '*.pyc' \
    --exclude 'data/' \
    --exclude '.DS_Store' \
    --exclude '*.log' \
    ./ ${PI_USER}@${PI_HOST}:${PI_PATH}/

echo -e "${GREEN}✓ Code synced${NC}"
echo ""

# Run setup on Pi
echo -e "${YELLOW}Running setup on Pi...${NC}"
ssh ${PI_USER}@${PI_HOST} "bash -s" << 'ENDSSH'
set -e

cd /home/sentinel/iotsentinel

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  IoTSentinel Setup (Zeek-based Architecture)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# 1. Create directory structure
echo "Creating directory structure..."
mkdir -p data/{baseline,models,database,logs}
mkdir -p capture ml dashboard config services scripts

# 2. Check Zeek installation
echo "Checking Zeek installation..."
if ! command -v /opt/zeek/bin/zeek &> /dev/null; then
    echo "❌ Zeek is not installed at /opt/zeek/bin/zeek"
    echo "Please install Zeek first!"
    exit 1
fi

ZEEK_VERSION=$(/opt/zeek/bin/zeek --version | head -1)
echo "✓ Found Zeek: $ZEEK_VERSION"

# 3. Verify Zeek is running
echo "Checking Zeek status..."
ZEEK_STATUS=$(sudo /opt/zeek/bin/zeekctl status)
echo "$ZEEK_STATUS"

if echo "$ZEEK_STATUS" | grep -q "running"; then
    echo "✓ Zeek is running"
else
    echo "⚠️  Zeek is not running. Starting..."
    sudo /opt/zeek/bin/zeekctl deploy
    sleep 3
    sudo /opt/zeek/bin/zeekctl status
fi

# 4. Create/update Python virtual environment
if [ ! -d "venv" ]; then
    echo "Creating Python virtual environment..."
    python3 -m venv venv
else
    echo "✓ Virtual environment exists"
fi

# 5. Install Python dependencies
echo "Installing Python dependencies..."
source venv/bin/activate
pip install --upgrade pip setuptools --quiet
pip install -r requirements-pi.txt --quiet

echo "✓ Python packages installed"

# 6. Make scripts executable
echo "Setting permissions..."
chmod +x scripts/*.sh 2>/dev/null || true
chmod +x scripts/*.py 2>/dev/null || true
chmod +x capture/*.py 2>/dev/null || true

# 7. Initialize database
if [ ! -f "data/database/iotsentinel.db" ]; then
    echo "Initializing database..."
    python3 config/init_database.py
else
    echo "✓ Database already exists"
fi

# 8. Install systemd services
echo "Installing systemd services..."
sudo cp services/iotsentinel-backend.service /etc/systemd/system/ || echo "⚠️  Could not install iotsentinel-backend.service"
sudo cp services/iotsentinel-dashboard.service /etc/systemd/system/ || echo "⚠️  Could not install iotsentinel-dashboard.service"
sudo systemctl daemon-reload
sudo systemctl enable --now iotsentinel-backend.service || echo "⚠️  Could not enable iotsentinel-backend.service"
sudo systemctl enable --now iotsentinel-dashboard.service || echo "⚠️  Could not enable iotsentinel-dashboard.service"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  ✓ Setup Complete!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
ENDSSH

echo -e "${GREEN}✓ Remote setup complete${NC}"
echo ""
echo -e "${GREEN}=================================================${NC}"
echo -e "${GREEN}   Deployment Successful!${NC}"
echo -e "${GREEN}=================================================${NC}"
echo ""
echo -e "${BLUE}Architecture: Zeek-based (Professional)${NC}"
echo ""
echo "Next steps:"
echo "  1. SSH to Pi: ${YELLOW}ssh ${PI_USER}@${PI_HOST}${NC}"
echo "  2. Test Zeek parser: ${YELLOW}cd ~/iotsentinel && source venv/bin/activate${NC}"
echo "     ${YELLOW}python3 capture/zeek_log_parser.py --once${NC}"
echo "  3. Start baseline: ${YELLOW}python3 scripts/baseline_collector.py start${NC}"
echo ""
