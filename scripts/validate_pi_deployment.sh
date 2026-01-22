#!/bin/bash
# Pi Deployment Validation Script
# Run this AFTER deploying to verify 100% readiness

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0

check_pass() {
    echo -e "${GREEN}✓${NC} $1"
    PASS_COUNT=$((PASS_COUNT + 1))
}

check_fail() {
    echo -e "${RED}✗${NC} $1"
    FAIL_COUNT=$((FAIL_COUNT + 1))
}

check_warn() {
    echo -e "${YELLOW}⚠${NC} $1"
    WARN_COUNT=$((WARN_COUNT + 1))
}

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${BLUE}  IoTSentinel Pi Deployment Validation${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# 1. System Requirements
echo -e "${BLUE}[1/10] System Requirements${NC}"

# Check RAM
TOTAL_RAM=$(free -m | awk 'NR==2{print $2}')
if [ "$TOTAL_RAM" -ge 3500 ]; then
    check_pass "RAM: ${TOTAL_RAM}MB (≥4GB recommended)"
else
    check_warn "RAM: ${TOTAL_RAM}MB (<4GB, may be slow with AI features)"
fi

# Check disk space
DISK_FREE=$(df -BG / | awk 'NR==2{print $4}' | sed 's/G//')
if [ "$DISK_FREE" -ge 8 ]; then
    check_pass "Disk space: ${DISK_FREE}GB free"
else
    check_fail "Disk space: ${DISK_FREE}GB (<8GB required)"
fi

# Check Python version
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
if [[ "$PYTHON_VERSION" =~ ^3\.(9|10|11|12) ]]; then
    check_pass "Python version: $PYTHON_VERSION"
else
    check_fail "Python version: $PYTHON_VERSION (need 3.9+)"
fi

echo ""

# 2. Zeek Installation
echo -e "${BLUE}[2/10] Zeek Network Monitor${NC}"

if command -v /opt/zeek/bin/zeek &> /dev/null; then
    ZEEK_VERSION=$(/opt/zeek/bin/zeek --version 2>&1 | head -1)
    check_pass "Zeek installed: $ZEEK_VERSION"

    # Check Zeek is running
    if sudo /opt/zeek/bin/zeekctl status 2>&1 | grep -q "running"; then
        check_pass "Zeek is running"

        # Check log files exist
        if [ -f "/opt/zeek/logs/current/conn.log" ]; then
            LOG_SIZE=$(ls -lh /opt/zeek/logs/current/conn.log | awk '{print $5}')
            check_pass "Zeek generating logs: conn.log ($LOG_SIZE)"
        else
            check_warn "Zeek running but no conn.log yet (may need time)"
        fi
    else
        check_fail "Zeek is NOT running"
    fi
else
    check_fail "Zeek not found at /opt/zeek/bin/zeek"
fi

echo ""

# 3. Python Dependencies
echo -e "${BLUE}[3/10] Python Dependencies${NC}"

source venv/bin/activate 2>/dev/null || true

# Check critical packages
check_package() {
    if python3 -c "import $1" 2>/dev/null; then
        VERSION=$(python3 -c "import $1; print($1.__version__)" 2>/dev/null || echo "installed")
        check_pass "$2: $VERSION"
        return 0
    else
        check_fail "$2 not installed"
        return 1
    fi
}

check_package "river" "River ML"
check_package "scapy" "Scapy"
check_package "dash" "Dash"
check_package "sqlite3" "SQLite"

echo ""

# 4. Scapy Network Capabilities
echo -e "${BLUE}[4/10] Scapy Network Access${NC}"

if python3 -c "from utils.arp_scanner import SCAPY_AVAILABLE; exit(0 if SCAPY_AVAILABLE else 1)" 2>/dev/null; then
    check_pass "Scapy imported successfully"

    # Check capabilities
    PYTHON_BIN=$(readlink -f $(which python3))
    if getcap "$PYTHON_BIN" 2>/dev/null | grep -q "cap_net_raw"; then
        check_pass "Python has network capabilities set"
    else
        check_warn "Python lacks network capabilities (may need sudo for ARP scanning)"
        echo "       Fix: sudo setcap cap_net_raw,cap_net_admin=eip $PYTHON_BIN"
    fi

    # Check nmap fallback
    if command -v nmap &> /dev/null; then
        check_pass "nmap available as fallback"
    else
        check_warn "nmap not installed (recommended as fallback)"
    fi
else
    check_fail "Scapy not available"
fi

echo ""

# 5. Database
echo -e "${BLUE}[5/10] Database${NC}"

if [ -f "data/database/iotsentinel.db" ]; then
    DB_SIZE=$(ls -lh data/database/iotsentinel.db | awk '{print $5}')
    check_pass "Database exists: $DB_SIZE"

    # Check tables
    TABLE_COUNT=$(sqlite3 data/database/iotsentinel.db "SELECT COUNT(*) FROM sqlite_master WHERE type='table';" 2>/dev/null || echo "0")
    if [ "$TABLE_COUNT" -gt 10 ]; then
        check_pass "Database schema: $TABLE_COUNT tables"
    else
        check_fail "Database schema incomplete: only $TABLE_COUNT tables"
    fi

    # Check devices
    DEVICE_COUNT=$(sqlite3 data/database/iotsentinel.db "SELECT COUNT(*) FROM devices;" 2>/dev/null || echo "0")
    check_pass "Devices discovered: $DEVICE_COUNT"

    # Check connections
    CONN_COUNT=$(sqlite3 data/database/iotsentinel.db "SELECT COUNT(*) FROM connections;" 2>/dev/null || echo "0")
    check_pass "Connections logged: $CONN_COUNT"
else
    check_fail "Database not initialized"
fi

echo ""

# 6. ML Models
echo -e "${BLUE}[6/10] Machine Learning${NC}"

# Check River ML
if python3 -c "from ml.river_engine import RiverMLEngine; from database.db_manager import DatabaseManager; db=DatabaseManager('data/database/iotsentinel.db'); engine=RiverMLEngine(db); print('OK')" 2>/dev/null | grep -q "OK"; then
    check_pass "River ML engine initializes"

    # Check model file
    if [ -f "data/models/river_engine.pkl" ]; then
        MODEL_SIZE=$(ls -lh data/models/river_engine.pkl | awk '{print $5}')
        check_pass "Model saved: $MODEL_SIZE"
    else
        check_warn "No saved model yet (will be created after first predictions)"
    fi

    # Get stats
    STATS=$(python3 -c "from ml.river_engine import RiverMLEngine; from database.db_manager import DatabaseManager; db=DatabaseManager('data/database/iotsentinel.db'); engine=RiverMLEngine(db); s=engine.get_stats(); print(f\"{s['predictions_made']} predictions, {s['anomalies_detected']} anomalies\")" 2>/dev/null || echo "0 predictions, 0 anomalies")
    check_pass "ML stats: $STATS"
else
    check_fail "River ML engine failed to initialize"
fi

echo ""

# 7. Services
echo -e "${BLUE}[7/10] System Services${NC}"

if systemctl is-active --quiet iotsentinel-backend.service 2>/dev/null; then
    check_pass "Backend service running"
else
    check_warn "Backend service not running (may need manual start)"
fi

if systemctl is-active --quiet iotsentinel-dashboard.service 2>/dev/null; then
    check_pass "Dashboard service running"
else
    check_warn "Dashboard service not running (may need manual start)"
fi

# Check Zeek monitoring cron
if crontab -l 2>/dev/null | grep -q "zeekctl cron"; then
    check_pass "Zeek monitoring cron configured"
else
    check_warn "Zeek monitoring cron not configured"
fi

echo ""

# 8. Network Configuration
echo -e "${BLUE}[8/10] Network Configuration${NC}"

# Check config file
if [ -f "config/default_config.json" ]; then
    check_pass "Configuration file exists"

    # Check Zeek path configured
    ZEEK_PATH=$(python3 -c "import json; c=json.load(open('config/default_config.json')); print(c['network']['zeek_log_path'])" 2>/dev/null || echo "")
    if [ -n "$ZEEK_PATH" ]; then
        check_pass "Zeek log path configured: $ZEEK_PATH"
    else
        check_fail "Zeek log path not configured"
    fi
else
    check_fail "Configuration file missing"
fi

# Check .env file
if [ -f ".env" ]; then
    check_pass ".env file exists"

    if grep -q "change-this" .env 2>/dev/null; then
        check_warn ".env contains default values (should be changed)"
    fi
else
    check_warn ".env file missing (optional but recommended)"
fi

echo ""

# 9. Performance Test
echo -e "${BLUE}[9/10] Performance Validation${NC}"

# CPU usage
CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)
CPU_INT=${CPU_USAGE%.*}
if [ "$CPU_INT" -lt 30 ]; then
    check_pass "CPU usage: ${CPU_USAGE}% (<30% target)"
elif [ "$CPU_INT" -lt 50 ]; then
    check_warn "CPU usage: ${CPU_USAGE}% (acceptable but above 30% target)"
else
    check_fail "CPU usage: ${CPU_USAGE}% (too high!)"
fi

# Memory usage
MEM_USAGE=$(free | awk 'NR==2{printf "%.0f", $3*100/$2}')
if [ "$MEM_USAGE" -lt 50 ]; then
    check_pass "Memory usage: ${MEM_USAGE}% (<50% target)"
elif [ "$MEM_USAGE" -lt 70 ]; then
    check_warn "Memory usage: ${MEM_USAGE}% (acceptable but watch for growth)"
else
    check_fail "Memory usage: ${MEM_USAGE}% (too high!)"
fi

# Test ML inference speed
echo -n "   Testing ML inference speed... "
INFERENCE_TIME=$(python3 -c "
import time
from ml.river_engine import RiverMLEngine
from database.db_manager import DatabaseManager

db = DatabaseManager('data/database/iotsentinel.db')
engine = RiverMLEngine(db)

test_conn = {
    'device_ip': '192.168.1.100',
    'dest_ip': '8.8.8.8',
    'dest_port': 443,
    'bytes_sent': 1024,
    'bytes_received': 2048,
    'duration': 1.5,
    'protocol': 'tcp'
}

start = time.time()
for _ in range(100):
    engine.analyze_connection(test_conn)
elapsed = time.time() - start

print(f'{elapsed:.2f}')
" 2>/dev/null || echo "999")

if (( $(echo "$INFERENCE_TIME < 30" | bc -l) )); then
    check_pass "ML inference: ${INFERENCE_TIME}s for 100 connections (<30s target)"
else
    check_fail "ML inference: ${INFERENCE_TIME}s for 100 connections (too slow!)"
fi

echo ""

# 10. Connectivity
echo -e "${BLUE}[10/10] Connectivity & Access${NC}"

# Check if dashboard is accessible
if curl -s -o /dev/null -w "%{http_code}" http://localhost:8050 2>/dev/null | grep -q "200"; then
    check_pass "Dashboard accessible at http://localhost:8050"
else
    check_warn "Dashboard not accessible (may not be started)"
fi

# Check Zeek parser can read logs
if python3 -c "from capture.zeek_log_parser import ZeekLogParser; parser=ZeekLogParser(); print('OK')" 2>/dev/null | grep -q "OK"; then
    check_pass "Zeek log parser initializes"
else
    check_fail "Zeek log parser failed to initialize"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${BLUE}  Validation Summary${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo -e "${GREEN}Passed:${NC}  $PASS_COUNT checks"
echo -e "${YELLOW}Warnings:${NC} $WARN_COUNT checks"
echo -e "${RED}Failed:${NC}  $FAIL_COUNT checks"
echo ""

# Calculate readiness percentage
TOTAL_CHECKS=$((PASS_COUNT + WARN_COUNT + FAIL_COUNT))
READINESS=$(( (PASS_COUNT * 100 + WARN_COUNT * 50) / TOTAL_CHECKS ))

echo -e "Deployment Readiness: ${BLUE}${READINESS}%${NC}"
echo ""

if [ "$FAIL_COUNT" -eq 0 ]; then
    if [ "$WARN_COUNT" -eq 0 ]; then
        echo -e "${GREEN}✓ System is 100% ready for production deployment!${NC}"
        echo ""
        echo "Next steps:"
        echo "  1. Monitor system for 24 hours"
        echo "  2. Access dashboard: http://$(hostname -I | awk '{print $1}'):8050"
        echo "  3. Review first alerts and adjust thresholds if needed"
        exit 0
    else
        echo -e "${YELLOW}⚠ System is functional but has warnings${NC}"
        echo ""
        echo "Recommended actions:"
        echo "  1. Review warnings above"
        echo "  2. Set Python capabilities: sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))"
        echo "  3. Update .env with production values"
        echo "  4. Monitor system for 24 hours"
        exit 0
    fi
else
    echo -e "${RED}✗ System has critical issues that must be fixed${NC}"
    echo ""
    echo "Required actions:"
    echo "  1. Fix all failed checks above"
    echo "  2. Re-run this validation script"
    echo "  3. Check logs: journalctl -u iotsentinel-backend -n 50"
    exit 1
fi
