#!/bin/bash
# IoTSentinel — Pi Hardware Validation
#
# Run this on the Raspberry Pi after setup_pi.sh completes (or after flashing the .img).
# Reports pass/warn/fail for every critical system requirement.
#
# Usage:
#   bash scripts/validate_pi.sh
#
# Output:
#   Prints a checklist to the terminal.
#   Exits 0 if all critical checks pass, 1 if any critical check fails.

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

PASS=0; WARN=0; FAIL=0

pass() { echo -e "  ${GREEN}✓${NC}  $*"; PASS=$((PASS+1)); }
warn() { echo -e "  ${YELLOW}⚠${NC}  $*"; WARN=$((WARN+1)); }
fail() { echo -e "  ${RED}✗${NC}  $*"; FAIL=$((FAIL+1)); }

section() { echo -e "\n${BLUE}▶  $*${NC}"; }

PROJECT="${HOME}/iotsentinel"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${BLUE}  IoTSentinel — Pi Validation${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# ── 1. Hardware ──────────────────────────────────────────────────────────────
section "1/8  Hardware"

ARCH=$(uname -m)
if [[ "$ARCH" == "aarch64" ]]; then
    pass "Architecture: $ARCH (64-bit ARM)"
else
    warn "Architecture: $ARCH (expected aarch64 for Pi 5)"
fi

TOTAL_RAM=$(free -m | awk 'NR==2{print $2}')
if [ "$TOTAL_RAM" -ge 3500 ]; then
    pass "RAM: ${TOTAL_RAM} MB"
elif [ "$TOTAL_RAM" -ge 1800 ]; then
    warn "RAM: ${TOTAL_RAM} MB (< 4 GB — Ollama AI disabled)"
else
    fail "RAM: ${TOTAL_RAM} MB (< 2 GB — system may be too slow)"
fi

DISK_FREE=$(df -BG / | awk 'NR==2{print $4}' | sed 's/G//')
if [ "$DISK_FREE" -ge 16 ]; then
    pass "Disk free: ${DISK_FREE} GB"
elif [ "$DISK_FREE" -ge 8 ]; then
    warn "Disk free: ${DISK_FREE} GB (low — consider using a larger card)"
else
    fail "Disk free: ${DISK_FREE} GB (< 8 GB required)"
fi

# ── 2. Python environment ────────────────────────────────────────────────────
section "2/8  Python environment"

if python3 -c "import sys; exit(0 if sys.version_info >= (3,9) else 1)" 2>/dev/null; then
    pass "Python: $(python3 --version 2>&1 | awk '{print $2}')"
else
    fail "Python 3.9+ not found"
fi

if [ -f "$PROJECT/venv/bin/python3" ]; then
    pass "Virtual environment: $PROJECT/venv"
else
    fail "Virtual environment not found at $PROJECT/venv — run setup_pi.sh"
fi

if "$PROJECT/venv/bin/python3" -c "import dash, flask, psutil, river" 2>/dev/null; then
    pass "Core Python packages installed (dash, flask, psutil, river)"
else
    fail "One or more core packages missing — run: pip install -r requirements-pi.txt"
fi

# ── 3. Database ──────────────────────────────────────────────────────────────
section "3/8  Database"

DB_FILE=$(find "$PROJECT" -name "iotsentinel.db" -maxdepth 5 2>/dev/null | head -1)
if [ -n "$DB_FILE" ]; then
    DB_SIZE=$(du -sh "$DB_FILE" | awk '{print $1}')
    pass "Database: $DB_FILE ($DB_SIZE)"
    # Quick integrity check
    if sqlite3 "$DB_FILE" "PRAGMA integrity_check;" 2>/dev/null | grep -q "^ok$"; then
        pass "Database integrity: ok"
    else
        warn "Database integrity check returned non-ok (may still be functional)"
    fi
else
    fail "Database file not found — run: python3 config/init_database.py"
fi

# ── 4. Zeek ──────────────────────────────────────────────────────────────────
section "4/8  Zeek network monitor"

if command -v /opt/zeek/bin/zeek &>/dev/null; then
    ZEEK_VER=$(/opt/zeek/bin/zeek --version 2>&1 | head -1)
    pass "Zeek installed: $ZEEK_VER"
else
    fail "Zeek not found at /opt/zeek/bin/zeek — run setup_pi.sh"
fi

if /opt/zeek/bin/zeekctl status 2>&1 | grep -q "running" 2>/dev/null; then
    pass "Zeek is running"
else
    warn "Zeek is not currently running (will start when monitoring begins)"
fi

# ── 5. Systemd services ──────────────────────────────────────────────────────
section "5/8  Systemd services"

for svc in iotsentinel-provision iotsentinel-backend iotsentinel-dashboard; do
    if systemctl is-enabled --quiet "$svc" 2>/dev/null; then
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            pass "$svc: enabled + active"
        else
            warn "$svc: enabled but not currently active"
        fi
    else
        fail "$svc: not enabled — run: sudo systemctl enable --now $svc"
    fi
done

# Connectivity recovery timer — re-arms the setup hotspot if home Wi-Fi is lost.
if systemctl is-enabled --quiet iotsentinel-connectivity.timer 2>/dev/null; then
    pass "iotsentinel-connectivity.timer: enabled (Wi-Fi loss auto-recovery)"
else
    warn "iotsentinel-connectivity.timer: not enabled — run: sudo systemctl enable --now iotsentinel-connectivity.timer"
fi

# ── 6. Network & WiFi provisioning ──────────────────────────────────────────
section "6/8  Network & WiFi"

if command -v nmcli &>/dev/null; then
    pass "NetworkManager (nmcli) available"
else
    fail "nmcli not found — install: sudo apt install network-manager"
fi

if command -v avahi-daemon &>/dev/null || systemctl is-active --quiet avahi-daemon 2>/dev/null; then
    pass "avahi-daemon running (iotsentinel.local mDNS will work)"
else
    warn "avahi-daemon not running — 'iotsentinel.local' may not resolve"
fi

PI_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
if [ -n "$PI_IP" ]; then
    pass "Network IP: $PI_IP"
else
    warn "No IP address assigned yet"
fi

# ── 7. Ollama AI ─────────────────────────────────────────────────────────────
section "7/8  Ollama AI (optional)"

if command -v ollama &>/dev/null; then
    pass "Ollama installed: $(ollama --version 2>/dev/null | head -1 || true)"
    if ollama list 2>/dev/null | grep -q "phi3.5:mini"; then
        pass "phi3.5:mini model ready"
    else
        warn "phi3.5:mini not downloaded — run: ollama pull phi3.5:mini"
    fi
    if curl -s http://localhost:11434/api/tags >/dev/null 2>&1; then
        pass "Ollama API responding at localhost:11434"
    else
        warn "Ollama API not responding (service may not be running)"
    fi
else
    warn "Ollama not installed (AI explanations unavailable — optional feature)"
fi

# ── 8. Dashboard reachability ────────────────────────────────────────────────
section "8/8  Dashboard"

if curl -s --max-time 5 "http://localhost:8050/health" >/dev/null 2>&1; then
    pass "Dashboard responding at http://localhost:8050"
elif curl -s --max-time 5 "http://localhost:8050/" >/dev/null 2>&1; then
    pass "Dashboard responding at http://localhost:8050"
else
    warn "Dashboard not responding yet (may still be starting up)"
fi

# Config state
CONFIGURED=$(python3 -c "
import json
try:
    d = json.load(open('$PROJECT/config/default_config.json'))
    print(d.get('system', {}).get('is_configured', False))
except: print('unknown')
" 2>/dev/null)
if [ "$CONFIGURED" = "True" ]; then
    pass "is_configured: true (wizard completed)"
else
    warn "is_configured: false (wizard not yet completed — open http://${PI_IP:-<pi-ip>}:8050/setup)"
fi

# ── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if [ "$FAIL" -eq 0 ]; then
    echo -e "${GREEN}  RESULT: ${PASS} passed, ${WARN} warnings, 0 failures${NC}"
    echo -e "${GREEN}  Pi is ready to use.${NC}"
else
    echo -e "${RED}  RESULT: ${PASS} passed, ${WARN} warnings, ${FAIL} FAILED${NC}"
    echo -e "${RED}  Fix the failures above, then re-run this script.${NC}"
fi
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
[ "$FAIL" -eq 0 ]
