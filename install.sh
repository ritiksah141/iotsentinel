#!/usr/bin/env bash
# IoTSentinel — one-command install for macOS and Linux
#
# Usage:  bash install.sh
# What it does:
#   1. Checks Python 3.9+
#   2. Creates a virtual environment (venv/)
#   3. Installs Python dependencies
#   4. Initialises the database schema (no default admin — you create one on first launch)
#   5. Opens your browser to http://localhost:8050/setup
#   6. Starts the dashboard

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

BANNER="${BLUE}
 ___    ___  _____  ____                _   _            _
|_ _|  / _ \|_   _|/ ___|  ___ _ __ | |_(_)_ __   ___| |
 | |  | | | | | |  \___ \ / _ \ '_ \| __| | '_ \ / _ \ |
 | |  | |_| | | |   ___) |  __/ | | | |_| | | | |  __/ |
|___|  \___/  |_|  |____/ \___|_| |_|\__|_|_| |_|\___|_|
${NC}"

echo -e "$BANNER"
echo -e "${BLUE}IoTSentinel Installer${NC}"
echo "==============================="
echo ""

# ---------------------------------------------------------------------------
# 1. Locate Python 3.9+
# ---------------------------------------------------------------------------
find_python() {
    for cmd in python3.13 python3.12 python3.11 python3.10 python3.9 python3 python; do
        if command -v "$cmd" &>/dev/null; then
            ver=$("$cmd" -c "import sys; print(sys.version_info >= (3,9))" 2>/dev/null)
            if [ "$ver" = "True" ]; then
                echo "$cmd"
                return 0
            fi
        fi
    done
    return 1
}

echo -e "${YELLOW}Checking Python version...${NC}"
PYTHON=$(find_python) || {
    echo -e "${RED}✗ Python 3.9 or higher is required but was not found.${NC}"
    echo "  Download it from https://www.python.org/downloads/"
    exit 1
}
PYTHON_VER=$("$PYTHON" --version)
echo -e "${GREEN}✓ Found $PYTHON_VER${NC}"
echo ""

# ---------------------------------------------------------------------------
# 2. Create virtual environment
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ ! -d "venv" ]; then
    echo -e "${YELLOW}Creating virtual environment...${NC}"
    "$PYTHON" -m venv venv
    echo -e "${GREEN}✓ Virtual environment created${NC}"
else
    echo -e "${GREEN}✓ Virtual environment already exists${NC}"
fi
echo ""

# ---------------------------------------------------------------------------
# 3. Install dependencies
# ---------------------------------------------------------------------------
echo -e "${YELLOW}Installing dependencies (this may take a few minutes)...${NC}"
source venv/bin/activate
pip install --upgrade pip --quiet
pip install -r requirements.txt --quiet
echo -e "${GREEN}✓ Dependencies installed${NC}"
echo ""

# ---------------------------------------------------------------------------
# 4. Initialise database
# ---------------------------------------------------------------------------
echo -e "${YELLOW}Initialising database schema...${NC}"
# Redirect stdin from /dev/null so init_database.py runs non-interactively.
# No default admin is created — IoTSentinel will prompt you to create one on first launch.
python3 config/init_database.py </dev/null
echo -e "${GREEN}✓ Database schema ready${NC}"
echo ""

# ---------------------------------------------------------------------------
# 5. Schedule automated DB maintenance (backup + rotation via cron)
# ---------------------------------------------------------------------------
echo -e "${YELLOW}Scheduling database maintenance cron jobs...${NC}"
if bash scripts/setup_db_automation.sh 2>/dev/null; then
    echo -e "${GREEN}✓ DB maintenance cron jobs registered${NC}"
else
    echo -e "${YELLOW}⚠ Could not register cron jobs (run 'bash scripts/setup_db_automation.sh' manually)${NC}"
fi
echo ""

# ---------------------------------------------------------------------------
# 6. Open browser after a short delay (let the server start first)
# ---------------------------------------------------------------------------
# Prefer a Chromium-based browser in --app mode so the dashboard launches as a
# chromeless, native-feeling window (no tabs/address bar) — the "open like an app"
# experience. Falls back to the default browser if none is found.
open_browser() {
    sleep 4
    URL="http://localhost:8050/setup"

    # macOS: launch a registered app bundle in app mode.
    if [ "$(uname)" = "Darwin" ]; then
        for app in "Google Chrome" "Microsoft Edge" "Brave Browser" "Chromium"; do
            if [ -d "/Applications/$app.app" ]; then
                open -na "$app" --args --app="$URL" && return
            fi
        done
        command -v open &>/dev/null && open "$URL" && return
    fi

    # Linux: try Chromium-family binaries in --app mode.
    for bin in google-chrome google-chrome-stable chromium chromium-browser microsoft-edge brave-browser; do
        if command -v "$bin" &>/dev/null; then
            "$bin" --app="$URL" >/dev/null 2>&1 & return
        fi
    done

    # Fallback: default browser (plain tab).
    if command -v xdg-open &>/dev/null; then        # Linux (X11 / Wayland)
        xdg-open "$URL"
    elif command -v wslview &>/dev/null; then        # WSL
        wslview "$URL"
    fi
}

open_browser &

# ---------------------------------------------------------------------------
# 6. Start dashboard
# ---------------------------------------------------------------------------
echo -e "${GREEN}===============================${NC}"
echo -e "${GREEN}✓ Setup complete!${NC}"
echo -e "${GREEN}===============================${NC}"
echo ""
echo -e "  Opening ${BLUE}http://localhost:8050/setup${NC} in your browser…"
echo -e "  ${YELLOW}Press Ctrl+C to stop the server.${NC}"
echo ""

python3 dashboard/app.py
