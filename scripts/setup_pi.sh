#!/bin/bash
# IoTSentinel — End-to-End Setup (Raspberry Pi, or a spare PC / Linux VM)
#
# Installs everything on a freshly-flashed Raspberry Pi OS Lite (64-bit, Bookworm).
# Also runs on x86_64 Debian/Ubuntu (a spare PC or a Linux VM) for real monitoring
# without a Pi — it continues past the ARM check and installs Zeek the same way.
# Safe to run multiple times (idempotent).
#
# Usage (fresh Pi, no repo yet):
#   bash <(curl -fsSL https://raw.githubusercontent.com/ritiksah141/iotsentinel/main/scripts/setup_pi.sh)
#
# Usage (already cloned):
#   bash scripts/setup_pi.sh [--non-interactive] [--skip-ollama] [--tag=v1.0.0]
#
# Flags:
#   --non-interactive   Skip all prompts (used by build_pi_image.sh)
#   --skip-ollama       Do not install Ollama / the on-device model
#   --tag=TAG           Git tag to clone (default: latest main)

set -euo pipefail

# ── Argument parsing ─────────────────────────────────────────────────────────
NON_INTERACTIVE=false
SKIP_OLLAMA=false
SKIP_APT=false
TAG=""

for arg in "$@"; do
  case "$arg" in
    --non-interactive) NON_INTERACTIVE=true ;;
    --skip-ollama)     SKIP_OLLAMA=true ;;
    --skip-apt)        SKIP_APT=true ;;
    --tag=*)           TAG="${arg#*=}" ;;
  esac
done

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

step() { echo -e "\n${BLUE}▶  $*${NC}"; }
ok()   { echo -e "   ${GREEN}✓${NC}  $*"; }
warn() { echo -e "   ${YELLOW}⚠${NC}  $*"; }
die()  { echo -e "\n${RED}✗  $*${NC}"; exit 1; }

prompt() {
    $NON_INTERACTIVE && return 0
    read -rp "   $* [y/N] " _r
    [[ "$_r" =~ ^[Yy]$ ]]
}

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${BLUE}  IoTSentinel — Setup (Raspberry Pi, spare PC, or Linux VM)${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# ── User / privilege model ───────────────────────────────────────────────────
# Normal use: run as a regular user with passwordless sudo (on a booted Pi/PC).
# Image build: the pi-gen chroot runs us AS ROOT, where `su`/`sudo` are unreliable
# under qemu. In that case set IOTSENTINEL_TARGET_USER (e.g. "sentinel"): we then
# run privileged commands directly (sudo shim) and install into that user's home,
# chowning everything to them at the end.
if [ "$EUID" -eq 0 ]; then
    [ -n "${IOTSENTINEL_TARGET_USER:-}" ] || die "Run as a regular user with sudo rights, not root (or set IOTSENTINEL_TARGET_USER for image builds)."
    TARGET_USER="$IOTSENTINEL_TARGET_USER"
    sudo() { "$@"; }   # already root inside the chroot — no sudo needed
else
    TARGET_USER="${IOTSENTINEL_TARGET_USER:-$(whoami)}"
fi
TARGET_HOME="$(getent passwd "$TARGET_USER" 2>/dev/null | cut -d: -f6)"
TARGET_HOME="${TARGET_HOME:-$HOME}"

# ─────────────────────────────────────────────────────────────────────────────
step "1/9  System pre-flight checks"
# ─────────────────────────────────────────────────────────────────────────────

ARCH=$(uname -m)
if [[ "$ARCH" == "aarch64" || "$ARCH" == "armv7l" ]]; then
    ok "Architecture: $ARCH"
else
    warn "Architecture: $ARCH (not a Pi — continuing; fine for a spare PC or Linux VM)"
fi

TOTAL_RAM=$(free -m | awk 'NR==2{print $2}')
if [ "$TOTAL_RAM" -ge 3500 ]; then
    ok "RAM: ${TOTAL_RAM} MB"
else
    warn "RAM: ${TOTAL_RAM} MB (< 3.5 GB — on-device Ollama will be disabled; a 4 GB Pi is fine)"
    SKIP_OLLAMA=true
fi

DISK_FREE=$(df -BG / | awk 'NR==2{print $4}' | sed 's/G//')
if [ "$DISK_FREE" -ge 8 ]; then
    ok "Disk free: ${DISK_FREE} GB"
else
    die "Disk free: ${DISK_FREE} GB — need at least 8 GB"
fi

if python3 -c "import sys; exit(0 if sys.version_info >= (3,9) else 1)" 2>/dev/null; then
    ok "Python: $(python3 --version 2>&1 | awk '{print $2}')"
else
    die "Python 3.9+ required. Install it first: sudo apt install python3 python3-venv"
fi

# ─────────────────────────────────────────────────────────────────────────────
step "2/9  Configure Raspberry Pi"
# ─────────────────────────────────────────────────────────────────────────────

if command -v raspi-config &>/dev/null; then
    sudo raspi-config nonint do_expand_rootfs 2>/dev/null \
        && ok "Filesystem expanded" \
        || warn "Filesystem expand skipped (may already be full size)"
    sudo raspi-config nonint do_hostname iotsentinel 2>/dev/null \
        && ok "Hostname set to 'iotsentinel'" || true
    sudo raspi-config nonint do_ssh 0 2>/dev/null \
        && ok "SSH enabled" || true
    # Wi-Fi country: on a Pi the radio is rfkill-blocked and won't do AP (hotspot)
    # mode until a country is set. Without this the IoTSentinel-Setup hotspot never
    # appears on a headless first boot. GB by default; change to your ISO country.
    sudo raspi-config nonint do_wifi_country "${IOTSENTINEL_WIFI_COUNTRY:-GB}" 2>/dev/null \
        && ok "Wi-Fi country set (${IOTSENTINEL_WIFI_COUNTRY:-GB})" \
        || warn "Could not set Wi-Fi country — hotspot may not start until you set it"
else
    warn "raspi-config not found — skipping Pi configuration"
fi

# ─────────────────────────────────────────────────────────────────────────────
step "3/9  Install system packages"
# ─────────────────────────────────────────────────────────────────────────────

# --skip-apt: the image build pre-installs the full system-package set as root in a
# dedicated pi-gen stage (reliable), so re-running apt inside the emulated build
# chroot here is redundant AND fragile (apt-key can't write /tmp temp files there,
# which fails on the Debian/arm64 base). Skip it in that case; install normally on a
# real Pi / spare-PC run.
if $SKIP_APT; then
    warn "Skipping system-package install (--skip-apt; pre-installed by the image build)"
else
    sudo apt-get update -qq
    sudo apt-get install -y --no-install-recommends \
        curl git python3 python3-venv python3-pip \
        build-essential libssl-dev gnupg2 libpcap-dev \
        tcpdump net-tools iputils-ping openssl nmap \
        network-manager dnsmasq-base avahi-daemon iptables nftables
    ok "System packages installed"
    # Let nmap do ARP/ICMP host-discovery without root (the dashboard runs as an
    # unprivileged user). Scoped capability, not a sudoers grant. Non-fatal.
    if command -v nmap &>/dev/null; then
        sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+ep "$(command -v nmap)" 2>/dev/null \
            && ok "nmap granted net_raw capability (root-free host discovery)" \
            || warn "Could not setcap nmap — active scans will use TCP-connect fallback"
    fi
fi

# ─────────────────────────────────────────────────────────────────────────────
# Install Tailscale (optional remote-access — wizard enables Funnel later)
# ─────────────────────────────────────────────────────────────────────────────
if command -v tailscale &>/dev/null; then
    ok "Tailscale already installed: $(tailscale version 2>/dev/null | head -1 || true)"
else
    echo "   Installing Tailscale…"
    # NON-FATAL: Tailscale is optional (remote access; the wizard enables Funnel later).
    # Its installer adds an apt repo via apt-key, which fails inside the emulated build
    # chroot (can't write /tmp temp files) — that must NOT abort the whole setup under
    # `set -e`. If it fails here it can be installed on first boot / from the wizard.
    if curl -fsSL https://tailscale.com/install.sh | sh; then
        ok "Tailscale installed (sign-in happens inside the setup wizard)"
    else
        warn "Tailscale install skipped (failed in this environment) — remote access can be enabled later"
    fi
fi

# ─────────────────────────────────────────────────────────────────────────────
step "4/9  Install Zeek (network monitor)"
# ─────────────────────────────────────────────────────────────────────────────

if command -v /opt/zeek/bin/zeek &>/dev/null; then
    ok "Zeek already installed: $(/opt/zeek/bin/zeek --version 2>&1 | head -1)"
elif $SKIP_APT; then
    warn "Zeek not found and --skip-apt set — expected it pre-installed by the image build"
else
    echo "   Adding Zeek repository (Debian Bookworm / Pi OS)..."
    echo 'deb http://download.opensuse.org/repositories/security:/zeek/Debian_12/ /' \
        | sudo tee /etc/apt/sources.list.d/security:zeek.list > /dev/null
    curl -fsSL https://download.opensuse.org/repositories/security:/zeek/Debian_12/Release.key \
        | gpg --dearmor \
        | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null
    sudo apt-get update -qq
    sudo apt-get install -y zeek
    ok "Zeek installed: $(/opt/zeek/bin/zeek --version 2>&1 | head -1)"
fi

# Persist Zeek on PATH
if ! grep -qF '/opt/zeek/bin' "$TARGET_HOME/.bashrc" 2>/dev/null; then
    echo 'export PATH="/opt/zeek/bin:$PATH"' >> "$TARGET_HOME/.bashrc"
fi
export PATH="/opt/zeek/bin:$PATH"

# ─────────────────────────────────────────────────────────────────────────────
step "5/9  Clone / update IoTSentinel"
# ─────────────────────────────────────────────────────────────────────────────

PROJECT_DIR="$TARGET_HOME/iotsentinel"
REPO_URL="https://github.com/ritiksah141/iotsentinel.git"

if [ -d "$PROJECT_DIR/.git" ]; then
    ok "Repo already present at $PROJECT_DIR"
    if prompt "Pull latest changes?"; then
        git -C "$PROJECT_DIR" pull --ff-only \
            && ok "Updated to latest" \
            || warn "Could not pull — continuing with existing code"
    fi
else
    # If this script is running from inside a cloned repo, copy it in place
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-./scripts/setup_pi.sh}")/.." 2>/dev/null && pwd || echo "")"
    if [ -f "$SCRIPT_DIR/dashboard/app.py" ] && [ "$SCRIPT_DIR" != "$PROJECT_DIR" ]; then
        cp -r "$SCRIPT_DIR/." "$PROJECT_DIR"
        ok "Copied repo to $PROJECT_DIR"
    elif [ -f "$PROJECT_DIR/dashboard/app.py" ]; then
        ok "Repo already at $PROJECT_DIR"
    else
        echo "   Cloning from $REPO_URL..."
        if [ -n "$TAG" ]; then
            git clone --branch "$TAG" --depth 1 "$REPO_URL" "$PROJECT_DIR"
        else
            git clone --depth 1 "$REPO_URL" "$PROJECT_DIR"
        fi
        ok "Cloned to $PROJECT_DIR"
    fi
fi

mkdir -p \
    "$PROJECT_DIR/data/baseline" \
    "$PROJECT_DIR/data/models" \
    "$PROJECT_DIR/data/database" \
    "$PROJECT_DIR/data/logs"

cd "$PROJECT_DIR"

# ─────────────────────────────────────────────────────────────────────────────
step "6/9  Python environment & IoTSentinel dependencies"
# ─────────────────────────────────────────────────────────────────────────────

if [ ! -d "$PROJECT_DIR/venv" ]; then
    python3 -m venv "$PROJECT_DIR/venv"
    ok "Virtual environment created"
else
    ok "Virtual environment already exists"
fi

source "$PROJECT_DIR/venv/bin/activate"
# More tolerant of transient TLS/network hiccups during downloads.
PIP_OPTS="--retries 5 --timeout 60"
pip install $PIP_OPTS --upgrade pip -q

REQ_FILE="$PROJECT_DIR/requirements-pi.txt"
[ -f "$REQ_FILE" ] || REQ_FILE="$PROJECT_DIR/requirements.txt"
pip install $PIP_OPTS -r "$REQ_FILE" -q
ok "Python packages installed from $(basename "$REQ_FILE")"

python3 config/init_database.py </dev/null \
    && ok "Database initialised" \
    || warn "DB init reported an error — check logs/init.log"

# Ensure a stable FLASK_SECRET_KEY exists before first boot
ENV_FILE="$PROJECT_DIR/.env"
if ! grep -qF "FLASK_SECRET_KEY" "$ENV_FILE" 2>/dev/null; then
    SK=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    echo "FLASK_SECRET_KEY=$SK" >> "$ENV_FILE"
    ok "Flask secret key generated and persisted"
fi

# ─────────────────────────────────────────────────────────────────────────────
step "7/9  Optimisations, cron jobs & systemd services"
# ─────────────────────────────────────────────────────────────────────────────

# Pi system optimisations (swappiness, GPU memory split, etc.)
if [ -f "$PROJECT_DIR/config/optimize_pi.sh" ]; then
    sudo bash "$PROJECT_DIR/config/optimize_pi.sh" 2>/dev/null \
        && ok "Pi optimisations applied" \
        || warn "Optimisations skipped (non-fatal)"
fi

# Cron jobs — idempotent, only added once
CRON_MONITOR="*/5 * * * * $PROJECT_DIR/config/zeek_monitor.sh"
CRON_CLEANUP="0 3 * * * $PROJECT_DIR/config/zeek_cleanup.sh"
if [ -f "$PROJECT_DIR/config/zeek_monitor.sh" ]; then
    (crontab -l 2>/dev/null | grep -qF "zeek_monitor.sh") || \
        { crontab -l 2>/dev/null; echo "$CRON_MONITOR"; } | crontab - 2>/dev/null || true
fi
if [ -f "$PROJECT_DIR/config/zeek_cleanup.sh" ]; then
    (crontab -l 2>/dev/null | grep -qF "zeek_cleanup.sh") || \
        { crontab -l 2>/dev/null; echo "$CRON_CLEANUP"; } | crontab - 2>/dev/null || true
fi
ok "Cron jobs configured"

# DB maintenance cron (daily backup + weekly optimize + backup rotation)
if bash "$PROJECT_DIR/scripts/setup_db_automation.sh" 2>/dev/null; then
    ok "DB maintenance cron jobs registered"
else
    warn "Could not register DB maintenance cron — run 'bash scripts/setup_db_automation.sh' manually"
fi

# Allow the (unprivileged) service user to run exactly the commands IoTSentinel
# needs, and nothing else:
#  - nmcli wifi          (wizard: connect/list/hotspot for home-Wi-Fi + setup hotspot)
#  - nmcli connection    (wizard: create+activate the home-Wi-Fi profile, tear down setup hotspot)
#  - setup_hotspot.sh    (wizard: disarm the provisioning hotspot after the Wi-Fi join)
#  - configure_ap.sh     (orchestrator brings the IoT access point up/down — gateway mode)
#  - configure_zeek.sh   (orchestrator points Zeek at the monitored interface)
#  - nft / iptables      (firewall_enforcer inline block/unblock — the IPS path)
#  - zeekctl deploy      (health watchdog restarts Zeek if it crashes)
#  - systemctl restart iotsentinel-backend (re-run subnet self-heal after the Wi-Fi join)
#  - tailscale up / funnel  (wizard: enable remote access — needs root, no operator set)
# Scripts are invoked by absolute path (executable shebang) so the match is exact.
CURRENT_USER="$TARGET_USER"
SUDOERS_LINE="$CURRENT_USER ALL=(ALL) NOPASSWD: /usr/bin/nmcli dev wifi connect *, /usr/bin/nmcli dev wifi list *, /usr/bin/nmcli dev wifi hotspot *, /usr/bin/nmcli connection add *, /usr/bin/nmcli connection modify *, /usr/bin/nmcli connection up *, /usr/bin/nmcli connection down *, /usr/bin/nmcli connection delete *, $PROJECT_DIR/scripts/setup_hotspot.sh disarm, $PROJECT_DIR/config/configure_ap.sh, $PROJECT_DIR/config/configure_ap.sh --down, $PROJECT_DIR/config/configure_zeek.sh, $PROJECT_DIR/config/configure_zeek.sh *, /usr/sbin/nft *, /usr/sbin/iptables *, /opt/zeek/bin/zeekctl deploy, /usr/sbin/iw reg set *, /usr/bin/raspi-config nonint do_wifi_country *, /usr/bin/systemctl restart iotsentinel-backend, /usr/bin/tailscale up *, /usr/bin/tailscale funnel *"
# Guard keys on a token only the current line has, so an older install's file is rewritten.
if ! grep -qF "tailscale funnel" /etc/sudoers.d/iotsentinel 2>/dev/null; then
    echo "$SUDOERS_LINE" | sudo tee /etc/sudoers.d/iotsentinel > /dev/null
    sudo chmod 440 /etc/sudoers.d/iotsentinel
    ok "sudoers rules added for $CURRENT_USER (nmcli + hotspot disarm + AP/Zeek + nft/iptables + backend restart)"
fi

# Systemd services — substitute actual username and home dir into service files
SERVICES_SRC="$PROJECT_DIR/services"
if [ -f "$SERVICES_SRC/iotsentinel-backend.service" ]; then
    for svc in iotsentinel-backend iotsentinel-dashboard iotsentinel-provision iotsentinel-localai iotsentinel-connectivity iotsentinel-firstboot-report iotsentinel-model-eval; do
        [ -f "$SERVICES_SRC/${svc}.service" ] || continue
        sed "s|/home/sentinel|$TARGET_HOME|g; s|User=sentinel|User=$CURRENT_USER|g" \
            "$SERVICES_SRC/${svc}.service" \
            | sudo tee /etc/systemd/system/${svc}.service > /dev/null
    done
    # The connectivity recovery timer (no username/path substitution needed).
    if [ -f "$SERVICES_SRC/iotsentinel-connectivity.timer" ]; then
        sudo cp "$SERVICES_SRC/iotsentinel-connectivity.timer" /etc/systemd/system/
    fi
    # daemon-reload needs a RUNNING systemd; it fails inside the image-build chroot,
    # so it must never abort the script (set -e). Harmless on a real system.
    sudo systemctl daemon-reload 2>/dev/null || true
    # `systemctl enable` creates the wants-symlinks offline (works in a chroot). `--now`
    # additionally starts the unit on a real system and harmlessly fails in the chroot.
    sudo systemctl enable --now iotsentinel-provision iotsentinel-backend iotsentinel-dashboard 2>/dev/null || true
    # Connectivity recovery: re-arms the setup hotspot if home WiFi is ever lost.
    sudo systemctl enable --now iotsentinel-connectivity.timer 2>/dev/null || true
    # First-boot diagnostic report (writes Wi-Fi/AP state to the FAT boot partition).
    sudo systemctl enable iotsentinel-firstboot-report 2>/dev/null || true
    # localai pulls the on-device model on first boot; enable for next boot (no --now).
    sudo systemctl enable iotsentinel-localai 2>/dev/null || true
    # model-eval populates the ML model-performance card (and seeds demo traffic in demo
    # mode) on first boot; enable for next boot (no --now).
    sudo systemctl enable iotsentinel-model-eval 2>/dev/null || true
    # Fallback: guarantee the autostart symlinks exist even if `systemctl enable` could
    # not talk to systemd in the chroot, so the image always boots the services.
    sudo mkdir -p /etc/systemd/system/multi-user.target.wants \
                  /etc/systemd/system/timers.target.wants 2>/dev/null || true
    for _u in iotsentinel-provision iotsentinel-backend iotsentinel-dashboard \
              iotsentinel-firstboot-report iotsentinel-localai iotsentinel-model-eval; do
        sudo ln -sf "/etc/systemd/system/${_u}.service" \
            "/etc/systemd/system/multi-user.target.wants/${_u}.service" 2>/dev/null || true
    done
    sudo ln -sf /etc/systemd/system/iotsentinel-connectivity.timer \
        /etc/systemd/system/timers.target.wants/iotsentinel-connectivity.timer 2>/dev/null || true
    # Cap the systemd journal so it can never fill the SD card. A full disk makes
    # SQLite raise "disk I/O error" and bricks the app; the default 10% cap plus
    # crash-loop traceback spam is enough to get there on a small card.
    sudo mkdir -p /etc/systemd/journald.conf.d 2>/dev/null || true
    printf '[Journal]\nSystemMaxUse=200M\nSystemKeepFree=200M\nRuntimeMaxUse=64M\n' \
        | sudo tee /etc/systemd/journald.conf.d/00-iotsentinel-size.conf > /dev/null 2>&1 || true
    sudo systemctl restart systemd-journald 2>/dev/null || true
    ok "Systemd services installed and enabled (autostart on boot)"
else
    warn "Service files not found in $SERVICES_SRC — skipping systemd"
fi

# ─────────────────────────────────────────────────────────────────────────────
# Pull the model named in config (ai_assistant.ollama_model); keep this in sync
# with config/default_config.json and scripts/setup_local_ai.sh.
MODEL="$(python3 -c "import json,pathlib;print(json.loads(pathlib.Path('$PROJECT_DIR/config/default_config.json').read_text()).get('ai_assistant',{}).get('ollama_model','gemma2:2b'))" 2>/dev/null || echo 'gemma2:2b')"
step "8/9  Ollama AI — ${MODEL} (on-device, optimised for Pi 4/5 4 GB)"
# ─────────────────────────────────────────────────────────────────────────────

if $SKIP_OLLAMA; then
    warn "Ollama skipped (< 4 GB RAM or --skip-ollama)"
else
    if command -v ollama &>/dev/null; then
        ok "Ollama already installed: $(ollama --version 2>/dev/null | head -1 || true)"
    else
        echo "   Downloading and installing Ollama..."
        curl -fsSL https://ollama.com/install.sh | sh
        ok "Ollama installed"
    fi

    # Start the service
    sudo systemctl enable --now ollama 2>/dev/null \
        || sudo systemctl start ollama 2>/dev/null \
        || true

    # Wait for Ollama API (up to 20 s)
    echo "   Waiting for Ollama API to be ready..."
    _OLLAMA_READY=false
    for _i in $(seq 1 10); do
        if curl -s http://localhost:11434/api/tags >/dev/null 2>&1; then
            _OLLAMA_READY=true
            break
        fi
        sleep 2
    done

    if $_OLLAMA_READY; then
        if ollama list 2>/dev/null | grep -q "${MODEL%%:*}"; then
            ok "${MODEL} already downloaded"
        else
            echo "   Pulling ${MODEL} (~1.6 GB — may take 10–20 min on a slow SD card)..."
            ollama pull "$MODEL" && ok "${MODEL} ready"
        fi
    else
        warn "Ollama API did not respond — model pull skipped. Retry: ollama pull ${MODEL}"
    fi
fi

# When we ran as root targeting another user (image build), everything we created
# in their home (venv, .env, data/, .bashrc) is root-owned — hand it back so the
# unprivileged service user can read/write it at runtime.
if [ "$EUID" -eq 0 ] && [ "$TARGET_USER" != "root" ]; then
    chown -R "$TARGET_USER":"$TARGET_USER" "$PROJECT_DIR" "$TARGET_HOME/.bashrc" 2>/dev/null || true
    ok "Ownership handed to $TARGET_USER"
fi

# ─────────────────────────────────────────────────────────────────────────────
step "9/9  Quick validation"
# ─────────────────────────────────────────────────────────────────────────────

PASS=0; SKIP=0

_chk() {
    if eval "$2" &>/dev/null; then
        ok "$1"; PASS=$((PASS+1))
    else
        warn "Not yet: $1"; SKIP=$((SKIP+1))
    fi
}

_chk "Zeek binary"                      "command -v /opt/zeek/bin/zeek"
_chk "Python venv"                      "[ -f '$PROJECT_DIR/venv/bin/python3' ]"
_chk "Python packages (dash)"           "'$PROJECT_DIR/venv/bin/python3' -c 'import dash'"
_chk "Database file"                    "find '$PROJECT_DIR' -name 'iotsentinel.db' -maxdepth 4 | grep -q ."
_chk "systemd service installed"        "[ -f '/etc/systemd/system/iotsentinel-dashboard.service' ]"
_chk "systemd service enabled"          "systemctl is-enabled --quiet iotsentinel-dashboard 2>/dev/null"

if ! $SKIP_OLLAMA; then
    _chk "Ollama binary"                "command -v ollama"
    _chk "${MODEL} model"               "ollama list 2>/dev/null | grep -q '${MODEL%%:*}'"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${GREEN}  Setup complete — ${PASS} checks passed, ${SKIP} pending${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
PI_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
echo "  Open your browser on the same network and go to:"
echo ""
echo -e "     ${BLUE}http://${PI_IP:-<pi-ip>}:8050/setup${NC}"
echo ""
echo "  Complete the 6-step wizard to finish configuration."
echo "  The dashboard autostarts on every reboot."
if ! $SKIP_OLLAMA; then
    echo "  AI explanations: powered by ${MODEL} running locally on the Pi."
fi
echo ""
