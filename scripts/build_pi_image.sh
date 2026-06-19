#!/usr/bin/env bash
# build_pi_image.sh — Build a Raspberry Pi OS custom image with IoTSentinel pre-installed.
#
# Prerequisites (on Ubuntu runner or dev machine):
#   apt install coreutils qemu-user-static binfmt-support git
#   pi-gen cloned to ../pi-gen  (or set PIGEN_DIR)
#
# Usage:
#   bash scripts/build_pi_image.sh [--tag v1.0.0] [--pigen-dir /path/to/pi-gen]
#
# Outputs:
#   deploy/  — contains IoTSentinel-<TAG>.img.xz and IoTSentinel-<TAG>.img.xz.sha256
#
# What the image does on first boot:
#   1. Pi boots Raspberry Pi OS Lite (64-bit, Bookworm)
#   2. Zeek + Python 3.11 + Tailscale are pre-installed
#   3. IoTSentinel is pre-installed at /home/pi/iotsentinel
#   4. Systemd services (backend + dashboard + provision + localai) are enabled and start on boot
#   5. Provision service creates an "IoTSentinel-Setup" hotspot
#   6. is_configured=false → browser wizard served at http://10.42.0.1:8050/setup
#   7. WiFi / admin password / remote access = configured inside the 6-step browser wizard
#   8. Once online, localai service installs Ollama + pulls gemma2:2b in the
#      background (niced, ~1.6 GB) — on-device AI with zero accounts/keys.
#      Skipped automatically on <3 GB RAM or when ollama_enabled=false.
#
# This script does NOT bake in WiFi credentials or a fixed password.
# All first-boot personalisation happens inside the browser wizard.

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TAG="${TAG:-$(git -C "$REPO_DIR" describe --tags --abbrev=0 2>/dev/null || echo "v1.0.0")}"
PIGEN_DIR="${PIGEN_DIR:-${REPO_DIR}/../pi-gen}"
DEPLOY_DIR="${REPO_DIR}/deploy"
STAGE_NAME="stage-iotsentinel"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'

step() { echo -e "\n${GREEN}▶ $*${NC}"; }
warn() { echo -e "${YELLOW}⚠  $*${NC}"; }
die()  { echo -e "${RED}✗ $*${NC}"; exit 1; }

# Parse args
for arg in "$@"; do
  case $arg in
    --tag=*)     TAG="${arg#*=}" ;;
    --pigen-dir=*) PIGEN_DIR="${arg#*=}" ;;
  esac
done

# ---------------------------------------------------------------------------
step "Checking prerequisites"
# ---------------------------------------------------------------------------
command -v qemu-aarch64-static &>/dev/null || die "qemu-user-static not found. Run: apt install qemu-user-static binfmt-support"
command -v git &>/dev/null || die "git not found"
[ -d "$PIGEN_DIR" ] || die "pi-gen directory not found at $PIGEN_DIR. Clone it: git clone https://github.com/RPi-Distro/pi-gen $PIGEN_DIR"

echo "  Repo: $REPO_DIR"
echo "  Tag:  $TAG"
echo "  pi-gen: $PIGEN_DIR"

# ---------------------------------------------------------------------------
step "Configuring pi-gen"
# ---------------------------------------------------------------------------
cat > "$PIGEN_DIR/config" <<EOF
IMG_NAME="IoTSentinel"
RELEASE="bookworm"
DEPLOY_COMPRESSION="xz"
LOCALE_DEFAULT="en_US.UTF-8"
TARGET_HOSTNAME="iotsentinel"
KEYBOARD_KEYMAP="gb"
KEYBOARD_LAYOUT="English (UK)"
TIMEZONE_DEFAULT="Europe/London"
FIRST_USER_NAME="sentinel"
FIRST_USER_PASS="iotsentinel"
ENABLE_SSH=1
WPA_ESSID=""
WPA_PASSWORD=""
WPA_COUNTRY="GB"
EOF

# Disable stages we don't need (desktop, recommended packages)
for stage in stage3 stage4 stage5; do
  touch "$PIGEN_DIR/$stage/SKIP" 2>/dev/null || true
done
# We build up to stage2 (headless server) + our custom stage
touch "$PIGEN_DIR/stage2/SKIP_IMAGES" 2>/dev/null || true

# ---------------------------------------------------------------------------
step "Creating custom pi-gen stage: $STAGE_NAME"
# ---------------------------------------------------------------------------
CUSTOM_STAGE="$PIGEN_DIR/$STAGE_NAME"
rm -rf "$CUSTOM_STAGE"
mkdir -p "$CUSTOM_STAGE/files"

# 00 — Install system dependencies (Zeek, Python 3.11, tools)
mkdir -p "$CUSTOM_STAGE/00-install-deps"
cat > "$CUSTOM_STAGE/00-install-deps/00-run.sh" <<'SHELL'
#!/bin/bash -e
# Install Zeek via apt (official Zeek repository for Debian Bookworm)
apt-get install -y curl gnupg2

# Add Zeek repository
echo 'deb http://download.opensuse.org/repositories/security:/zeek/Debian_12/ /' \
  > /etc/apt/sources.list.d/security:zeek.list
curl -fsSL https://download.opensuse.org/repositories/security:/zeek/Debian_12/Release.key \
  | gpg --dearmor > /etc/apt/trusted.gpg.d/security_zeek.gpg
apt-get update

# Install Zeek + Python build tools + networking stack.
# nftables: native inline-blocking backend (firewall_enforcer prefers it, falls back
#   to iptables). dnsmasq-base: required for NetworkManager shared-mode AP (gateway).
apt-get install -y zeek python3.11 python3.11-venv python3-pip build-essential libssl-dev \
    network-manager avahi-daemon avahi-utils iptables nftables dnsmasq-base

# Enable avahi for iotsentinel.local mDNS discovery
systemctl enable avahi-daemon 2>/dev/null || true

# Create sentinel user home directory if missing
mkdir -p /home/sentinel
SHELL
chmod +x "$CUSTOM_STAGE/00-install-deps/00-run.sh"

# 01 — Copy repo and run setup_pi.sh
mkdir -p "$CUSTOM_STAGE/01-install-iotsentinel/files"
# The repo is bundled as a tarball for reproducibility
(cd "$REPO_DIR" && git archive --format=tar --prefix=iotsentinel/ HEAD) \
  | gzip > "$CUSTOM_STAGE/01-install-iotsentinel/files/iotsentinel.tar.gz"

cat > "$CUSTOM_STAGE/01-install-iotsentinel/00-run-chroot.sh" <<'SHELL'
#!/bin/bash -e
cd /home/sentinel
tar xzf /tmp/iotsentinel_stage/iotsentinel.tar.gz
chown -R sentinel:sentinel iotsentinel

# Run setup as the sentinel user
su - sentinel -c "cd /home/sentinel/iotsentinel && bash scripts/setup_pi.sh --non-interactive"

# Pre-seed is_configured=false so first boot shows the wizard
python3 -c "
import json, pathlib
p = pathlib.Path('/home/sentinel/iotsentinel/config/default_config.json')
d = json.loads(p.read_text())
d.setdefault('system', {})['is_configured'] = False
p.write_text(json.dumps(d, indent=2))
"

# Remove the build-time FLASK_SECRET_KEY so it is NOT shared across every flashed
# device. The provision service regenerates a unique key per device on first boot.
sed -i '/^FLASK_SECRET_KEY=/d' /home/sentinel/iotsentinel/.env 2>/dev/null || true
SHELL
chmod +x "$CUSTOM_STAGE/01-install-iotsentinel/00-run-chroot.sh"

# 02 — Install and enable systemd services
mkdir -p "$CUSTOM_STAGE/02-systemd-services"
cat > "$CUSTOM_STAGE/02-systemd-services/00-run-chroot.sh" <<'SHELL'
#!/bin/bash -e
SERVICES_SRC="/home/sentinel/iotsentinel/services"
cp "${SERVICES_SRC}/iotsentinel-provision.service" /etc/systemd/system/
cp "${SERVICES_SRC}/iotsentinel-backend.service"   /etc/systemd/system/
cp "${SERVICES_SRC}/iotsentinel-dashboard.service" /etc/systemd/system/
cp "${SERVICES_SRC}/iotsentinel-localai.service"   /etc/systemd/system/

# Sudoers are written by setup_pi.sh (stage 01) as the single source of truth, with
# the FULL gateway-mode set (nmcli, configure_ap.sh, configure_zeek.sh, nft, iptables,
# zeekctl). This stage must NOT overwrite that file — doing so previously dropped the
# nft/iptables/configure_ap permissions and silently broke gateway inline IDS/IPS.
# Instead, validate it so a future regression fails the build loudly.
SUDOERS=/etc/sudoers.d/iotsentinel
[ -f "$SUDOERS" ] || { echo "FATAL: $SUDOERS missing — setup_pi.sh did not run"; exit 1; }
visudo -cf "$SUDOERS" >/dev/null || { echo "FATAL: $SUDOERS has invalid syntax"; exit 1; }
for needed in "/usr/sbin/nft" "/usr/sbin/iptables" "configure_ap.sh"; do
  grep -qF "$needed" "$SUDOERS" || { echo "FATAL: $SUDOERS missing gateway perm: $needed"; exit 1; }
done
echo "[build] sudoers validated (gateway nft/iptables/configure_ap present)"

systemctl enable iotsentinel-provision.service
systemctl enable iotsentinel-backend.service
systemctl enable iotsentinel-dashboard.service
# AI in the box: installs Ollama + pulls the on-device model in the background
# on first boot (skips on <3 GB RAM or when ollama_enabled=false in config).
systemctl enable iotsentinel-localai.service
SHELL
chmod +x "$CUSTOM_STAGE/02-systemd-services/00-run-chroot.sh"

# Mark stage order for pi-gen
echo "$STAGE_NAME" >> "$PIGEN_DIR/STAGE_LIST" 2>/dev/null || true

# ---------------------------------------------------------------------------
step "Running pi-gen build (this takes 30-45 minutes)"
# ---------------------------------------------------------------------------
mkdir -p "$DEPLOY_DIR"

cd "$PIGEN_DIR"
# pi-gen's build.sh must run as root (it chroots, mounts loop devices, debootstraps).
# On a CI runner the step runs as a non-root user with passwordless sudo, so elevate.
# CLEAN=1 is passed through as an explicit sudo env assignment; the rest of the build
# config is read from the ./config file inside build.sh.
if [ "$(id -u)" -eq 0 ]; then
  CLEAN=1 bash build.sh 2>&1 | tee "$DEPLOY_DIR/build.log"
else
  sudo CLEAN=1 bash build.sh 2>&1 | tee "$DEPLOY_DIR/build.log"
fi

# ---------------------------------------------------------------------------
step "Collecting output"
# ---------------------------------------------------------------------------
# pi-gen wrote deploy/ as root; reclaim ownership so the non-root copy/sha steps work.
sudo chown -R "$(id -u):$(id -g)" "$PIGEN_DIR/deploy" 2>/dev/null || true
IMG_XZ=$(find "$PIGEN_DIR/deploy" -name "*.img.xz" | sort -r | head -1)
[ -n "$IMG_XZ" ] || die "No .img.xz found in $PIGEN_DIR/deploy — check $DEPLOY_DIR/build.log"

FINAL_NAME="IoTSentinel-${TAG}.img.xz"
cp "$IMG_XZ" "$DEPLOY_DIR/$FINAL_NAME"
sha256sum "$DEPLOY_DIR/$FINAL_NAME" > "$DEPLOY_DIR/$FINAL_NAME.sha256"

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Image ready: deploy/$FINAL_NAME${NC}"
echo -e "${GREEN}  SHA256: $(cat "$DEPLOY_DIR/$FINAL_NAME.sha256" | awk '{print $1}')${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Upload to GitHub Release:"
echo "  gh release upload $TAG deploy/$FINAL_NAME deploy/$FINAL_NAME.sha256"
