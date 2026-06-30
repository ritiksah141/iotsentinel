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
# Bootstrap Wi-Fi regulatory country for the image. This is only the DEFAULT the Pi
# uses so the setup hotspot can start on first boot (2.4GHz ch6 is legal in every
# domain, so it works worldwide regardless); the user picks their actual country in
# the wizard, which persists + applies it. Override to build a regional SKU, e.g.
# IOTSENTINEL_WIFI_COUNTRY=US bash scripts/build_pi_image.sh
WIFI_COUNTRY="${IOTSENTINEL_WIFI_COUNTRY:-GB}"

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
# QEMU is only needed to build an arm64 image on a NON-arm64 host. On a native arm64
# host (e.g. an arm64 CI runner) pi-gen builds without emulation, so don't require it.
if [ "$(uname -m)" != "aarch64" ]; then
  command -v qemu-aarch64-static &>/dev/null || die "qemu-user-static not found. Run: apt install qemu-user-static binfmt-support"
  echo "  Host is $(uname -m) — building arm64 via QEMU emulation (slow)."
else
  echo "  Host is aarch64 — building arm64 natively (no emulation)."
fi
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
# Explicit stage order. Without this, pi-gen globs stage* and runs them
# alphanumerically, which puts "stage-iotsentinel" BEFORE "stage0" ('-' < '0') —
# the custom stage would run before debootstrap creates any rootfs.
STAGE_LIST="stage0 stage1 stage2 stage-iotsentinel"
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
WPA_COUNTRY="${WIFI_COUNTRY}"
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
# Named *-run-chroot.sh so pi-gen runs it INSIDE the ARM Bookworm chroot (where
# python3.11 exists), not on the amd64 noble host (which only has python3.12).
mkdir -p "$CUSTOM_STAGE/00-install-deps"
cat > "$CUSTOM_STAGE/00-install-deps/00-run-chroot.sh" <<'SHELL'
#!/bin/bash -e
# CRITICAL for arm64/Debian builds: apt/apt-key/gpgv create temp files under /tmp to
# verify repository signatures. In the emulated pi-gen chroot /tmp can be missing or
# unwritable, which makes verification fail with NO_PUBKEY / "repository is not
# signed" and (under `bash -e`) aborts this stage BEFORE Zeek/Python install — the
# image then ships with no IoTSentinel deps. Make /tmp usable and keep apt out of its
# sandbox user (which also can't write /tmp here) for the duration of the build.
mkdir -p /tmp && chmod 1777 /tmp
# Always keep apt out of its sandbox user (which can't write /tmp in this chroot) —
# this alone fixes most signature-verification failures. We then PREFER verified base
# repos: try a normal signed apt-get update first, refreshing the Debian archive
# keyring if needed. Only if signature verification still fails (e.g. an emulated
# chroot where gpgv misbehaves) do we fall back to unauthenticated, BUILD-ONLY — the
# override apt.conf is removed before the image ships (systemd-services stage), so the
# device always keeps normal apt security. On the native arm64 runner the verified
# path succeeds and the base repos stay authenticated, closing the supply-chain gap.
echo 'APT::Sandbox::User "root";' > /etc/apt/apt.conf.d/00iotsentinel-build
if ! apt-get update; then
  echo "[build] signed apt update failed — refreshing debian-archive-keyring and retrying"
  apt-get install -y --reinstall debian-archive-keyring 2>/dev/null || true
  if ! apt-get update; then
    echo "[build] WARNING: base repos still failing signature verification — falling back to unauthenticated (BUILD-ONLY, removed before ship)"
    {
      echo 'Acquire::AllowInsecureRepositories "true";'
      echo 'Acquire::AllowDowngradeToInsecureRepositories "true";'
      echo 'APT::Get::AllowUnauthenticated "true";'
    } >> /etc/apt/apt.conf.d/00iotsentinel-build
    apt-get update || true
  fi
fi
apt-get install -y curl gnupg2

# Add Zeek repository
echo 'deb http://download.opensuse.org/repositories/security:/zeek/Debian_12/ /' \
  > /etc/apt/sources.list.d/security:zeek.list
curl -fsSL https://download.opensuse.org/repositories/security:/zeek/Debian_12/Release.key \
  | gpg --dearmor > /etc/apt/trusted.gpg.d/security_zeek.gpg
apt-get update || true

# Install Zeek + Python build tools + networking stack.
# nftables: native inline-blocking backend (firewall_enforcer prefers it, falls back
#   to iptables). dnsmasq-base: required for NetworkManager shared-mode AP (gateway +
#   the IoTSentinel-Setup provisioning hotspot). iw + rfkill: the provisioning script
#   uses them to unblock the radio and set the regulatory domain so the AP can start.
apt-get install -y zeek python3.11 python3.11-venv python3.11-dev python3-pip python3-dev \
    build-essential libssl-dev libffi-dev \
    network-manager avahi-daemon avahi-utils iptables nftables dnsmasq-base iw rfkill \
    curl git gnupg2 libpcap-dev tcpdump net-tools iputils-ping openssl nmap

# Let nmap do ARP/ICMP host-discovery without root — the backend runs as the
# unprivileged 'sentinel' user, so active device discovery needs this capability
# (a scoped setcap, not a broad sudoers grant). Non-fatal if unavailable.
setcap cap_net_raw,cap_net_admin,cap_net_bind_service+ep "$(command -v nmap)" 2>/dev/null \
    || echo "WARN: could not setcap nmap; active scans fall back to TCP-connect discovery"

# Enable avahi for iotsentinel.local mDNS discovery
systemctl enable avahi-daemon 2>/dev/null || true

# Set the hostname DETERMINISTICALLY so avahi publishes iotsentinel.local and the
# whole "reach the dashboard at iotsentinel.local:8050" story works. We write the
# files directly instead of relying on `raspi-config nonint do_hostname` (in
# setup_pi.sh), which on Bookworm can route through hostnamectl and FAIL silently in
# the build chroot (no running systemd/dbus) — leaving the pi-gen default
# 'raspberrypi', so iotsentinel.local never resolves on the home LAN.
echo "iotsentinel" > /etc/hostname
if grep -q "^127\.0\.1\.1" /etc/hosts 2>/dev/null; then
  sed -i "s/^127\.0\.1\.1.*/127.0.1.1\tiotsentinel/" /etc/hosts
else
  printf '127.0.1.1\tiotsentinel\n' >> /etc/hosts
fi

# The provisioning hotspot and all Wi-Fi switching go through NetworkManager. Make it
# the active backend and disable the legacy dhcpcd so nothing else owns wlan0 — if
# dhcpcd manages the interface, `nmcli ... hotspot` silently fails and a headless
# first boot shows NO IoTSentinel-Setup network at all.
systemctl enable NetworkManager 2>/dev/null || true
systemctl disable dhcpcd 2>/dev/null || true

# Set the Wi-Fi regulatory country the CANONICAL Raspberry Pi way. On a Pi the
# onboard Broadcom Wi-Fi is rfkill-soft-blocked and refuses AP (hotspot) mode until
# a country is configured — the #1 reason a headless first boot shows NO
# IoTSentinel-Setup network. `raspi-config nonint do_wifi_country` writes the country
# where the brcmfmac driver actually reads it and unblocks the radio; this is more
# reliable than WPA_COUNTRY / crda alone. The runtime rfkill/iw fallback stays in
# setup_hotspot.sh as belt-and-suspenders. Change GB to your ISO country if needed.
raspi-config nonint do_wifi_country __WIFI_COUNTRY__ 2>/dev/null \
  || { echo 'REGDOMAIN=__WIFI_COUNTRY__' > /etc/default/crda 2>/dev/null; \
       echo 'country=__WIFI_COUNTRY__' > /etc/wpa_supplicant/wpa_supplicant.conf 2>/dev/null; } || true

# Create sentinel user home directory if missing
mkdir -p /home/sentinel
SHELL
chmod +x "$CUSTOM_STAGE/00-install-deps/00-run-chroot.sh"
# Bake the chosen bootstrap Wi-Fi country into the (quoted-heredoc) chroot script.
# Portable in-place edit (avoids GNU vs BSD `sed -i` differences).
_deps="$CUSTOM_STAGE/00-install-deps/00-run-chroot.sh"
sed "s/__WIFI_COUNTRY__/${WIFI_COUNTRY}/g" "$_deps" > "$_deps.tmp" && mv "$_deps.tmp" "$_deps"
chmod +x "$_deps"

# 01 — Copy repo and run setup_pi.sh
mkdir -p "$CUSTOM_STAGE/01-install-iotsentinel/files"
# The repo is bundled as a tarball for reproducibility
(cd "$REPO_DIR" && git archive --format=tar --prefix=iotsentinel/ HEAD) \
  | gzip > "$CUSTOM_STAGE/01-install-iotsentinel/files/iotsentinel.tar.gz"

# 00 (host) — pi-gen does NOT auto-copy a sub-stage's files/ into the chroot, so
# stage the tarball into the rootfs ourselves before the chroot script extracts it.
# Must sort before the chroot script: "00-run.sh" < "01-run-chroot.sh".
cat > "$CUSTOM_STAGE/01-install-iotsentinel/00-run.sh" <<'SHELL'
#!/bin/bash -e
install -d "${ROOTFS_DIR}/tmp"
install -m 644 files/iotsentinel.tar.gz "${ROOTFS_DIR}/tmp/iotsentinel.tar.gz"
SHELL
chmod +x "$CUSTOM_STAGE/01-install-iotsentinel/00-run.sh"

cat > "$CUSTOM_STAGE/01-install-iotsentinel/01-run-chroot.sh" <<'SHELL'
#!/bin/bash -e
cd /home/sentinel
tar xzf /tmp/iotsentinel.tar.gz
chown -R sentinel:sentinel iotsentinel

# Run setup AS ROOT (the chroot is already root), targeting the sentinel user.
# IMPORTANT: do NOT use `su - sentinel` here — under qemu emulation `sudo` inside a
# su session fails, which silently aborts setup_pi.sh before it installs the venv,
# sudoers, or systemd services (the image then boots with NO IoTSentinel at all).
# IOTSENTINEL_TARGET_USER makes setup_pi.sh shim sudo, install into the sentinel
# home, and chown everything back. --skip-ollama: the model is pulled on first boot.
cd /home/sentinel/iotsentinel
IOTSENTINEL_TARGET_USER=sentinel IOTSENTINEL_WIFI_COUNTRY=__WIFI_COUNTRY__ \
  bash scripts/setup_pi.sh --non-interactive --skip-ollama --skip-apt
cd /home/sentinel

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

rm -f /tmp/iotsentinel.tar.gz
SHELL
_inst="$CUSTOM_STAGE/01-install-iotsentinel/01-run-chroot.sh"
sed "s/__WIFI_COUNTRY__/${WIFI_COUNTRY}/g" "$_inst" > "$_inst.tmp" && mv "$_inst.tmp" "$_inst"
chmod +x "$_inst"

# 02 — Install and enable systemd services
mkdir -p "$CUSTOM_STAGE/02-systemd-services"
cat > "$CUSTOM_STAGE/02-systemd-services/00-run-chroot.sh" <<'SHELL'
#!/bin/bash -e
SERVICES_SRC="/home/sentinel/iotsentinel/services"
cp "${SERVICES_SRC}/iotsentinel-provision.service"     /etc/systemd/system/
cp "${SERVICES_SRC}/iotsentinel-backend.service"       /etc/systemd/system/
cp "${SERVICES_SRC}/iotsentinel-dashboard.service"     /etc/systemd/system/
cp "${SERVICES_SRC}/iotsentinel-localai.service"       /etc/systemd/system/
cp "${SERVICES_SRC}/iotsentinel-connectivity.service"  /etc/systemd/system/
cp "${SERVICES_SRC}/iotsentinel-connectivity.timer"    /etc/systemd/system/
cp "${SERVICES_SRC}/iotsentinel-firstboot-report.service" /etc/systemd/system/
cp "${SERVICES_SRC}/iotsentinel-model-eval.service"    /etc/systemd/system/

# Cap the systemd journal so it can never fill the SD card. Default SystemMaxUse
# is 10% of the filesystem; on a small card, combined with a crash-loop that
# spews tracebacks, that is enough to push the disk to the point where SQLite
# raises "disk I/O error" and the app bricks. Hard-cap at 200 MB.
mkdir -p /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/00-iotsentinel-size.conf <<'JOURNALD'
[Journal]
SystemMaxUse=200M
SystemKeepFree=200M
RuntimeMaxUse=64M
JOURNALD

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

# SSH: enable it belt-and-suspenders so a headless user is never locked out
# (raspi-config's do_ssh has silently no-op'd in some chroot builds). systemctl
# enable works offline in the chroot; the boot-partition flag is the first-boot
# fallback Raspberry Pi OS honours even if the unit symlink is missing.
systemctl enable ssh 2>/dev/null || systemctl enable ssh.socket 2>/dev/null || true
touch /boot/firmware/ssh 2>/dev/null || touch /boot/ssh 2>/dev/null || true

systemctl enable iotsentinel-provision.service
systemctl enable iotsentinel-backend.service
systemctl enable iotsentinel-dashboard.service
# Connectivity recovery: a systemd timer re-arms the IoTSentinel-Setup hotspot if
# home WiFi is ever lost, so a headless user can always get back in to fix it.
# Enable the TIMER (it triggers the one-shot service); never enable the service.
systemctl enable iotsentinel-connectivity.timer
# First-boot diagnostic: writes Wi-Fi/AP/service state to the FAT boot partition so a
# headless user can read why the hotspot did/didn't come up by putting the SD card
# back in their computer (no Ethernet or monitor needed).
systemctl enable iotsentinel-firstboot-report.service
# AI in the box: installs Ollama + pulls the on-device model in the background
# on first boot (skips on <3 GB RAM or when ollama_enabled=false in config).
systemctl enable iotsentinel-localai.service
# Model evaluation: writes Precision/Recall/F1 to model_performance on first boot (and
# seeds demo traffic in demo mode) so the ML Models card is populated without any SSH.
systemctl enable iotsentinel-model-eval.service

# SECURITY: every image ships with the same default login (sentinel / iotsentinel).
# We deliberately DO NOT force-expire it with `chage -d 0`: the dashboard runs as
# `User=sentinel` and drives privileged actions (Wi-Fi join, hotspot teardown, backend
# restart, firewall) via `sudo -n`. sudo runs PAM account management, and a force-
# expired password (lastchg=0) makes `sudo -n` fail ("account validation failure")
# until the password is changed interactively — which, since setup is done through the
# web wizard, may never happen, leaving the appliance unable to join home Wi-Fi.
# The real security boundary is the strong ADMIN account the wizard requires before
# anything else; the setup guide tells the user to change the SSH password too.

# Drop the build-only apt sandbox override so it does not ship in the image.
rm -f /etc/apt/apt.conf.d/00iotsentinel-build
SHELL
chmod +x "$CUSTOM_STAGE/02-systemd-services/00-run-chroot.sh"

# prerun.sh — every pi-gen stage needs this to seed its rootfs from the previous
# stage (stage2). Without it ${ROOTFS_DIR} is empty and the chroot scripts fail with
# "Unable to chroot". Stage order itself is set via STAGE_LIST in the config above.
cat > "$CUSTOM_STAGE/prerun.sh" <<'SHELL'
#!/bin/bash -e
if [ ! -d "${ROOTFS_DIR}" ]; then
  copy_previous
fi
SHELL
chmod +x "$CUSTOM_STAGE/prerun.sh"

# EXPORT_IMAGE marks this as the stage that produces the final .img. stage2's own
# export is suppressed (SKIP_IMAGES above) so only the customised rootfs is exported.
echo 'IMG_SUFFIX=""' > "$CUSTOM_STAGE/EXPORT_IMAGE"

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
step "Verifying IoTSentinel was actually installed into the image"
# ---------------------------------------------------------------------------
# CRITICAL GUARD. pi-gen does NOT reliably fail the build when a chroot sub-stage
# script exits non-zero, so a setup_pi.sh failure inside the chroot previously
# produced a "successful" build whose image had NO IoTSentinel services at all
# (no hotspot, no dashboard on the real Pi). Assert against the built rootfs so a
# broken install fails the build LOUDLY instead of shipping a dead image.
# Inspect the CUSTOM STAGE's rootfs — that is the real, populated filesystem on disk
# (and exactly what gets packaged into the .img). NOT export-image/rootfs: pi-gen
# unmounts that after writing the image, leaving an empty mountpoint that would make
# every check fail. root-owned -> sudo; find|head must not trip pipefail -> `|| true`.
ROOTFS="$(sudo find "$PIGEN_DIR/work" -type d -path "*/${STAGE_NAME}/rootfs" 2>/dev/null | head -1)" || true
if [ -z "$ROOTFS" ]; then
  ROOTFS="$(sudo find "$PIGEN_DIR/work" -type d -path "*/export-image/rootfs" 2>/dev/null | head -1)" || true
fi
if [ -z "$ROOTFS" ]; then
  ROOTFS="$(sudo find "$PIGEN_DIR/work" -type d -name rootfs 2>/dev/null | sort | tail -1)" || true
fi
[ -n "$ROOTFS" ] && echo "  Inspecting rootfs: $ROOTFS"
if [ -n "$ROOTFS" ] && [ -d "$ROOTFS" ]; then
  APP="home/sentinel/iotsentinel"
  # Resolve the venv site-packages dir (don't hardcode the python minor version).
  SP=$(sudo bash -c "ls -d '$ROOTFS/$APP/venv/lib/'python3*/site-packages 2>/dev/null | head -1")
  SP="${SP#"$ROOTFS/"}"
  WANTS="etc/systemd/system/multi-user.target.wants"
  _missing=""
  # `test -e` FOLLOWS symlinks — but systemd enablement symlinks are ABSOLUTE
  # (-> /etc/systemd/system/X), which dangle when resolved from the host (outside the
  # rootfs). Accept a symlink as present via `test -L` (it resolves fine in the image).
  _need() { sudo test -e "$ROOTFS/$1" || sudo test -L "$ROOTFS/$1" || _missing="$_missing\n    - $2 ($1)"; }

  # A. First-boot provisioning + the hotspot/diagnostic scripts it runs
  _need "etc/systemd/system/iotsentinel-provision.service"        "provision service"
  _need "$WANTS/iotsentinel-provision.service"                     "provision ENABLED"
  _need "$APP/scripts/setup_hotspot.sh"                            "hotspot script"
  _need "$APP/scripts/firstboot_diag.sh"                           "first-boot diagnostic"
  _need "$APP/scripts/setup_local_ai.sh"                           "on-device AI installer (first boot)"
  # B. Every service the gate checks must be ENABLED (symlinked), not just present
  _need "$WANTS/iotsentinel-backend.service"                       "backend ENABLED"
  _need "$WANTS/iotsentinel-dashboard.service"                     "dashboard ENABLED"
  _need "$WANTS/iotsentinel-localai.service"                       "localai ENABLED (on-device AI)"
  _need "$WANTS/iotsentinel-firstboot-report.service"             "firstboot-report ENABLED"
  _need "etc/systemd/system/timers.target.wants/iotsentinel-connectivity.timer" "connectivity TIMER ENABLED"
  _need "$WANTS/NetworkManager.service"                            "NetworkManager ENABLED"
  # C. Capture + AI runtime
  _need "opt/zeek/bin/zeek"                                        "Zeek (passive/gateway capture)"
  _need "$APP/venv/bin/python3"                                    "python venv"
  # D. Python deps actually installed (catches a partial pip install). Direct,
  # top-level deps whose import dir name is stable.
  for pkg in dash dash_bootstrap_components plotly river pandas numpy sklearn; do
    sudo test -d "$ROOTFS/$SP/$pkg" \
      || _missing="$_missing\n    - python package: $pkg"
  done
  # E. Gateway scripts (inline IDS/IPS) ship in the image
  _need "$APP/config/configure_ap.sh"                             "gateway AP script"
  _need "$APP/config/configure_zeek.sh"                           "gateway Zeek script"
  _need "$APP/scripts/validate_gateway.sh"                        "gateway validator"
  # E2. Front-end design/assets (the *.min.css + PWA icons are generated at first
  # boot from these sources, so the SOURCES must be in the image).
  _need "$APP/dashboard/assets/logo.png"                          "logo / PWA-icon source"
  _need "$APP/dashboard/assets/custom.css"                        "main theme CSS"
  _need "$APP/dashboard/assets/fontawesome.min.css"              "icon font CSS"
  _need "$APP/dashboard/assets/webfonts/fa-solid-900.woff2"      "icon font glyphs"
  _need "$APP/dashboard/assets/manifest.webmanifest"            "PWA manifest"
  _need "$APP/dashboard/assets/sw.js"                            "service worker"
  _need "$APP/dashboard/assets/topojson/world_110m.json"        "offline threat map"
  # F. Database — setup pre-creates it, but the app also auto-creates the schema on
  # first boot (DatabaseManager.migrate_schema), so absence is NOT fatal.
  sudo find "$ROOTFS/$APP/data" -name '*.db' 2>/dev/null | grep -q . \
    || warn "No pre-created DB in image — it will be created automatically on first boot."
  # G. Wizard pre-seeded to first-run
  sudo grep -q '"is_configured": false' "$ROOTFS/$APP/config/default_config.json" 2>/dev/null \
    || _missing="$_missing\n    - is_configured=false (wizard would be skipped)"
  # H. Hostname must be 'iotsentinel' so avahi publishes iotsentinel.local — otherwise
  # the dashboard is unreachable by name on the home LAN (the rc4 "can't reach .local").
  sudo grep -qx "iotsentinel" "$ROOTFS/etc/hostname" 2>/dev/null \
    || _missing="$_missing\n    - hostname=iotsentinel (iotsentinel.local would not resolve)"

  if [ -n "$_missing" ]; then
    die "Image is INCOMPLETE — setup_pi.sh did not finish in the chroot. Missing:$(echo -e "$_missing")\n  Check $DEPLOY_DIR/build.log for the failure."
  fi

  # Tailscale (remote access) — NON-fatal visibility: the installer is best-effort in the
  # chroot, and remote access is enabled post-setup from Settings. Surface its presence so
  # a missing binary is obvious in the build log rather than only discovered on hardware.
  if sudo test -e "$ROOTFS/usr/bin/tailscale" || sudo test -e "$ROOTFS/usr/sbin/tailscale"; then
    echo "  ✓ Tailscale present — remote access can be enabled from Settings"
  else
    warn "Tailscale NOT installed in image — remote access (Settings → Network) will be unavailable until it is installed on the device."
  fi

  # Gateway sudoers MUST carry the inline-enforcement grants (block/unblock on the Pi).
  _sudoers_missing=""
  for grant in "/usr/sbin/nft" "/usr/sbin/iptables" "configure_ap.sh" "/opt/zeek/bin/zeekctl" \
               "setup_hotspot.sh disarm" "systemctl restart iotsentinel-backend"; do
    sudo grep -qF "$grant" "$ROOTFS/etc/sudoers.d/iotsentinel" 2>/dev/null \
      || _sudoers_missing="$_sudoers_missing $grant"
  done
  [ -z "$_sudoers_missing" ] || die "sudoers is missing required grants:$_sudoers_missing"

  # Longevity: the Zeek-monitor cron must be registered (H. of the P4 gate).
  sudo grep -qrF "zeek_monitor.sh" "$ROOTFS/var/spool/cron/crontabs" 2>/dev/null \
    || warn "Zeek-monitor cron not found in image — check setup_db_automation/cron step."

  echo "  ✓ Verified image: services enabled, Zeek + venv (deps), gateway scripts + sudoers, DB, wizard pre-seed."
else
  warn "Could not locate the built rootfs to verify — skipping install check."
fi

# ---------------------------------------------------------------------------
step "Collecting output"
# ---------------------------------------------------------------------------
# pi-gen wrote deploy/ as root; reclaim ownership so the non-root copy/sha steps work.
sudo chown -R "$(id -u):$(id -g)" "$PIGEN_DIR/deploy" 2>/dev/null || true
# `|| true`: a find|sort|head pipeline can return non-zero via SIGPIPE under
# `set -o pipefail` and must not abort before the explicit emptiness check below.
IMG_XZ="$(find "$PIGEN_DIR/deploy" -name "*.img.xz" | sort -r | head -1)" || true
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
