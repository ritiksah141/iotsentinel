#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# configure_ap.sh — bring up (or tear down) the IoTSentinel Wi-Fi access point.
#
# In gateway capture mode the Pi serves a dedicated Wi-Fi network on a USB Wi-Fi
# adapter (network.ap_interface). IoT devices join it, so all their traffic + DNS
# route through the Pi and Zeek (pointed at ap_interface) sees everything. We use
# NetworkManager "shared" mode, which provides DHCP + DNS (dnsmasq) + NAT +
# ip_forward to the active uplink automatically — no hand-rolled hostapd/iptables.
#
# SAFETY: this script ONLY manages its own connection profile ("iotsentinel-ap")
# on the AP interface. It never touches the home-Wi-Fi uplink connection, so it
# cannot break the user's home network. Idempotent and non-fatal.
#
# Usage:
#   sudo bash configure_ap.sh            # bring the AP up from config (gateway mode)
#   sudo bash configure_ap.sh --down     # tear the AP down (rollback / safe-mode)
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CFG="$PROJECT_DIR/config/default_config.json"
CON="iotsentinel-ap"
LOG_FILE="$PROJECT_DIR/data/logs/ap_configure.log"

mkdir -p "$(dirname "$LOG_FILE")"
log() { echo "$(date '+%Y-%m-%d %H:%M:%S') $*" | tee -a "$LOG_FILE"; }

if ! command -v nmcli >/dev/null 2>&1; then
    log "nmcli not available — cannot manage the access point. Skipping."
    exit 0
fi

# Tear-down path (used by rollback / safe-mode). Never fatal.
if [ "${1:-}" = "--down" ]; then
    nmcli connection down "$CON" >/dev/null 2>&1 || true
    log "Access point '$CON' brought down."
    exit 0
fi

# ── Read AP settings from config ────────────────────────────────────────────────
read_cfg() {
    python3 -c "
import json, ipaddress
try:
    n = json.load(open('$CFG')).get('network', {})
    subnet = n.get('ap_subnet') or '10.42.0.0/24'
    net = ipaddress.ip_network(subnet, strict=False)
    gw = str(net.network_address + 1)
    prefix = net.prefixlen
    print('|'.join([
        n.get('capture_mode') or 'passive',
        n.get('ap_interface') or 'wlan1',
        n.get('ap_ssid') or 'IoTSentinel',
        n.get('ap_password') or '',
        n.get('ap_band') or 'bg',
        str(n.get('ap_channel') or 6),
        gw, str(prefix),
    ]))
except Exception:
    print('')
" 2>/dev/null
}

IFS='|' read -r MODE AP_IFACE SSID PASSWORD BAND CHANNEL GW PREFIX <<< "$(read_cfg)"

if [ "${MODE:-passive}" != "gateway" ]; then
    log "capture_mode is '${MODE:-passive}', not 'gateway' — AP not started."
    exit 0
fi
if [ -z "${AP_IFACE:-}" ] || [ ! -e "/sys/class/net/$AP_IFACE" ]; then
    log "AP interface '${AP_IFACE:-?}' not present (USB Wi-Fi adapter plugged in?) — skipping."
    exit 0
fi
if [ -z "${PASSWORD:-}" ] || [ "${#PASSWORD}" -lt 8 ]; then
    log "AP password missing or shorter than 8 characters — refusing to start an open/weak AP."
    exit 0
fi

# ── Create or update the AP connection profile ──────────────────────────────────
if nmcli -t -f NAME connection show 2>/dev/null | grep -qx "$CON"; then
    log "Updating existing AP profile '$CON' on ${AP_IFACE}."
else
    log "Creating AP profile '$CON' on ${AP_IFACE}."
    nmcli connection add type wifi ifname "$AP_IFACE" con-name "$CON" \
        autoconnect yes ssid "$SSID" >>"$LOG_FILE" 2>&1 || {
        log "Failed to create AP connection."; exit 0; }
fi

nmcli connection modify "$CON" \
    connection.interface-name "$AP_IFACE" \
    connection.autoconnect yes \
    802-11-wireless.mode ap \
    802-11-wireless.ssid "$SSID" \
    802-11-wireless.band "$BAND" \
    802-11-wireless.channel "$CHANNEL" \
    ipv4.method shared \
    ipv4.addresses "${GW}/${PREFIX}" \
    wifi-sec.key-mgmt wpa-psk \
    wifi-sec.psk "$PASSWORD" >>"$LOG_FILE" 2>&1 || {
    log "Failed to configure AP connection."; exit 0; }

if nmcli connection up "$CON" >>"$LOG_FILE" 2>&1; then
    log "Access point '$SSID' is up on ${AP_IFACE} (gateway ${GW}/${PREFIX})."
else
    log "AP profile saved but activation reported an error — see entries above."
fi
exit 0
