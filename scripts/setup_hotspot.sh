#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# setup_hotspot.sh — bring up the "IoTSentinel-Setup" provisioning hotspot when
# the Pi has no working home-Wi-Fi connection, so a headless user can always get
# back in to (re)configure WiFi.
#
# Single source of truth, shared by two systemd units:
#   - iotsentinel-provision.service   (first boot:  setup_hotspot.sh boot)
#   - iotsentinel-connectivity.timer  (every 2 min: setup_hotspot.sh recover)
#
# Modes:
#   boot      Arm the hotspot immediately if the Pi is not already on home WiFi.
#             Used during first-boot onboarding — no grace period.
#   recover   Runtime safety net. Requires several CONSECUTIVE offline checks
#             before arming, so a brief Wi-Fi blip never knocks the user onto the
#             setup AP. Once armed, the hotspot stays up (user fixes WiFi from the
#             dashboard's Settings → Network → Change WiFi, or reboots) — it never
#             flaps, which also avoids disrupting an in-progress setup session.
#
# MUST run as root (it is invoked by root system services). It calls nmcli and
# iptables directly; every operation is best-effort and never fatal.
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail

HOTSPOT="IoTSentinel-Setup"
IFACE="${IOTSENTINEL_WIFI_IFACE:-wlan0}"
PORT="${IOTSENTINEL_DASHBOARD_PORT:-8050}"
STATE_DIR="/run/iotsentinel"
FAIL_FILE="$STATE_DIR/offline_count"
FAIL_THRESHOLD="${IOTSENTINEL_OFFLINE_THRESHOLD:-3}"   # x 2-min timer ≈ 6 min offline

log() { echo "[hotspot] $*"; }

command -v nmcli >/dev/null 2>&1 || { log "nmcli not available — skipping"; exit 0; }
mkdir -p "$STATE_DIR" 2>/dev/null || true

# An active Wi-Fi connection that is NOT our own setup hotspot.
active_home_wifi() {
    nmcli -t -f NAME,TYPE,STATE device status 2>/dev/null \
        | grep ":wifi:" | grep ":connected:" | grep -v "$HOTSPOT" || true
}

hotspot_active() {
    nmcli -t -f NAME connection show --active 2>/dev/null | grep -q "^${HOTSPOT}\$"
}

arm_hotspot() {
    if hotspot_active; then log "hotspot already active"; return 0; fi
    log "no home WiFi — starting '$HOTSPOT' hotspot on $IFACE"
    nmcli device wifi hotspot ifname "$IFACE" ssid "$HOTSPOT" band bg channel 6 2>&1 | head -5 || true
    # Captive redirect: send any port-80 request to the dashboard. -C first so the
    # rule is never duplicated across repeated arms.
    iptables -t nat -C PREROUTING -i "$IFACE" -p tcp --dport 80 -j REDIRECT --to-port "$PORT" 2>/dev/null \
        || iptables -t nat -A PREROUTING -i "$IFACE" -p tcp --dport 80 -j REDIRECT --to-port "$PORT" 2>/dev/null || true
    sleep 2
    log "hotspot ready — join '$HOTSPOT' and open http://10.42.0.1:$PORT/setup"
}

MODE="${1:-recover}"
case "$MODE" in
    boot)
        if [ -n "$(active_home_wifi)" ]; then log "already on home WiFi — hotspot not needed"; exit 0; fi
        arm_hotspot
        ;;
    recover)
        # Already in recovery mode: leave it to the user (Change WiFi in the
        # dashboard) or a reboot. Do not flap the AP.
        if hotspot_active; then exit 0; fi
        if [ -n "$(active_home_wifi)" ]; then
            echo 0 > "$FAIL_FILE" 2>/dev/null || true
            exit 0
        fi
        count=$(cat "$FAIL_FILE" 2>/dev/null || echo 0)
        count=$((count + 1))
        echo "$count" > "$FAIL_FILE" 2>/dev/null || true
        log "no home WiFi (consecutive=$count/$FAIL_THRESHOLD)"
        if [ "$count" -ge "$FAIL_THRESHOLD" ]; then
            arm_hotspot
        fi
        ;;
    *)
        log "usage: setup_hotspot.sh [boot|recover]"
        exit 2
        ;;
esac
