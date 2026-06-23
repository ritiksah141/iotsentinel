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
COUNTRY="${IOTSENTINEL_WIFI_COUNTRY:-GB}"              # regulatory domain — AP won't broadcast if unset

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

# Name of a saved Wi-Fi client profile that is NOT our setup AP, i.e. the home network
# the wizard persisted with autoconnect. Empty if none exists yet.
saved_home_profile() {
    nmcli -t -f NAME,TYPE connection show 2>/dev/null \
        | grep ":802-11-wireless\$" | grep -v "^${HOTSPOT}:" | head -1 | cut -d: -f1
}

# Give a saved home profile an explicit activation push. On a single radio, NM cannot
# autoconnect while the AP is up, so the wizard's autoconnect profile can otherwise sit
# idle. Called while offline and BEFORE arming the hotspot, so it never flaps a live AP.
try_home_profile() {
    local home
    home="$(saved_home_profile)"
    [ -n "$home" ] || return 1
    log "offline with saved home profile '$home' — attempting to (re)join before arming AP"
    nmcli --wait 20 connection up "$home" >/dev/null 2>&1 || true
    [ -n "$(active_home_wifi)" ]
}

# Wait (best-effort, up to ~60s) for NetworkManager to be running and for the Wi-Fi
# interface to be managed and available. On a cold first boot the provision one-shot
# can otherwise fire before NM has taken over wlan0, so the AP creation silently
# no-ops and no hotspot ever appears.
wait_for_nm_wlan() {
    rfkill unblock wifi 2>/dev/null || true   # do this first so the device isn't 'unavailable'
    local i state
    for i in $(seq 1 30); do
        if nmcli -t -f RUNNING general 2>/dev/null | grep -q "running"; then
            state=$(nmcli -t -f DEVICE,STATE device status 2>/dev/null | grep "^${IFACE}:" | cut -d: -f2)
            case "$state" in
                disconnected|connected|connecting) return 0 ;;   # managed + radio up
            esac
        fi
        sleep 2
    done
    log "NetworkManager/$IFACE not ready after wait — arming anyway (best effort)"
    return 0
}

arm_hotspot() {
    if hotspot_active; then log "hotspot already active"; return 0; fi
    log "no home WiFi — starting open '$HOTSPOT' hotspot on $IFACE"

    # The radio must be unblocked and a regulatory domain set, or the AP silently
    # fails to start on a regulated channel — the #1 reason a headless first boot
    # shows no hotspot. Both are cheap and idempotent, so do them every time.
    rfkill unblock wifi 2>/dev/null || true
    iw reg set "$COUNTRY" 2>/dev/null || true

    # Create an explicit OPEN access point (no password) in NetworkManager shared
    # mode (DHCP + DNS + NAT, gateway 10.42.0.1). This is deterministic and joinable
    # by anyone — unlike `nmcli device wifi hotspot`, which makes a WPA2 network with
    # a generated password the user would never know. Recreate it so a stale profile
    # never lingers.
    nmcli connection delete "$HOTSPOT" >/dev/null 2>&1 || true
    if nmcli connection add type wifi ifname "$IFACE" con-name "$HOTSPOT" autoconnect no \
            ssid "$HOTSPOT" \
            802-11-wireless.mode ap 802-11-wireless.band bg 802-11-wireless.channel 6 \
            ipv4.method shared >/dev/null 2>&1 \
       && nmcli --wait 20 connection up "$HOTSPOT" >/dev/null 2>&1; then
        log "open hotspot up (NetworkManager shared mode)"
    else
        # Fallback so we never end up with no AP at all (this variant may be
        # WPA2-protected with a generated password — last resort only).
        log "shared-mode AP failed — falling back to 'nmcli device wifi hotspot'"
        nmcli device wifi hotspot ifname "$IFACE" ssid "$HOTSPOT" band bg channel 6 2>&1 | head -5 || true
    fi

    # Captive redirect: send any port-80 request to the dashboard. -C first so the
    # rule is never duplicated across repeated arms.
    iptables -t nat -C PREROUTING -i "$IFACE" -p tcp --dport 80 -j REDIRECT --to-port "$PORT" 2>/dev/null \
        || iptables -t nat -A PREROUTING -i "$IFACE" -p tcp --dport 80 -j REDIRECT --to-port "$PORT" 2>/dev/null || true
    sleep 2
    log "hotspot ready — join '$HOTSPOT' (open, no password) and open http://10.42.0.1:$PORT/setup"
}

# Tear the setup hotspot down so wlan0 returns to being an ordinary Wi-Fi client.
# Called after the wizard successfully joins home Wi-Fi: the AP and the client
# share wlan0, so the lingering AP profile both blocks/confuses the client
# connection and keeps the dashboard reachable only on 10.42.0.1. Best-effort.
disarm_hotspot() {
    log "tearing down '$HOTSPOT' (joined home Wi-Fi — wlan0 returns to client mode)"
    nmcli connection down "$HOTSPOT" >/dev/null 2>&1 || true
    nmcli connection delete "$HOTSPOT" >/dev/null 2>&1 || true
    # Drop the captive port-80 redirect so normal browsing isn't bent to the dashboard.
    iptables -t nat -D PREROUTING -i "$IFACE" -p tcp --dport 80 -j REDIRECT --to-port "$PORT" 2>/dev/null || true
    # Reset the recovery watchdog so it doesn't immediately re-arm.
    echo 0 > "$FAIL_FILE" 2>/dev/null || true
}

MODE="${1:-recover}"
case "$MODE" in
    boot)
        wait_for_nm_wlan
        if [ -n "$(active_home_wifi)" ]; then log "already on home WiFi — hotspot not needed"; exit 0; fi
        # Retry: cold-boot Wi-Fi firmware / regulatory settling can make the first
        # arm fail. Confirm the AP is actually active before giving up.
        for attempt in 1 2 3; do
            arm_hotspot
            sleep 3
            if hotspot_active; then
                log "hotspot confirmed active (attempt $attempt)"
                exit 0
            fi
            log "hotspot not up yet (attempt $attempt/3) — retrying"
        done
        log "WARNING: hotspot did not come up after 3 attempts — connectivity timer will keep trying"
        ;;
    recover)
        if [ -n "$(active_home_wifi)" ]; then
            echo 0 > "$FAIL_FILE" 2>/dev/null || true
            # On home Wi-Fi: the provisioning/recovery AP is redundant and keeps wlan0
            # in a confused AP+client state (dashboard then reachable only on 10.42.0.1).
            # Disarm it as a root-side backstop in case the dashboard's post-wizard
            # disarm was missed. Safe — only runs when we are genuinely on home Wi-Fi.
            if hotspot_active; then
                log "home WiFi active but setup hotspot still up — disarming"
                disarm_hotspot
            fi
            exit 0
        fi
        # No home Wi-Fi. If the recovery hotspot is already up, leave it (do not flap).
        if hotspot_active; then exit 0; fi
        # The radio is free (no AP up): nudge a saved home profile up first. If it joins,
        # we are back on home Wi-Fi and never arm the AP — this breaks the single-radio
        # trap where a re-armed hotspot permanently blocks NM's autoconnect.
        if try_home_profile; then
            echo 0 > "$FAIL_FILE" 2>/dev/null || true
            log "re-joined home WiFi via saved profile — hotspot not needed"
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
    disarm)
        disarm_hotspot
        ;;
    *)
        log "usage: setup_hotspot.sh [boot|recover|disarm]"
        exit 2
        ;;
esac
