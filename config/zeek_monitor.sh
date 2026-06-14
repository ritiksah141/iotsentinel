#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# zeek_monitor.sh — Zeek watchdog. Runs from cron every 5 minutes (registered by
# scripts/setup_pi.sh). If Zeek is not capturing, it restarts it and logs the event.
#
# IoTSentinel is blind without Zeek, so a silent Zeek crash must self-heal.
# Deliberately NOT `set -e`: a down service is an expected branch, not a failure.
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail

# Resolve project dir from this script's location (config/ -> project root)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

LOG_DIR="$PROJECT_DIR/data/logs"
LOG_FILE="$LOG_DIR/zeek_monitor.log"
ZEEKCTL="/opt/zeek/bin/zeekctl"

mkdir -p "$LOG_DIR"
log() { echo "$(date '+%Y-%m-%d %H:%M:%S') $*" >> "$LOG_FILE"; }

is_running() {
    # Prefer a systemd unit if one exists, else zeekctl, else a raw process check.
    if systemctl list-unit-files 2>/dev/null | grep -q '^zeek\.service'; then
        systemctl is-active --quiet zeek && return 0 || return 1
    fi
    if [ -x "$ZEEKCTL" ]; then
        "$ZEEKCTL" status 2>/dev/null | grep -qiE '\brunning\b' && return 0 || return 1
    fi
    pgrep -f '/opt/zeek/bin/zeek' >/dev/null 2>&1 && return 0 || return 1
}

restart_zeek() {
    if systemctl list-unit-files 2>/dev/null | grep -q '^zeek\.service'; then
        systemctl restart zeek 2>/dev/null && return 0 || return 1
    fi
    if [ -x "$ZEEKCTL" ]; then
        "$ZEEKCTL" deploy 2>/dev/null && return 0 || return 1
    fi
    return 1
}

if is_running; then
    # Healthy: stay quiet to keep the log small (cleanup rotates it anyway).
    exit 0
fi

log "Zeek not running — attempting restart."
if restart_zeek; then
    sleep 3
    if is_running; then
        log "Zeek restarted successfully."
    else
        log "Restart command ran but Zeek still not active."
    fi
else
    log "Could not restart Zeek (no systemd unit / zeekctl available)."
fi
exit 0
