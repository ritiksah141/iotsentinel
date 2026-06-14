#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# optimize_pi.sh — Raspberry Pi system tuning for a headless IoTSentinel sensor.
#
# Called by scripts/setup_pi.sh (step 7) via `sudo bash`. Idempotent: every change
# is guarded so re-runs are no-ops. Exits 0 even when a change is already applied or
# a knob is unavailable, so the caller's `|| warn` stays accurate (non-fatal).
#
# Tuning applied:
#   - gpu_mem=16     headless box needs almost no GPU memory → more RAM for the ML/DB
#   - vm.swappiness  low, to spare the SD card from swap write wear
#   - cpu governor   performance, so packet parsing / inference isn't throttled
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail

log() { echo "[optimize_pi] $*"; }

# 1. GPU memory split (Bookworm path first, legacy fallback)
CONFIG_TXT="/boot/firmware/config.txt"
[ -f "$CONFIG_TXT" ] || CONFIG_TXT="/boot/config.txt"
if [ -f "$CONFIG_TXT" ]; then
    if grep -qE '^\s*gpu_mem=' "$CONFIG_TXT"; then
        log "gpu_mem already set in $CONFIG_TXT — leaving as-is."
    else
        echo "gpu_mem=16" >> "$CONFIG_TXT" \
            && log "gpu_mem=16 appended to $CONFIG_TXT (takes effect next boot)." \
            || log "Could not write $CONFIG_TXT — skipping GPU split."
    fi
else
    log "No config.txt found — not a Pi boot layout, skipping GPU split."
fi

# 2. Swappiness (persistent, applied immediately)
SYSCTL_FILE="/etc/sysctl.d/99-iotsentinel.conf"
if [ -f "$SYSCTL_FILE" ] && grep -qF "vm.swappiness=10" "$SYSCTL_FILE"; then
    log "vm.swappiness already configured."
else
    echo "vm.swappiness=10" > "$SYSCTL_FILE" \
        && sysctl --system >/dev/null 2>&1 \
        && log "vm.swappiness=10 set and applied." \
        || log "Could not set swappiness — skipping."
fi

# 3. CPU governor (best-effort via sysfs; not all boards expose it)
GOV_GLOB=/sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
if compgen -G "$GOV_GLOB" >/dev/null 2>&1; then
    changed=0
    for gov in $GOV_GLOB; do
        if [ "$(cat "$gov" 2>/dev/null)" != "performance" ]; then
            echo performance > "$gov" 2>/dev/null && changed=1
        fi
    done
    [ "$changed" -eq 1 ] && log "CPU governor set to performance." \
                         || log "CPU governor already performance."
else
    log "cpufreq governor not exposed on this board — skipping."
fi

log "Done."
exit 0
