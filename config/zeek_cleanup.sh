#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# zeek_cleanup.sh — Zeek + app log rotation. Runs from cron daily at 03:00
# (registered by scripts/setup_pi.sh). Keeps the SD card from filling with old
# capture logs on a long-running sensor.
#
# Deletes archived Zeek logs and rolled app logs older than RETENTION_DAYS.
# The live Zeek "current/" directory is never touched.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

RETENTION_DAYS=14

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

ZEEK_LOG_DIR="/opt/zeek/logs"
APP_LOG_DIR="$PROJECT_DIR/data/logs"
CLEANUP_LOG="$APP_LOG_DIR/zeek_cleanup.log"

mkdir -p "$APP_LOG_DIR"
log() { echo "$(date '+%Y-%m-%d %H:%M:%S') $*" >> "$CLEANUP_LOG"; }

freed_before=0
if command -v du >/dev/null 2>&1 && [ -d "$ZEEK_LOG_DIR" ]; then
    freed_before=$(du -sk "$ZEEK_LOG_DIR" 2>/dev/null | awk '{print $1}')
fi

deleted=0
# Archived Zeek logs: dated directories alongside (but never) "current/".
if [ -d "$ZEEK_LOG_DIR" ]; then
    while IFS= read -r -d '' f; do
        rm -f "$f" && deleted=$((deleted + 1))
    done < <(find "$ZEEK_LOG_DIR" -path "$ZEEK_LOG_DIR/current" -prune -o \
                  -type f \( -name '*.log' -o -name '*.log.gz' \) \
                  -mtime "+$RETENTION_DAYS" -print0 2>/dev/null)
    # Prune now-empty dated archive directories.
    find "$ZEEK_LOG_DIR" -path "$ZEEK_LOG_DIR/current" -prune -o \
         -type d -empty -delete 2>/dev/null || true
fi

# Rolled application logs (keep the active *.log, drop old rotations).
if [ -d "$APP_LOG_DIR" ]; then
    while IFS= read -r -d '' f; do
        rm -f "$f" && deleted=$((deleted + 1))
    done < <(find "$APP_LOG_DIR" -type f \( -name '*.log.*' -o -name '*.log.gz' \) \
                  -mtime "+$RETENTION_DAYS" -print0 2>/dev/null)
fi

freed_after=0
if command -v du >/dev/null 2>&1 && [ -d "$ZEEK_LOG_DIR" ]; then
    freed_after=$(du -sk "$ZEEK_LOG_DIR" 2>/dev/null | awk '{print $1}')
fi
freed_kb=$(( freed_before - freed_after ))
[ "$freed_kb" -lt 0 ] && freed_kb=0

log "Removed $deleted file(s) older than ${RETENTION_DAYS}d; freed ~${freed_kb} KB."
exit 0
