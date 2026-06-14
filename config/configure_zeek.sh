#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# configure_zeek.sh — point Zeek at the monitored interface and (re)deploy it.
#
# Without this, Zeek installs but never captures the interface the user picked in
# the setup wizard, so the dashboard sees no traffic. Run as root (via sudo). Idempotent:
# it only rewrites node.cfg and redeploys when the interface actually changes.
#
# Usage:
#   sudo bash configure_zeek.sh <interface>
#   sudo bash configure_zeek.sh            # interface read from default_config.json
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

ZEEK_PREFIX="/opt/zeek"
NODE_CFG="$ZEEK_PREFIX/etc/node.cfg"
ZEEKCTL="$ZEEK_PREFIX/bin/zeekctl"
LOG_FILE="$PROJECT_DIR/data/logs/zeek_configure.log"

mkdir -p "$(dirname "$LOG_FILE")"
log() { echo "$(date '+%Y-%m-%d %H:%M:%S') $*" | tee -a "$LOG_FILE"; }

# 1. Resolve the interface: CLI arg wins, else config, else a sensible default.
IFACE="${1:-}"
if [ -z "$IFACE" ] && [ -f "$PROJECT_DIR/config/default_config.json" ]; then
    IFACE="$(python3 -c "
import json
try:
    c = json.load(open('$PROJECT_DIR/config/default_config.json'))
    print(c.get('network', {}).get('interface') or '')
except Exception:
    print('')
" 2>/dev/null)"
fi
if [ -z "$IFACE" ]; then
    # Fall back to the first non-loopback interface that is up.
    IFACE="$(ls /sys/class/net 2>/dev/null | grep -v '^lo$' | head -1)"
fi
if [ -z "$IFACE" ]; then
    log "Could not determine an interface to monitor — skipping Zeek deploy."
    exit 0
fi

if [ ! -x "$ZEEKCTL" ]; then
    log "zeekctl not found at $ZEEKCTL — is Zeek installed? Skipping."
    exit 0
fi

# 2. Desired standalone node.cfg for this interface.
DESIRED="[zeek]
type=standalone
host=localhost
interface=${IFACE}"

if [ -f "$NODE_CFG" ] && [ "$(cat "$NODE_CFG")" = "$DESIRED" ]; then
    log "node.cfg already targets ${IFACE} — nothing to do."
    exit 0
fi

printf '%s\n' "$DESIRED" > "$NODE_CFG" || { log "Failed to write $NODE_CFG"; exit 0; }
log "Wrote node.cfg → monitoring interface ${IFACE}."

# 3. Deploy (install + start). Non-fatal: log the outcome either way.
if "$ZEEKCTL" deploy >>"$LOG_FILE" 2>&1; then
    log "zeekctl deploy succeeded."
else
    log "zeekctl deploy reported an error — see entries above."
fi
exit 0
