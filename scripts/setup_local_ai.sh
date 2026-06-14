#!/usr/bin/env bash
# IoTSentinel — first-boot local AI (Ollama) provisioning
#
# Installs Ollama and pulls the on-device model (gemma2:2b) in the background
# so the Pi image ships with zero-config, fully on-device AI. No accounts,
# no API keys, works offline once installed.
#
# Behaviour:
#   - Skips entirely when ai_assistant.ollama_enabled is false in the config
#     (the opt-out) or when the device has less than ~3 GB RAM.
#   - Idempotent: a stamp file marks completion; reruns exit immediately.
#   - Never blocks boot: invoked by iotsentinel-localai.service after
#     network-online, niced down, and any failure exits 0 (retry next boot).
#   - Cloud AI and the rule-template fallback work regardless of the outcome.
#
# Manual usage:  sudo bash scripts/setup_local_ai.sh

set -u

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_JSON="${REPO_DIR}/config/default_config.json"
STAMP_FILE="/var/lib/iotsentinel/local-ai-ready"
LOG_PREFIX="[local-ai]"
MODEL="gemma2:2b"

log() { echo "${LOG_PREFIX} $*"; }

# ---------------------------------------------------------------------------
# 0. Idempotency + opt-out + hardware gates
# ---------------------------------------------------------------------------
if [ -f "$STAMP_FILE" ]; then
    log "Already provisioned ($STAMP_FILE exists) — nothing to do."
    exit 0
fi

if [ -f "$CONFIG_JSON" ]; then
    ENABLED=$(python3 -c "
import json
try:
    cfg = json.load(open('$CONFIG_JSON'))
    print(str(cfg.get('ai_assistant', {}).get('ollama_enabled', True)).lower())
except Exception:
    print('true')
" 2>/dev/null || echo "true")
    if [ "$ENABLED" = "false" ]; then
        log "ollama_enabled is false in config — skipping local AI install (opt-out)."
        exit 0
    fi
fi

# The gemma2:2b model needs ~1.6 GB RAM during inference; require ~3 GB total
# so the rest of IoTSentinel keeps running comfortably.
MEM_KB=$(grep MemTotal /proc/meminfo 2>/dev/null | awk '{print $2}' || echo 0)
if [ "${MEM_KB:-0}" -gt 0 ] && [ "$MEM_KB" -lt 3000000 ]; then
    log "Only $((MEM_KB / 1024)) MB RAM detected — skipping local AI (needs ~3 GB)."
    exit 0
fi

# Read the configured model name (falls back to gemma2:2b)
if [ -f "$CONFIG_JSON" ]; then
    MODEL=$(python3 -c "
import json
try:
    cfg = json.load(open('$CONFIG_JSON'))
    print(cfg.get('ai_assistant', {}).get('ollama_model', 'gemma2:2b'))
except Exception:
    print('gemma2:2b')
" 2>/dev/null || echo "gemma2:2b")
fi

# ---------------------------------------------------------------------------
# 1. Install Ollama (official installer; arm64-aware)
# ---------------------------------------------------------------------------
if ! command -v ollama >/dev/null 2>&1; then
    log "Installing Ollama..."
    if ! curl -fsSL https://ollama.com/install.sh | sh; then
        log "Ollama install failed (offline or transient error). Will retry next boot."
        exit 0
    fi
    log "Ollama installed."
else
    log "Ollama already installed."
fi

# Make sure the server is up (the installer registers + starts ollama.service)
systemctl enable ollama 2>/dev/null || true
systemctl start ollama 2>/dev/null || true

for _ in $(seq 1 30); do
    if curl -fsS http://localhost:11434/ >/dev/null 2>&1; then
        break
    fi
    sleep 2
done

if ! curl -fsS http://localhost:11434/ >/dev/null 2>&1; then
    log "Ollama server did not come up — will retry next boot."
    exit 0
fi

# ---------------------------------------------------------------------------
# 2. Pull the on-device model (~1.6 GB download, runs niced in the background
#    of first boot; the dashboard works normally while this completes)
# ---------------------------------------------------------------------------
if ollama list 2>/dev/null | grep -q "^${MODEL%%:*}"; then
    log "Model ${MODEL} already present."
else
    log "Pulling ${MODEL} (about 1.6 GB — this can take a while on first boot)..."
    if ! ollama pull "$MODEL"; then
        log "Model pull failed (offline or transient error). Will retry next boot."
        exit 0
    fi
    log "Model ${MODEL} ready."
fi

mkdir -p "$(dirname "$STAMP_FILE")"
date > "$STAMP_FILE"
log "Local AI ready — on-device explanations are now available with no API keys."
exit 0
