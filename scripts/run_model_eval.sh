#!/usr/bin/env bash
# First-boot ML setup — runs once, no SSH needed:
#   1. Offline model evaluation -> writes Precision/Recall/F1 to model_performance, so the
#      dashboard's "Model Performance" card (System & ML Models -> ML Models) is populated.
#   2. In DEMO mode only, seeds live anomaly traffic so the dashboard shows real alerts on
#      camera (the Pi as a passive Wi-Fi client otherwise sees little device traffic).
#
# Demo mode is OFF by default (real installs are never polluted with fake traffic). Enable
# it for a demo image by EITHER setting IOTSENTINEL_DEMO_TRAFFIC=1 in the environment, OR
# dropping an empty file named 'iotsentinel-demo' on the boot partition before first boot.
#
# Invoked by iotsentinel-model-eval.service. Always exits 0 (never blocks boot).
set -u

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAMP="/var/lib/iotsentinel/model-eval-done"
LOG="[model-eval]"

PY="$REPO_DIR/venv/bin/python3"
[ -x "$PY" ] || PY="$(command -v python3 || echo python3)"

if [ -f "$STAMP" ]; then
    echo "$LOG already provisioned ($STAMP) — nothing to do."
    exit 0
fi
mkdir -p /var/lib/iotsentinel 2>/dev/null || true

# 1. Offline evaluation (always). --dataset is optional; without it a synthetic sample runs.
echo "$LOG evaluating models (Precision/Recall/F1)…"
if [ -n "${IOTSENTINEL_EVAL_DATASET:-}" ]; then
    "$PY" "$REPO_DIR/scripts/evaluate_models.py" --dataset "$IOTSENTINEL_EVAL_DATASET" || true
else
    "$PY" "$REPO_DIR/scripts/evaluate_models.py" || true
fi

# 2. Demo traffic (gated): config flag demo.seed_traffic, OR env flag, OR a marker file on
#    the boot partition. The shipped demo build sets demo.seed_traffic=true so the dashboard
#    shows live alerts with zero manual steps; the public release sets it false.
DEMO_CFG="$("$PY" -c "import json,pathlib; print(json.loads(pathlib.Path('$REPO_DIR/config/default_config.json').read_text()).get('demo',{}).get('seed_traffic', False))" 2>/dev/null || echo False)"
if [ "$DEMO_CFG" = "True" ] || [ "${IOTSENTINEL_DEMO_TRAFFIC:-0}" = "1" ] \
   || [ -f /boot/firmware/iotsentinel-demo ] || [ -f /boot/iotsentinel-demo ]; then
    echo "$LOG demo mode: seeding live anomaly traffic…"
    "$PY" "$REPO_DIR/scripts/demo_traffic.py" --seed || true
    # Curated, plain-English-ready security alerts so the Alerts feed + the AI plain-
    # English feature have deterministic data on camera with ZERO manual steps. The
    # seeder is first-boot-safe (swallows DB-not-ready/locked errors); the background
    # LLM worker rewrites each plain line with the real model shortly after.
    if "$PY" "$REPO_DIR/scripts/seed_demo_alerts.py"; then
        echo "$LOG demo alerts seeded."
    else
        echo "$LOG demo alert seeding reported an issue (non-fatal); continuing."
    fi
fi

touch "$STAMP" 2>/dev/null || true
echo "$LOG done."
exit 0
