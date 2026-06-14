#!/usr/bin/env python3
"""
Pure helpers for the admin "AI Engine" health card.

Turns HybridAIAssistant.get_health() / get_stats() snapshots into plain data
rows so the Dash callback only does rendering. Keeping this UI-free makes it
testable without a running app (same pattern as build_followup_prompt in
alert_explainer).
"""

import time
from typing import List, Dict

from utils.alert_explainer import source_label

# Display order on the card: paid cloud, free cloud, local, offline fallback.
PROVIDER_ORDER = ("openai", "anthropic", "groq", "gemini", "ollama")


def relative_age(epoch: float, now: float = None) -> str:
    """Epoch seconds -> 'just now' / 'N minutes ago' / 'N hours ago' / 'N days ago'."""
    if not epoch:
        return ""
    seconds = (now or time.time()) - epoch
    if seconds < 0:
        seconds = 0
    if seconds < 60:
        return "just now"
    if seconds < 3600:
        minutes = int(seconds / 60)
        return f"{minutes} minute{'s' if minutes != 1 else ''} ago"
    if seconds < 86400:
        hours = int(seconds / 3600)
        return f"{hours} hour{'s' if hours != 1 else ''} ago"
    days = int(seconds / 86400)
    return f"{days} day{'s' if days != 1 else ''} ago"


def build_health_rows(health: dict, now: float = None) -> List[Dict]:
    """One row per provider plus the always-on rules fallback.

    Row shape:
        provider   - key ('openai', ...)
        label      - display name via source_label
        status     - 'ok' | 'failing' | 'untested' | 'off'
        detail     - short human sentence for the row
        last_error - provider error text (tooltip), '' when none
    """
    now = now or time.time()
    providers = (health or {}).get("providers", {})
    rows = []
    for name in PROVIDER_ORDER:
        state = providers.get(name, {})
        configured = bool(state.get("configured"))
        err_time = state.get("last_error_time")
        ok_time = state.get("last_success_time")
        last_error = state.get("last_error") or ""

        if not configured:
            status, detail = "off", "Not configured"
        elif err_time and (ok_time is None or ok_time < err_time):
            status = "failing"
            detail = f"Failing ({relative_age(err_time, now)})"
        elif ok_time:
            status = "ok"
            detail = f"Working ({relative_age(ok_time, now)})"
        else:
            status, detail = "untested", "Configured, not used yet"

        rows.append({
            "provider": name,
            "label": source_label(name),
            "status": status,
            "detail": detail,
            "last_error": last_error,
        })

    rows.append({
        "provider": "rules",
        "label": source_label("rules"),
        "status": "ok",
        "detail": "Always available",
        "last_error": "",
    })
    return rows


def build_usage_line(stats: dict) -> str:
    """Plain sentence summarising request distribution and cache savings."""
    total = (stats or {}).get("total_requests", 0)
    if not total:
        return "No AI requests yet this session."
    parts = []
    for name in ("openai", "anthropic", "groq", "gemini", "ollama"):
        pct = stats.get(f"{name}_percent", 0)
        if pct:
            parts.append(f"{source_label(name)} {pct}%")
    rules_pct = stats.get("rules_percent", 0)
    if rules_pct:
        parts.append(f"{source_label('rules')} {rules_pct}%")
    line = f"{total} requests this session"
    if parts:
        line += ": " + ", ".join(parts)
    cache_hits = stats.get("cache_hits", 0)
    if cache_hits:
        line += f". {cache_hits} answered from cache."
    else:
        line += "."
    return line
