#!/usr/bin/env python3
"""
Per-device AI personality profile generator for IoTSentinel.

Produces a plain-English behavioural summary of a single device:
"Your Roku is a creature of habit. Typically 2.1 GB/day, busiest 18:00-23:00,
talks to about 4 hosts (all Netflix/Roku CDN). Today looks normal."

No home IoT security product ships per-device AI behavioural narration.

Usage:
    from utils.device_personality import build_profile_facts, generate_personality

    facts = build_profile_facts(db, device_ip)
    text, source = generate_personality(facts, ai_assistant)
"""

import logging
from typing import Any, Dict, Tuple

logger = logging.getLogger(__name__)

# How long the personality card stays fresh before auto-regenerating (seconds)
PERSONALITY_TTL = 3600  # 1 hour — regeneration is cheap; daily would be enough


# ---------------------------------------------------------------------------
# Facts gathering
# ---------------------------------------------------------------------------

def build_profile_facts(db: Any, device_ip: str) -> Dict:
    """Gather a concise behavioural snapshot for one device.

    All queries are read-only and safe from any thread. Wraps each block in
    its own try/except so a missing table never kills the whole card.
    """
    facts: Dict = {'device_ip': device_ip}
    try:
        cur = db.conn.cursor()

        # Device identity
        cur.execute(
            "SELECT device_name, custom_name, device_type "
            "FROM devices WHERE device_ip = ?",
            (device_ip,),
        )
        row = cur.fetchone()
        if row:
            facts['device_name'] = row[1] or row[0] or device_ip
            facts['device_type'] = row[2] or 'Unknown'
        else:
            facts['device_name'] = device_ip
            facts['device_type'] = 'Unknown'

        # Total alert count (subquery — not a column in devices)
        try:
            cur.execute(
                "SELECT COUNT(*) FROM alerts WHERE device_ip = ?", (device_ip,)
            )
            facts['total_alerts'] = int(cur.fetchone()[0] or 0)
        except Exception:
            facts['total_alerts'] = 0

        # Baseline metrics from the learned behavioural table
        _metric_map = {
            'hourly_connections':            'avg_connections',
            'bytes_sent_per_connection':     'avg_bytes_sent',
            'bytes_received_per_connection': 'avg_bytes_received',
            'unique_destinations_per_hour':  'avg_unique_destinations',
        }
        try:
            cur.execute(
                "SELECT metric_name, baseline_value "
                "FROM device_behavior_baselines WHERE device_ip = ?",
                (device_ip,),
            )
            for metric_name, value in cur.fetchall():
                key = _metric_map.get(metric_name)
                if key:
                    facts[key] = float(value)
            facts['has_baseline'] = any(k in facts for k in _metric_map.values())
        except Exception:
            facts['has_baseline'] = False

        # Today's activity
        try:
            cur.execute(
                "SELECT COALESCE(SUM(bytes_sent), 0), COALESCE(SUM(bytes_received), 0), "
                "       COUNT(*), COUNT(DISTINCT dest_ip) "
                "FROM connections "
                "WHERE device_ip = ? AND timestamp >= date('now')",
                (device_ip,),
            )
            r = cur.fetchone()
            facts['today_bytes_sent']    = int(r[0] or 0)
            facts['today_bytes_recv']    = int(r[1] or 0)
            facts['today_connections']   = int(r[2] or 0)
            facts['today_unique_dests']  = int(r[3] or 0)
        except Exception:
            facts['today_bytes_sent'] = facts['today_bytes_recv'] = 0
            facts['today_connections'] = facts['today_unique_dests'] = 0

        # Busiest hours — top 3-hour window in the last 7 days
        try:
            cur.execute(
                "SELECT CAST(strftime('%H', timestamp) AS INTEGER) AS hr, COUNT(*) as cnt "
                "FROM connections "
                "WHERE device_ip = ? AND timestamp >= datetime('now', '-7 days') "
                "GROUP BY hr ORDER BY cnt DESC LIMIT 3",
                (device_ip,),
            )
            peak_hours = [row[0] for row in cur.fetchall()]
            if peak_hours:
                peak_hours.sort()
                facts['peak_hours'] = peak_hours
                facts['peak_hour_range'] = f"{peak_hours[0]:02d}:00-{(peak_hours[-1]+1)%24:02d}:00"
            else:
                facts['peak_hours'] = []
                facts['peak_hour_range'] = None
        except Exception:
            facts['peak_hours'] = []
            facts['peak_hour_range'] = None

        # Last alert date
        try:
            cur.execute(
                "SELECT MAX(timestamp) FROM alerts WHERE device_ip = ?",
                (device_ip,),
            )
            r = cur.fetchone()
            facts['last_alert_date'] = r[0] if r and r[0] else None
        except Exception:
            facts['last_alert_date'] = None

    except Exception as exc:
        logger.warning(f"[device_personality] build_profile_facts error for {device_ip}: {exc}")

    return facts


# ---------------------------------------------------------------------------
# Prompt / text helpers
# ---------------------------------------------------------------------------

_PROMPT_TEMPLATE = """\
You are IoTSentinel's friendly security narrator writing a brief device personality \
profile for a non-technical home user.

Rules:
- 2 to 3 short paragraphs
- Warm, plain English, like a knowledgeable friend
- No em dashes, no markdown bold, no bullet points, no raw IP addresses
- Describe the device's normal behaviour patterns (when it's active, how much data it uses, \
how many destinations it typically talks to)
- If today looks normal, say so reassuringly; if there is a noticeable spike, mention it gently
- End with one short positive sentence about monitoring

Device facts:
{facts_text}

Write the profile now:"""


def _facts_to_text(facts: Dict) -> str:
    """Convert facts dict to a readable summary for the LLM prompt."""
    lines = []
    name = facts.get('device_name', facts.get('device_ip', 'this device'))
    dtype = facts.get('device_type', 'Unknown')
    lines.append(f"Device: {name} ({dtype})")

    if facts.get('has_baseline'):
        avg_conns = facts.get('avg_connections', 0)
        avg_sent  = facts.get('avg_bytes_sent', 0)
        avg_recv  = facts.get('avg_bytes_recv', facts.get('avg_bytes_received', 0))
        avg_dests = facts.get('avg_unique_destinations', 0)
        if avg_conns:
            lines.append(f"Typical connections per hour: {avg_conns:.1f}")
        if avg_sent or avg_recv:
            mb_sent = (avg_sent * avg_conns) / 1_000_000 if avg_conns else 0
            lines.append(
                f"Typical data: ~{mb_sent:.1f} MB sent per hour"
                if mb_sent > 0
                else f"Typical bytes sent per connection: {int(avg_sent)}"
            )
        if avg_dests:
            lines.append(f"Typical unique destinations per hour: {avg_dests:.1f}")
    else:
        lines.append("Baseline not yet learned (needs ~100+ connections over 7 days)")

    hr_range = facts.get('peak_hour_range')
    if hr_range:
        lines.append(f"Peak activity window (last 7 days): {hr_range}")

    today_b = facts.get('today_bytes_sent', 0) + facts.get('today_bytes_recv', 0)
    today_c = facts.get('today_connections', 0)
    today_d = facts.get('today_unique_dests', 0)
    if today_c:
        lines.append(f"Today so far: {today_c} connections, {today_d} unique destinations, "
                     f"{today_b // 1_000_000} MB total")

    total_alerts = facts.get('total_alerts', 0)
    last_alert = facts.get('last_alert_date')
    if total_alerts == 0:
        lines.append("Alerts: none recorded")
    else:
        lines.append(f"Total alerts ever: {total_alerts}"
                     + (f", last flagged: {last_alert[:10]}" if last_alert else ""))

    return "\n".join(f"- {l}" for l in lines)


def _template_fallback(facts: Dict) -> str:
    """Rule-based profile when no LLM provider is available."""
    name   = facts.get('device_name', 'This device')
    dtype  = facts.get('device_type', 'device')
    alerts = facts.get('total_alerts', 0)
    hr     = facts.get('peak_hour_range')
    today  = facts.get('today_connections', 0)
    dests  = facts.get('avg_unique_destinations', 0)

    hr_note = f" Most active between {hr}." if hr else ""
    dest_note = (f" It typically talks to around {int(dests)} external host{'' if int(dests)==1 else 's'}."
                 if dests else "")
    today_note = f" {today} connections recorded so far today." if today else ""
    alert_note = (
        "No security alerts have ever been raised for this device."
        if alerts == 0
        else f"It has triggered {alerts} security alert{'s' if alerts != 1 else ''} since it was first seen."
    )

    return (
        f"{name} is a {dtype.lower()} on your network.{hr_note}{dest_note}{today_note}\n\n"
        f"{alert_note}\n\n"
        f"IoTSentinel is watching this device continuously. Check back for more detail once "
        f"the baseline learning period completes."
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_personality(facts: Dict, ai_assistant: Any) -> Tuple[str, str]:
    """Generate a plain-English device personality profile.

    Returns (profile_text, source) where source is a provider key
    ('groq', 'ollama', 'openai', 'rules'). Always returns something.
    """
    if ai_assistant is None or not getattr(ai_assistant, 'has_llm_provider', lambda: False)():
        return _template_fallback(facts), 'rules'

    facts_text = _facts_to_text(facts)
    prompt = _PROMPT_TEMPLATE.format(facts_text=facts_text)

    try:
        text, source = ai_assistant.get_response(
            prompt=prompt,
            max_tokens=280,
            temperature=0.55,
        )
        if not text or not text.strip() or source == 'rules':
            return _template_fallback(facts), 'rules'

        text = text.replace('—', '-').replace('–', '-').replace('**', '')
        return text.strip(), source

    except Exception as exc:
        logger.warning(f"[device_personality] LLM call failed: {exc}")
        return _template_fallback(facts), 'rules'
