#!/usr/bin/env python3
"""
Weekly AI security story generator for IoTSentinel.

Produces a plain-English narrative of what happened on the home network
in the past 7 days — "This Week on Your Network".  No competitor generates a personalised, AI-narrated weekly story.

Usage:
    from utils.weekly_story import generate_story, build_facts

    facts = build_facts(db)
    story, source = generate_story(facts, ai_assistant)
"""

import logging
from typing import (Any, Dict, Tuple)


logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Facts gathering
# ---------------------------------------------------------------------------

def build_facts(db: Any) -> Dict:
    """Gather a compact summary of the last 7 days from the DB.

    Returns a plain dict so callers can inspect / mock it easily.
    All queries are read-only and safe to run from any thread.
    """
    facts: Dict = {}
    try:
        cur = db.conn.cursor()

        # Alert counts by severity
        cur.execute(
            """SELECT severity, COUNT(*) FROM alerts
               WHERE timestamp >= datetime('now', '-7 days')
               GROUP BY severity"""
        )
        sev_counts = {r[0]: r[1] for r in cur.fetchall()}
        facts['alerts_critical'] = sev_counts.get('critical', 0)
        facts['alerts_high']     = sev_counts.get('high', 0)
        facts['alerts_medium']   = sev_counts.get('medium', 0)
        facts['alerts_low']      = sev_counts.get('low', 0)
        facts['alerts_total']    = sum(sev_counts.values())

        # How many were acknowledged (handled)
        cur.execute(
            """SELECT COUNT(*) FROM alerts
               WHERE timestamp >= datetime('now', '-7 days')
                 AND acknowledged = 1"""
        )
        facts['alerts_handled'] = cur.fetchone()[0] or 0

        # AI-explained alerts
        cur.execute(
            """SELECT COUNT(*) FROM alerts
               WHERE timestamp >= datetime('now', '-7 days')
                 AND plain_explanation_ai = 1"""
        )
        facts['alerts_ai_explained'] = cur.fetchone()[0] or 0

        # Agent actions (autonomous + approved)
        try:
            cur.execute(
                """SELECT COUNT(*), SUM(CASE WHEN status='auto' THEN 1 ELSE 0 END)
                   FROM agent_actions
                   WHERE created_at >= datetime('now', '-7 days')"""
            )
            r = cur.fetchone()
            facts['agent_actions_total'] = r[0] or 0
            facts['agent_actions_auto']  = r[1] or 0
        except Exception:
            facts['agent_actions_total'] = 0
            facts['agent_actions_auto']  = 0

        # Incidents opened this week
        try:
            cur.execute(
                """SELECT COUNT(*) FROM incidents
                   WHERE created_at >= datetime('now', '-7 days')"""
            )
            facts['incidents_total'] = cur.fetchone()[0] or 0
        except Exception:
            facts['incidents_total'] = 0

        # New devices joined
        cur.execute(
            """SELECT COUNT(*) FROM devices
               WHERE first_seen >= datetime('now', '-7 days')"""
        )
        facts['new_devices'] = cur.fetchone()[0] or 0

        # Active device count (seen in last 7 days)
        cur.execute(
            """SELECT COUNT(DISTINCT device_ip) FROM connections
               WHERE timestamp >= datetime('now', '-7 days')"""
        )
        facts['active_devices'] = cur.fetchone()[0] or 0

        # Bandwidth: bytes sent this week vs previous week
        cur.execute(
            """SELECT COALESCE(SUM(bytes_sent), 0) FROM connections
               WHERE timestamp >= datetime('now', '-7 days')"""
        )
        facts['bytes_this_week'] = int(cur.fetchone()[0] or 0)

        cur.execute(
            """SELECT COALESCE(SUM(bytes_sent), 0) FROM connections
               WHERE timestamp >= datetime('now', '-14 days')
                 AND timestamp <  datetime('now', '-7 days')"""
        )
        facts['bytes_prev_week'] = int(cur.fetchone()[0] or 0)

        # Most active device (by connection count)
        cur.execute(
            """SELECT c.device_ip, d.device_name, COUNT(*) as cnt
               FROM connections c
               LEFT JOIN devices d ON c.device_ip = d.device_ip
               WHERE c.timestamp >= datetime('now', '-7 days')
               GROUP BY c.device_ip ORDER BY cnt DESC LIMIT 1"""
        )
        r = cur.fetchone()
        facts['busiest_device'] = (r[1] or r[0]) if r else None
        facts['busiest_device_conns'] = r[2] if r else 0

    except Exception as exc:
        logger.warning(f"[weekly_story] build_facts error: {exc}")

    return facts


# ---------------------------------------------------------------------------
# Story generation
# ---------------------------------------------------------------------------

_PROMPT_TEMPLATE = """\
You are IoTSentinel's friendly security narrator. Write a brief "This Week on Your Network" \
story in plain English for a non-technical home user.

Rules:
- 3 to 5 short paragraphs
- Warm, reassuring tone — like a knowledgeable friend
- No em dashes, no markdown bold, no bullet points, no raw IP addresses
- Mention the AI's role naturally (e.g. "IoTSentinel's AI explained each alert")
- End with one positive, actionable takeaway

Network facts for this week:
{facts_text}

Write the story now:"""


def _facts_to_text(facts: Dict) -> str:
    """Convert the facts dict to a readable bullet list for the LLM prompt."""
    lines = []
    total = facts.get('alerts_total', 0)
    crit  = facts.get('alerts_critical', 0)
    high  = facts.get('alerts_high', 0)
    handled = facts.get('alerts_handled', 0)
    ai_exp  = facts.get('alerts_ai_explained', 0)
    auto    = facts.get('agent_actions_auto', 0)
    new_dev = facts.get('new_devices', 0)
    active  = facts.get('active_devices', 0)
    bw_this = facts.get('bytes_this_week', 0)
    bw_prev = facts.get('bytes_prev_week', 0)
    busiest = facts.get('busiest_device')

    lines.append(f"Total alerts: {total} ({crit} critical, {high} high)")
    lines.append(f"Alerts handled/reviewed: {handled}")
    if ai_exp:
        lines.append(f"Alerts explained by AI in plain English: {ai_exp}")
    if auto:
        lines.append(f"Actions taken automatically by the AI agent: {auto}")
    lines.append(f"New devices that joined the network: {new_dev}")
    lines.append(f"Active devices seen this week: {active}")
    if bw_this > 0:
        mb_this = bw_this // 1_000_000
        mb_prev = bw_prev // 1_000_000
        if mb_prev > 0:
            pct = int(((bw_this - bw_prev) / bw_prev) * 100)
            sign = '+' if pct >= 0 else ''
            lines.append(f"Bandwidth: {mb_this} MB ({sign}{pct}% vs last week)")
        else:
            lines.append(f"Bandwidth: {mb_this} MB")
    if busiest:
        lines.append(f"Busiest device: {busiest} ({facts.get('busiest_device_conns', 0)} connections)")

    return "\n".join(f"- {l}" for l in lines)


def _template_fallback(facts: Dict) -> str:
    """Rule-based story when no LLM provider is available.

    Always renders something credible for a demo.
    """
    total = facts.get('alerts_total', 0)
    crit  = facts.get('alerts_critical', 0)
    handled = facts.get('alerts_handled', 0)
    new_dev = facts.get('new_devices', 0)
    auto    = facts.get('agent_actions_auto', 0)
    bw_this = facts.get('bytes_this_week', 0)

    mood = "quiet" if total < 3 else "moderately active" if total < 10 else "busy"
    crit_note = f"{crit} needed immediate attention" if crit > 0 else "none were critical"
    handled_note = f"{handled} were reviewed and cleared" if handled > 0 else "none required action"
    new_dev_note = f"{new_dev} new device{'s' if new_dev != 1 else ''} joined" if new_dev > 0 else "no new devices appeared"
    auto_note = (f"IoTSentinel's AI agent automatically handled {auto} situation{'s' if auto != 1 else ''}."
                 if auto > 0 else "")
    bw_note = (f"Your network transferred {bw_this // 1_000_000} MB of data."
               if bw_this > 0 else "")

    paragraphs = [
        f"It was a {mood} week on your home network.",
        f"IoTSentinel detected {total} security alert{'s' if total != 1 else ''} - {crit_note}. "
        f"Of those, {handled_note}.",
    ]
    if auto_note:
        paragraphs.append(auto_note)
    if new_dev_note:
        paragraphs.append(f"On the device front, {new_dev_note} this week.")
    if bw_note:
        paragraphs.append(bw_note)
    paragraphs.append("Your network is being monitored continuously. Keep an eye on the alerts tab for anything that needs your attention.")

    return "\n\n".join(paragraphs)


def generate_story(facts: Dict, ai_assistant: Any) -> Tuple[str, str]:
    """Generate a plain-English weekly story.

    Returns (story_markdown, source) where source is a provider key
    (e.g. 'groq', 'ollama', 'rules').  Always returns something —
    falls back to a clean template when no LLM provider is reachable.
    """
    if ai_assistant is None or not getattr(ai_assistant, 'has_llm_provider', lambda: False)():
        return _template_fallback(facts), 'rules'

    facts_text = _facts_to_text(facts)
    prompt = _PROMPT_TEMPLATE.format(facts_text=facts_text)

    try:
        text, source = ai_assistant.get_response(
            prompt=prompt,
            max_tokens=350,
            temperature=0.6,
        )
        # If the AI assistant fell back to its generic rule-based panel-navigation
        # responses (source='rules'), those responses aren't useful as a weekly story
        # because they match on keywords in our prompt, not on network facts.
        # Use our own facts-aware template fallback instead.
        if not text or not text.strip() or source == 'rules':
            return _template_fallback(facts), 'rules'

        # Strip em dashes / bold per the AI output formatting rule
        text = text.replace('—', '-').replace('–', '-').replace('**', '')
        return text.strip(), source

    except Exception as exc:
        logger.warning(f"[weekly_story] LLM call failed: {exc}")
        return _template_fallback(facts), 'rules'
