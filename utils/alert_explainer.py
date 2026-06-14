#!/usr/bin/env python3
"""
Alert plain-English rewriter for IoTSentinel.

Shared helper used by:
- The background proactive-rewrite worker (orchestrator._plain_english_loop)
- The alert-detail modal callback (dashboard/callbacks/callbacks_alerts.py)

Keeps the prompt, parsing, and persistence logic in one place so both paths
produce identical output and the flag (plain_explanation_ai) is always set.
"""

import logging
from typing import Optional, List, Dict, Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def clean_ai_text(text: str) -> str:
    """Strip em/en dashes and markdown bold markers from AI text.

    Enforces the AI output formatting rule: no em dashes, no raw markdown bold
    in content rendered to non-technical home users.
    """
    return (text or '').replace('—', '-').replace('–', '-').replace('**', '')


# Alias so internal helpers and external callers can use the same symbol.
_clean = clean_ai_text


# ---------------------------------------------------------------------------
# Provider / source helpers  (single source of truth — import from here
# rather than duplicating the dict in callbacks_alerts, callbacks_overview, etc.)
# ---------------------------------------------------------------------------

_SOURCE_LABELS = {
    'groq':      'Groq AI',
    'openai':    'OpenAI',
    'anthropic': 'Claude AI',
    'gemini':    'Gemini AI',
    'ollama':    'Local AI',
    'rules':     'Smart Template',
    'database':  'Data Query',
}

_SOURCE_COLORS = {
    'groq':      'info',
    'openai':    'primary',
    'anthropic': 'dark',
    'gemini':    'success',
    'ollama':    'secondary',
    'rules':     'smart-template',
    'database':  'secondary',
}

_SOURCE_ICONS = {
    'groq':      'fa-bolt',
    'openai':    'fa-brain',
    'anthropic': 'fa-comment-dots',
    'gemini':    'fa-gem',
    'ollama':    'fa-microchip',
    'rules':     'fa-list',
    'database':  'fa-database',
}


def source_label(source: str) -> str:
    """Human-readable label for an AI provider key.

    Use this everywhere a provider name is displayed so the mapping stays in
    one place (avoids the 4-copy duplication that existed previously).
    """
    return _SOURCE_LABELS.get(source or '', source or '')


def source_badge_class(source: str) -> str:
    """Bootstrap badge class string for a provider key."""
    color = _SOURCE_COLORS.get(source or '', 'secondary')
    return f"ms-2 badge-sm badge bg-{color}"


def source_icon(source: str) -> str:
    """FontAwesome icon class for a provider key."""
    return _SOURCE_ICONS.get(source or '', 'fa-robot')


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_prompt(
    device_name: str,
    severity: str,
    today_count: int,
    tech_explanation: str,
    recs: Optional[List[Dict]] = None,
) -> str:
    """Build the structured plain-English prompt for an alert.

    Produces a prompt that mandates WHAT HAPPENED / WORRY LEVEL / TOP ACTION
    sections in plain sentences, without em dashes, markdown bold, or bullets.
    """
    recs_context = ""
    if recs:
        recs_context = "\nAvailable actions already identified:\n" + "\n".join(
            f"- {r['action']} (confidence {int(r['confidence'] * 100)}%)"
            for r in recs[:3]
        )

    return (
        f"Analyse this home network security alert. Respond in EXACTLY this format.\n"
        f"Use plain sentences. No em dashes, no markdown bold, no bullet points.\n\n"
        f"WHAT HAPPENED: [2 plain sentences explaining what the device is doing and why it matters]\n"
        f"WORRY LEVEL: [Exactly one of: 'Nothing to worry about' / 'Worth a quick check' / "
        f"'Take action now']. [One sentence explaining why, starting with a capital letter]\n"
        f"TOP ACTION: [One plain sentence - the single most important step for a home user right now]\n\n"
        f"Device: {device_name}\n"
        f"Severity: {severity}, alerts today: {today_count}\n"
        f"What triggered it: {tech_explanation}"
        f"{recs_context}"
    )


def parse_ai_text(ai_text: str, tech_explanation: str = "") -> Dict[str, str]:
    """Parse the structured AI response into named sections.

    Returns a dict with keys: what_happened, worry_level, worry_reason,
    top_action. Falls back to the raw cleaned text or tech_explanation when
    the expected sections are absent.
    """
    what_happened = worry_level = worry_reason = top_action = ""

    for line in (ai_text or "").splitlines():
        stripped = line.strip()
        if stripped.startswith("WHAT HAPPENED:"):
            what_happened = _clean(stripped[len("WHAT HAPPENED:"):].strip())
        elif stripped.startswith("WORRY LEVEL:"):
            rest = _clean(stripped[len("WORRY LEVEL:"):].strip())
            for sep in [". ", ", ", " - "]:
                if sep in rest:
                    worry_level, worry_reason = rest.split(sep, 1)
                    break
            else:
                worry_level = rest
        elif stripped.startswith("TOP ACTION:"):
            top_action = _clean(stripped[len("TOP ACTION:"):].strip())

    if not what_happened:
        what_happened = _clean(ai_text) or tech_explanation

    return {
        "what_happened": what_happened,
        "worry_level": worry_level,
        "worry_reason": worry_reason,
        "top_action": top_action,
    }


def rewrite_alert(
    alert_row: Dict[str, Any],
    today_count: int,
    recs: Optional[List[Dict]],
    ai_assistant: Any,
) -> Optional[Dict[str, str]]:
    """Call the LLM and return parsed sections, or None on failure.

    Does not persist — call persist() separately so callers control the DB
    write. Returns None when ai_assistant is None or the LLM returns empty text.
    """
    if ai_assistant is None:
        return None

    tech_explanation = alert_row.get('explanation', '')
    device_name = alert_row.get('device_name') or alert_row.get('device_ip', 'A device')
    severity = alert_row.get('severity', 'medium')

    prompt = build_prompt(device_name, severity, today_count, tech_explanation, recs)

    try:
        ai_text, source = ai_assistant.get_response(
            prompt=prompt, max_tokens=250, temperature=0.35
        )
    except Exception as exc:
        logger.debug(f"LLM call failed for alert {alert_row.get('id')}: {exc}")
        return None

    if not ai_text:
        return None

    sections = parse_ai_text(ai_text, tech_explanation)
    sections['_source'] = source
    return sections


def build_followup_prompt(
    alert_row: Dict[str, Any],
    today_count: int,
    destinations: list,
    recs: list,
    history: list,
    question: str,
) -> tuple:
    """Assemble the grounded prompt pair for the ask-why follow-up chat.

    Extracted from the inline closure in alert_followup_chat so the logic is
    unit-testable without importing Dash or registering callbacks.

    Returns (prompt, network_context) — both strings, ready to pass to
    ai_assistant.get_response(prompt=..., context=...).
    """
    device_name = alert_row.get('device_name') or alert_row.get('device_ip', 'Unknown')
    device_ip   = alert_row.get('device_ip', '')
    severity    = alert_row.get('severity', 'medium')
    plain_exp   = alert_row.get('plain_explanation', '')
    explanation = alert_row.get('explanation', '')

    context_lines = [
        f"Device: {device_name} ({device_ip})",
        f"Alert severity: {severity}, alerts today: {today_count}",
        f"What triggered this alert: {plain_exp or explanation}",
    ]
    if destinations:
        context_lines.append(
            f"Recent destinations (last 24h): {', '.join(destinations[:5])}"
        )
    if recs:
        context_lines.append(
            "Suggested actions: " + "; ".join(r.get('action', '') for r in recs[:3])
        )

    network_context = (
        "You are IoTSentinel's network security analyst. "
        "You have access to the user's real network data shown below. "
        "Give concise, plain-English answers that reference THIS device and THIS network. "
        "No em dashes. No jargon. No markdown bold. Never suggest expensive tools.\n\n"
        + "\n".join(context_lines)
    )

    prior_turns = [m for m in history[-4:] if m.get('role') != 'system']
    prior = "\n".join(
        f"{'User' if m['role'] == 'user' else 'AI'}: {m['content']}"
        for m in prior_turns
    )
    prompt = f"{prior}\nUser: {question}\nAI:" if prior else f"User: {question}\nAI:"

    return prompt, network_context


def persist(db: Any, alert_id: int, plain_text: str, source: str = None) -> bool:
    """Write LLM-generated plain text to the DB, set the AI flag, and record the source.

    Sets plain_explanation_ai = 1 so the background worker never re-processes
    this alert and the modal callback doesn't duplicate work.
    Records ai_source (e.g. 'groq', 'ollama', 'rules') so the UI can display
    which provider produced this explanation on the alert card.

    Returns True on success, False on error (caller decides whether to retry).
    """
    try:
        cursor = db.conn.cursor()
        cursor.execute(
            "UPDATE alerts "
            "SET plain_explanation = ?, plain_explanation_ai = 1, ai_source = ? "
            "WHERE id = ?",
            (plain_text[:500], source or '', int(alert_id)),
        )
        db.conn.commit()
        return True
    except Exception as exc:
        logger.warning(f"Failed to persist plain_explanation for alert {alert_id}: {exc}")
        return False
