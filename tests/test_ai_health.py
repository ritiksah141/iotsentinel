#!/usr/bin/env python3
"""
Unit tests for utils/ai_health.py (pure helpers behind the admin
"AI Engine Health" card).

Covers:
- relative_age formatting buckets
- build_health_rows: off / untested / ok / failing states, rules row,
  error tooltips, provider ordering
- build_usage_line: zero requests, distribution, cache hits

Run: pytest tests/test_ai_health.py -v
"""
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.ai_health import (
    PROVIDER_ORDER,
    relative_age,
    build_health_rows,
    build_usage_line,
)

NOW = 1_750_000_000.0


def make_health(**providers):
    base = {name: {"last_error": None, "last_error_time": None,
                   "last_success_time": None, "configured": False}
            for name in PROVIDER_ORDER}
    for name, overrides in providers.items():
        base[name].update(overrides)
    return {"providers": base, "privacy_mode": False, "status_level": "ok",
            "cache": {"entries": 0, "hits": 0, "ttl_seconds": 600}}


class TestRelativeAge:

    def test_empty_for_none(self):
        assert relative_age(None) == ""
        assert relative_age(0) == ""

    def test_just_now(self):
        assert relative_age(NOW - 5, NOW) == "just now"

    def test_minutes(self):
        assert relative_age(NOW - 120, NOW) == "2 minutes ago"
        assert relative_age(NOW - 60, NOW) == "1 minute ago"

    def test_hours(self):
        assert relative_age(NOW - 7200, NOW) == "2 hours ago"

    def test_days(self):
        assert relative_age(NOW - 3 * 86400, NOW) == "3 days ago"

    def test_future_clamped(self):
        assert relative_age(NOW + 100, NOW) == "just now"


class TestBuildHealthRows:

    def test_row_order_and_rules_last(self):
        rows = build_health_rows(make_health(), now=NOW)
        assert [r["provider"] for r in rows] == list(PROVIDER_ORDER) + ["rules"]

    def test_unconfigured_is_off(self):
        rows = build_health_rows(make_health(), now=NOW)
        groq = next(r for r in rows if r["provider"] == "groq")
        assert groq["status"] == "off"
        assert groq["detail"] == "Not configured"

    def test_configured_untested(self):
        health = make_health(groq={"configured": True})
        groq = next(r for r in build_health_rows(health, now=NOW)
                    if r["provider"] == "groq")
        assert groq["status"] == "untested"

    def test_working_provider(self):
        health = make_health(groq={"configured": True,
                                   "last_success_time": NOW - 60})
        groq = next(r for r in build_health_rows(health, now=NOW)
                    if r["provider"] == "groq")
        assert groq["status"] == "ok"
        assert "1 minute ago" in groq["detail"]

    def test_failing_provider_with_tooltip(self):
        health = make_health(groq={"configured": True,
                                   "last_error": "401 invalid key",
                                   "last_error_time": NOW - 30,
                                   "last_success_time": NOW - 600})
        groq = next(r for r in build_health_rows(health, now=NOW)
                    if r["provider"] == "groq")
        assert groq["status"] == "failing"
        assert groq["last_error"] == "401 invalid key"

    def test_recovered_provider_is_ok(self):
        health = make_health(groq={"configured": True,
                                   "last_error": "blip",
                                   "last_error_time": NOW - 600,
                                   "last_success_time": NOW - 30})
        groq = next(r for r in build_health_rows(health, now=NOW)
                    if r["provider"] == "groq")
        assert groq["status"] == "ok"

    def test_rules_always_ok(self):
        rules = build_health_rows(make_health(), now=NOW)[-1]
        assert rules["status"] == "ok"
        assert rules["label"] == "Smart Template"

    def test_labels_use_source_label(self):
        rows = build_health_rows(make_health(), now=NOW)
        labels = {r["provider"]: r["label"] for r in rows}
        assert labels["anthropic"] == "Claude AI"
        assert labels["gemini"] == "Gemini AI"
        assert labels["ollama"] == "Local AI"

    def test_empty_health_does_not_crash(self):
        rows = build_health_rows({}, now=NOW)
        assert len(rows) == len(PROVIDER_ORDER) + 1


class TestBuildUsageLine:

    def test_no_requests(self):
        assert "No AI requests yet" in build_usage_line({"total_requests": 0})
        assert "No AI requests yet" in build_usage_line({})

    def test_distribution(self):
        line = build_usage_line({
            "total_requests": 10,
            "groq_percent": 80.0,
            "ollama_percent": 10.0,
            "rules_percent": 10.0,
        })
        assert "10 requests" in line
        assert "Groq AI 80.0%" in line
        assert "Local AI 10.0%" in line
        assert "Smart Template 10.0%" in line

    def test_cache_hits_mentioned(self):
        line = build_usage_line({"total_requests": 5, "groq_percent": 100.0,
                                 "cache_hits": 3})
        assert "3 answered from cache" in line

    def test_no_cache_hits_no_mention(self):
        line = build_usage_line({"total_requests": 5, "groq_percent": 100.0})
        assert "cache" not in line
