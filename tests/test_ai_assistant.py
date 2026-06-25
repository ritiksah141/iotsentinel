#!/usr/bin/env python3
"""
Unit tests for utils/ai_assistant.py (HybridAIAssistant).

Covers:
- _as_bool: string/bool/None parsing for env-overridden config values
- from_config: defaults, config values, env-var precedence, missing keys
- fallback order: default mode, privacy mode, prefer_local, rules last resort
- config-driven model names passed to the OpenAI/Groq SDK calls
- provider health: success/failure recording, rate-limited WARNING logs,
  Ollama connection errors staying quiet (no WARNING spam on LAN-only Pis)
- get_status_level: ok / degraded / local-only matrix
- response cache: hit, miss, TTL expiry, eviction, history skip,
  rules-never-cached, local-first key separation, thread-safety smoke
- get_stats / get_health / reset_stats

No network calls — providers are stubbed at the _try_* level or via
pre-injected mock SDK clients.

Run: pytest tests/test_ai_assistant.py -v
"""
import logging
import sys
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import utils.ai_assistant as ai_mod
from utils.ai_assistant import HybridAIAssistant, _as_bool


@pytest.fixture(autouse=True)
def _no_env_keys(monkeypatch):
    """Keep developer machines' real API keys out of the tests."""
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)


def make_assistant(**kwargs):
    """Assistant with Ollama disabled by default so no network is touched."""
    kwargs.setdefault("ollama_enabled", False)
    return HybridAIAssistant(**kwargs)


class FakeConfig:
    """Mimics ConfigManager.get(section, key, default)."""

    def __init__(self, section_values=None):
        self._values = section_values or {}

    def get(self, section, key, default=None):
        assert section == 'ai_assistant'
        return self._values.get(key, default)


# ---------------------------------------------------------------------------
# _as_bool
# ---------------------------------------------------------------------------

class TestAsBool:

    @pytest.mark.parametrize("value", [True, "true", "True", "1", "yes", "on"])
    def test_truthy(self, value):
        assert _as_bool(value) is True

    @pytest.mark.parametrize("value", [False, "false", "False", "0", "no", "off", ""])
    def test_falsy(self, value):
        assert _as_bool(value) is False

    def test_none_returns_default(self):
        assert _as_bool(None, default=True) is True
        assert _as_bool(None, default=False) is False


# ---------------------------------------------------------------------------
# Constructor + from_config
# ---------------------------------------------------------------------------

class TestConstruction:

    def test_default_models(self):
        a = make_assistant()
        assert a.groq_model == "llama-3.1-8b-instant"
        assert a.openai_model == "gpt-4o-mini"

    def test_decommissioned_groq_model_not_default(self):
        # llama3-8b-8192 was decommissioned by Groq; the default must never
        # regress to it.
        assert "8192" not in make_assistant().groq_model

    def test_from_config_defaults_with_empty_config(self):
        a = HybridAIAssistant.from_config(FakeConfig())
        assert a.groq_model == "llama-3.1-8b-instant"
        assert a.openai_model == "gpt-4o-mini"
        assert a.ollama_model == "gemma2:2b"
        assert a.ollama_enabled is True
        assert a.cache_ttl == 600
        assert a.cache_max_entries == 100
        assert a.groq_api_key is None
        assert a.openai_api_key is None

    def test_from_config_reads_values(self):
        a = HybridAIAssistant.from_config(FakeConfig({
            'groq_model': 'custom-groq',
            'openai_model': 'custom-openai',
            'ollama_model': 'phi3:mini',
            'ollama_timeout': '20',
            'cache_ttl_seconds': 30,
            'cache_max_entries': 5,
            'groq_api_key': 'cfg-groq-key',  # pragma: allowlist secret
        }))
        assert a.groq_model == 'custom-groq'
        assert a.openai_model == 'custom-openai'
        assert a.ollama_model == 'phi3:mini'
        assert a.ollama_timeout == 20
        assert a.cache_ttl == 30
        assert a.cache_max_entries == 5
        assert a.groq_api_key == 'cfg-groq-key'  # pragma: allowlist secret

    def test_from_config_env_key_beats_config(self, monkeypatch):
        monkeypatch.setenv("GROQ_API_KEY", "env-key")
        a = HybridAIAssistant.from_config(FakeConfig({'groq_api_key': 'cfg-key'}))  # pragma: allowlist secret
        assert a.groq_api_key == "env-key"  # pragma: allowlist secret

    def test_from_config_string_boolean_from_env_override(self):
        # ConfigManager._override_with_env coerces everything to strings.
        a = HybridAIAssistant.from_config(FakeConfig({'ollama_enabled': 'false'}))
        assert a.ollama_enabled is False

    def test_from_config_broken_config_object(self):
        broken = MagicMock()
        broken.get.side_effect = RuntimeError("boom")
        a = HybridAIAssistant.from_config(broken)
        assert a.groq_model == "llama-3.1-8b-instant"

    def test_from_config_privacy_mode(self):
        assert HybridAIAssistant.from_config(FakeConfig(), privacy_mode=True).privacy_mode is True

    def test_availability_properties(self):
        a = make_assistant(groq_api_key="g", openai_api_key=None)
        assert a.groq_available is True
        assert a.openai_available is False


# ---------------------------------------------------------------------------
# Model names reach the SDK calls
# ---------------------------------------------------------------------------

class TestModelNames:

    def _chat_client(self, text="hi"):
        client = MagicMock()
        completion = MagicMock()
        completion.choices = [MagicMock(message=MagicMock(content=text))]
        client.chat.completions.create.return_value = completion
        return client

    def test_groq_called_with_configured_model(self):
        a = make_assistant(groq_api_key="k")
        a._groq_client = self._chat_client()
        result = a._try_groq("q", "", None, 100, 0.5)
        assert result == "hi"
        kwargs = a._groq_client.chat.completions.create.call_args.kwargs
        assert kwargs["model"] == "llama-3.1-8b-instant"

    def test_groq_custom_model(self):
        a = make_assistant(groq_api_key="k", groq_model="my-model")
        a._groq_client = self._chat_client()
        a._try_groq("q", "", None, 100, 0.5)
        kwargs = a._groq_client.chat.completions.create.call_args.kwargs
        assert kwargs["model"] == "my-model"

    def test_openai_called_with_configured_model(self):
        a = make_assistant(openai_api_key="k", openai_model="gpt-custom")
        a._openai_client = self._chat_client()
        a._try_openai("q", "", None, 100, 0.5)
        kwargs = a._openai_client.chat.completions.create.call_args.kwargs
        assert kwargs["model"] == "gpt-custom"


# ---------------------------------------------------------------------------
# Anthropic provider
# ---------------------------------------------------------------------------

class TestAnthropicProvider:

    def _client(self, text="claude says"):
        client = MagicMock()
        block = MagicMock()
        block.type = "text"
        block.text = text
        response = MagicMock()
        response.content = [block]
        client.messages.create.return_value = response
        return client

    def test_success(self):
        a = make_assistant(anthropic_api_key="k")
        a._anthropic_client = self._client()
        assert a._try_anthropic("q", "ctx", None, 100, 0.5) == "claude says"

    def test_model_and_system_param(self):
        a = make_assistant(anthropic_api_key="k", anthropic_model="claude-custom")
        a._anthropic_client = self._client()
        a._try_anthropic("q", "network context", None, 120, 0.4)
        kwargs = a._anthropic_client.messages.create.call_args.kwargs
        assert kwargs["model"] == "claude-custom"
        assert kwargs["system"] == "network context"
        assert kwargs["max_tokens"] == 120
        # Context must never appear as a system-role message
        assert all(m["role"] != "system" for m in kwargs["messages"])

    def test_no_system_param_without_context(self):
        a = make_assistant(anthropic_api_key="k")
        a._anthropic_client = self._client()
        a._try_anthropic("q", "", None, 100, 0.5)
        assert "system" not in a._anthropic_client.messages.create.call_args.kwargs

    def test_default_model(self):
        assert make_assistant().anthropic_model == "claude-haiku-4-5"

    def test_failure_records_health(self):
        a = make_assistant(anthropic_api_key="k")
        client = MagicMock()
        client.messages.create.side_effect = RuntimeError("overloaded")
        a._anthropic_client = client
        assert a._try_anthropic("q", "", None, 100, 0.5) is None
        assert "overloaded" in a.provider_health["anthropic"]["last_error"]

    def test_non_text_blocks_skipped(self):
        a = make_assistant(anthropic_api_key="k")
        thinking = MagicMock()
        thinking.type = "thinking"
        block = MagicMock()
        block.type = "text"
        block.text = "answer"
        response = MagicMock()
        response.content = [thinking, block]
        client = MagicMock()
        client.messages.create.return_value = response
        a._anthropic_client = client
        assert a._try_anthropic("q", "", None, 100, 0.5) == "answer"

    def test_history_passed_through(self):
        a = make_assistant(anthropic_api_key="k")
        a._anthropic_client = self._client()
        history = [{"role": "user", "content": "earlier"},
                   {"role": "assistant", "content": "reply"}]
        a._try_anthropic("q", "", history, 100, 0.5)
        messages = a._anthropic_client.messages.create.call_args.kwargs["messages"]
        assert messages[0] == {"role": "user", "content": "earlier"}
        assert messages[-1] == {"role": "user", "content": "q"}


# ---------------------------------------------------------------------------
# Gemini provider
# ---------------------------------------------------------------------------

class TestGeminiProvider:

    def _response(self, text="gemini says", status=200, candidates=None):
        resp = MagicMock()
        resp.status_code = status
        if candidates is None:
            candidates = [{"content": {"parts": [{"text": text}]}}]
        resp.json.return_value = {"candidates": candidates}
        return resp

    def test_success(self):
        a = make_assistant(gemini_api_key="k")
        with patch.object(ai_mod.requests, "post", return_value=self._response()) as post:
            assert a._try_gemini("q", "ctx", None, 100, 0.5) == "gemini says"
        url = post.call_args.args[0]
        assert "gemini-2.5-flash:generateContent" in url
        assert "key=" not in url  # key travels in the header, never the URL
        assert post.call_args.kwargs["headers"]["x-goog-api-key"] == "k"

    def test_body_shape(self):
        a = make_assistant(gemini_api_key="k", gemini_model="gemini-custom")
        history = [{"role": "assistant", "content": "earlier reply"}]
        with patch.object(ai_mod.requests, "post", return_value=self._response()) as post:
            a._try_gemini("q", "ctx", history, 150, 0.3)
        assert "gemini-custom" in post.call_args.args[0]
        body = post.call_args.kwargs["json"]
        assert body["system_instruction"] == {"parts": [{"text": "ctx"}]}
        assert body["generationConfig"]["maxOutputTokens"] == 150
        assert body["contents"][0]["role"] == "model"  # assistant -> model
        assert body["contents"][-1] == {"role": "user", "parts": [{"text": "q"}]}

    def test_non_200_fails(self):
        a = make_assistant(gemini_api_key="k")
        with patch.object(ai_mod.requests, "post", return_value=self._response(status=429)):
            assert a._try_gemini("q", "", None, 100, 0.5) is None
        assert "429" in a.provider_health["gemini"]["last_error"]

    def test_empty_candidates_fails_quietly(self, caplog):
        a = make_assistant(gemini_api_key="k")
        with caplog.at_level(logging.WARNING, logger="utils.ai_assistant"):
            with patch.object(ai_mod.requests, "post",
                              return_value=self._response(candidates=[])):
                assert a._try_gemini("q", "", None, 100, 0.5) is None
        assert [r for r in caplog.records if r.levelno == logging.WARNING] == []

    def test_timeout_records_health(self):
        a = make_assistant(gemini_api_key="k")
        with patch.object(ai_mod.requests, "post",
                          side_effect=ai_mod.requests.exceptions.Timeout()):
            assert a._try_gemini("q", "", None, 100, 0.5) is None
        assert "timed out" in a.provider_health["gemini"]["last_error"]


# ---------------------------------------------------------------------------
# On-device Ollama status probe (drives the privacy-mode UI honesty)
# ---------------------------------------------------------------------------

class TestOllamaStatus:
    """ollama_status() actively probes the local Ollama server so privacy mode can
    tell the user whether AI truly stays on-device or will fall back to cloud."""

    def _tags(self, models, status=200):
        resp = MagicMock()
        resp.status_code = status
        resp.json.return_value = {"models": [{"name": n} for n in models]}
        return resp

    def test_disabled_when_ollama_off(self):
        st = HybridAIAssistant(ollama_enabled=False).ollama_status()
        assert st["enabled"] is False
        assert st["reachable"] is False and st["model_present"] is False

    def test_ready_when_running_and_model_present(self):
        a = HybridAIAssistant(ollama_enabled=True, ollama_model="gemma2:2b")
        with patch.object(ai_mod.requests, "get",
                          return_value=self._tags(["gemma2:2b", "llama3:8b"])):
            st = a.ollama_status()
        assert st["reachable"] is True and st["model_present"] is True
        assert "ready" in st["detail"].lower()

    def test_running_but_model_not_pulled(self):
        a = HybridAIAssistant(ollama_enabled=True, ollama_model="gemma2:2b")
        with patch.object(ai_mod.requests, "get", return_value=self._tags(["llama3:8b"])):
            st = a.ollama_status()
        assert st["reachable"] is True and st["model_present"] is False

    def test_model_family_tag_counts_as_present(self):
        a = HybridAIAssistant(ollama_enabled=True, ollama_model="gemma2:2b")
        with patch.object(ai_mod.requests, "get", return_value=self._tags(["gemma2:latest"])):
            st = a.ollama_status()
        assert st["model_present"] is True

    def test_not_reachable_falls_back_to_cloud(self):
        a = HybridAIAssistant(ollama_enabled=True)
        with patch.object(ai_mod.requests, "get",
                          side_effect=ai_mod.requests.exceptions.ConnectionError()):
            st = a.ollama_status()
        assert st["reachable"] is False and st["model_present"] is False
        assert "not reachable" in st["detail"].lower()


# ---------------------------------------------------------------------------
# Fallback order
# ---------------------------------------------------------------------------

class TestFallbackOrder:

    def test_openai_first_when_available(self):
        a = make_assistant(openai_api_key="o", groq_api_key="g")
        a._try_openai = MagicMock(return_value="openai says")
        a._try_groq = MagicMock(return_value="groq says")
        text, source = a.get_response("hello")
        assert (text, source) == ("openai says", "openai")
        a._try_groq.assert_not_called()

    def test_groq_after_openai_failure(self):
        a = make_assistant(openai_api_key="o", groq_api_key="g")
        a._try_openai = MagicMock(return_value=None)
        a._try_groq = MagicMock(return_value="groq says")
        text, source = a.get_response("hello")
        assert (text, source) == ("groq says", "groq")
        assert a.stats["openai_failures"] == 1

    def test_unconfigured_providers_skipped(self):
        a = make_assistant(groq_api_key="g")
        a._try_openai = MagicMock(return_value="never")
        a._try_groq = MagicMock(return_value="groq says")
        text, source = a.get_response("hello")
        assert source == "groq"
        a._try_openai.assert_not_called()

    def test_ollama_last_resort_in_default_mode(self):
        a = HybridAIAssistant(groq_api_key="g", ollama_enabled=True)
        a._try_groq = MagicMock(return_value=None)
        a._try_ollama = MagicMock(return_value="local says")
        text, source = a.get_response("hello")
        assert (text, source) == ("local says", "ollama")
        # Ollama only after cloud
        assert a._try_groq.called

    def test_rules_when_everything_fails(self):
        a = HybridAIAssistant(groq_api_key="g", ollama_enabled=True)
        a._try_groq = MagicMock(return_value=None)
        a._try_ollama = MagicMock(return_value=None)
        text, source = a.get_response("how many devices?")
        assert source == "rules"
        assert "Devices" in text
        assert a.stats["rule_requests"] == 1

    def test_rules_when_nothing_configured(self):
        a = make_assistant()
        text, source = a.get_response("hello")
        assert source == "rules"

    def test_privacy_mode_ollama_first(self):
        a = HybridAIAssistant(groq_api_key="g", ollama_enabled=True, privacy_mode=True)
        a._try_groq = MagicMock(return_value="groq says")
        a._try_ollama = MagicMock(return_value="local says")
        text, source = a.get_response("hello")
        assert (text, source) == ("local says", "ollama")
        a._try_groq.assert_not_called()

    def test_privacy_mode_cloud_fallback_after_ollama_fails(self):
        # Privacy mode is local-FIRST, not local-only: when on-device Ollama is
        # unavailable the cloud chain is still used as a fallback (by design — see
        # setup_local_ai.sh / the wizard's "Local first" vs "Cloud first" choice).
        a = HybridAIAssistant(groq_api_key="g", ollama_enabled=True, privacy_mode=True)
        a._try_groq = MagicMock(return_value="groq says")
        a._try_ollama = MagicMock(return_value=None)
        text, source = a.get_response("hello")
        assert (text, source) == ("groq says", "groq")
        # Ollama must not be retried as last resort in local-first mode
        assert a._try_ollama.call_count == 1

    def test_prefer_local_behaves_like_privacy_mode(self):
        a = HybridAIAssistant(groq_api_key="g", ollama_enabled=True)
        a._try_groq = MagicMock(return_value="groq says")
        a._try_ollama = MagicMock(return_value="local says")
        text, source = a.get_response("hello", prefer_local=True)
        assert source == "ollama"
        a._try_groq.assert_not_called()

    def test_stats_counters(self):
        a = make_assistant(groq_api_key="g")
        a._try_groq = MagicMock(return_value="x")
        a.get_response("a")
        a.get_response("b")
        assert a.stats["total_requests"] == 2
        assert a.stats["groq_requests"] == 2
        assert a.stats["groq_failures"] == 0

    def test_full_six_tier_order(self):
        a = HybridAIAssistant(openai_api_key="o", anthropic_api_key="a",
                              groq_api_key="g", gemini_api_key="ge",
                              ollama_enabled=True)
        calls = []
        for name in ("openai", "anthropic", "groq", "gemini", "ollama"):
            setattr(a, f"_try_{name}",
                    MagicMock(side_effect=lambda *args, _n=name, **kw: calls.append(_n)))
        text, source = a.get_response("how many devices?")
        assert calls == ["openai", "anthropic", "groq", "gemini", "ollama"]
        assert source == "rules"

    def test_anthropic_before_groq(self):
        a = make_assistant(anthropic_api_key="a", groq_api_key="g")
        a._try_anthropic = MagicMock(return_value="claude says")
        a._try_groq = MagicMock(return_value="groq says")
        text, source = a.get_response("q")
        assert source == "anthropic"
        a._try_groq.assert_not_called()

    def test_gemini_after_groq_failure(self):
        a = make_assistant(groq_api_key="g", gemini_api_key="ge")
        a._try_groq = MagicMock(return_value=None)
        a._try_gemini = MagicMock(return_value="gemini says")
        text, source = a.get_response("q")
        assert (text, source) == ("gemini says", "gemini")

    def test_has_llm_provider_with_new_providers(self):
        assert make_assistant(anthropic_api_key="a").has_llm_provider() is True
        assert make_assistant(gemini_api_key="g").has_llm_provider() is True
        assert make_assistant().has_llm_provider() is False


# ---------------------------------------------------------------------------
# Provider health + logging
# ---------------------------------------------------------------------------

class TestProviderHealth:

    def test_success_recorded(self):
        a = make_assistant(groq_api_key="g")
        a._try_groq = MagicMock(return_value="x")
        a.get_response("q")
        assert a.provider_health["groq"]["last_success_time"] is not None
        assert a.provider_health["groq"]["last_error"] is None

    def test_failure_recorded_via_note_error(self):
        a = make_assistant()
        a._note_error("groq", RuntimeError("rate limit hit"))
        health = a.provider_health["groq"]
        assert "rate limit hit" in health["last_error"]
        assert health["last_error_time"] is not None

    def test_error_message_truncated_to_200(self):
        a = make_assistant()
        a._note_error("groq", "x" * 500)
        assert len(a.provider_health["groq"]["last_error"]) == 200

    def test_warning_logged_once_per_interval(self, caplog):
        a = make_assistant()
        with caplog.at_level(logging.WARNING, logger="utils.ai_assistant"):
            a._note_error("groq", "boom 1")
            a._note_error("groq", "boom 2")
        warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert len(warnings) == 1
        assert "groq" in warnings[0].message

    def test_warning_again_after_interval(self, caplog):
        a = make_assistant()
        with caplog.at_level(logging.WARNING, logger="utils.ai_assistant"):
            a._note_error("groq", "boom 1")
            a._last_warn_time["groq"] -= ai_mod._WARN_INTERVAL_SECONDS + 1
            a._note_error("groq", "boom 2")
        warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert len(warnings) == 2

    def test_warnings_rate_limited_per_provider(self, caplog):
        a = make_assistant()
        with caplog.at_level(logging.WARNING, logger="utils.ai_assistant"):
            a._note_error("groq", "boom")
            a._note_error("openai", "boom")
        warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert len(warnings) == 2

    def test_ollama_connection_error_no_warning(self, caplog):
        a = HybridAIAssistant(ollama_enabled=True)
        with caplog.at_level(logging.WARNING, logger="utils.ai_assistant"):
            with patch.object(ai_mod.requests, "post",
                              side_effect=ai_mod.requests.exceptions.ConnectionError()):
                result = a._try_ollama("q", "", None, 100, 0.5)
        assert result is None
        assert a.provider_health["ollama"]["last_error"] is not None
        warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert warnings == []

    def test_ollama_timeout_warns(self, caplog):
        a = HybridAIAssistant(ollama_enabled=True)
        with caplog.at_level(logging.WARNING, logger="utils.ai_assistant"):
            with patch.object(ai_mod.requests, "post",
                              side_effect=ai_mod.requests.exceptions.Timeout()):
                a._try_ollama("q", "", None, 100, 0.5)
        warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert len(warnings) == 1

    def test_sdk_failure_records_health(self):
        a = make_assistant(groq_api_key="k")
        client = MagicMock()
        client.chat.completions.create.side_effect = RuntimeError("401 invalid key")
        a._groq_client = client
        assert a._try_groq("q", "", None, 100, 0.5) is None
        assert "401" in a.provider_health["groq"]["last_error"]

    def test_get_health_shape(self):
        a = make_assistant(groq_api_key="g")
        health = a.get_health()
        assert health["providers"]["groq"]["configured"] is True
        assert health["providers"]["openai"]["configured"] is False
        assert health["privacy_mode"] is False
        assert health["status_level"] == "ok"
        assert health["cache"]["ttl_seconds"] == 600


# ---------------------------------------------------------------------------
# get_status_level
# ---------------------------------------------------------------------------

class TestStatusLevel:

    def test_ok_when_no_cloud_configured(self):
        assert make_assistant().get_status_level() == "ok"

    def test_ok_when_configured_and_healthy(self):
        a = make_assistant(groq_api_key="g")
        assert a.get_status_level() == "ok"

    def test_local_only_when_all_cloud_failing(self):
        a = make_assistant(groq_api_key="g")
        a._note_error("groq", "down")
        assert a.get_status_level() == "local-only"

    def test_degraded_when_one_of_two_failing(self):
        a = make_assistant(groq_api_key="g", openai_api_key="o")
        a._note_error("groq", "down")
        a._record_success("openai")
        assert a.get_status_level() == "degraded"

    def test_recovers_after_success(self):
        a = make_assistant(groq_api_key="g")
        a._note_error("groq", "down")
        a._record_success("groq")
        assert a.get_status_level() == "ok"

    def test_old_errors_ignored(self):
        a = make_assistant(groq_api_key="g")
        a._note_error("groq", "down")
        a.provider_health["groq"]["last_error_time"] -= ai_mod._FAILING_WINDOW_SECONDS + 1
        assert a.get_status_level() == "ok"

    def test_new_providers_counted_as_cloud(self):
        a = make_assistant(anthropic_api_key="a", gemini_api_key="g")
        a._note_error("anthropic", "down")
        assert a.get_status_level() == "degraded"
        a._note_error("gemini", "down")
        assert a.get_status_level() == "local-only"


# ---------------------------------------------------------------------------
# Response cache
# ---------------------------------------------------------------------------

class TestResponseCache:

    def _assistant(self, **kwargs):
        a = make_assistant(groq_api_key="g", **kwargs)
        a._try_groq = MagicMock(return_value="answer")
        return a

    def test_cache_hit_skips_provider(self):
        a = self._assistant()
        a.get_response("same question")
        a.get_response("same question")
        assert a._try_groq.call_count == 1
        assert a.stats["cache_hits"] == 1
        assert a.stats["groq_requests"] == 1

    def test_cached_source_preserved(self):
        a = self._assistant()
        a.get_response("q")
        text, source = a.get_response("q")
        assert (text, source) == ("answer", "groq")

    def test_different_prompts_miss(self):
        a = self._assistant()
        a.get_response("q1")
        a.get_response("q2")
        assert a._try_groq.call_count == 2

    def test_different_params_miss(self):
        a = self._assistant()
        a.get_response("q", max_tokens=100)
        a.get_response("q", max_tokens=200)
        assert a._try_groq.call_count == 2

    def test_history_never_cached(self):
        a = self._assistant()
        history = [{"role": "user", "content": "earlier"}]
        a.get_response("q", history=history)
        a.get_response("q", history=history)
        assert a._try_groq.call_count == 2
        assert a.stats["cache_hits"] == 0

    def test_rules_response_not_cached(self):
        a = make_assistant()  # nothing configured -> rules
        a.get_response("hello")
        a.get_response("hello")
        assert a.stats["cache_hits"] == 0
        assert a.stats["rule_requests"] == 2

    def test_ttl_expiry(self):
        a = self._assistant()
        a.get_response("q")
        key = next(iter(a._cache))
        stored_at, text, source = a._cache[key]
        a._cache[key] = (stored_at - a.cache_ttl - 1, text, source)
        a.get_response("q")
        assert a._try_groq.call_count == 2

    def test_eviction_at_max_entries(self):
        a = self._assistant(cache_max_entries=3)
        for i in range(5):
            a.get_response(f"q{i}")
        assert len(a._cache) == 3
        # Oldest entries evicted -> q0 misses again
        a.get_response("q0")
        assert a._try_groq.call_count == 6

    def test_local_first_uses_separate_key(self):
        a = HybridAIAssistant(groq_api_key="g", ollama_enabled=True)
        a._try_groq = MagicMock(return_value="cloud answer")
        a._try_ollama = MagicMock(return_value="local answer")
        text1, _ = a.get_response("q")
        text2, _ = a.get_response("q", prefer_local=True)
        assert text1 == "cloud answer"
        assert text2 == "local answer"

    def test_cache_disabled_with_zero_ttl(self):
        a = self._assistant(cache_ttl=0)
        a.get_response("q")
        a.get_response("q")
        assert a._try_groq.call_count == 2

    def test_thread_safety_smoke(self):
        a = self._assistant()
        errors = []

        def worker(n):
            try:
                for i in range(50):
                    a.get_response(f"q{n}-{i % 5}")
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(n,)) for n in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert errors == []
        assert len(a._cache) <= a.cache_max_entries


# ---------------------------------------------------------------------------
# Stats / status message
# ---------------------------------------------------------------------------

class TestStats:

    def test_get_stats_zero_requests(self):
        stats = make_assistant().get_stats()
        assert stats["total_requests"] == 0
        assert stats["cache_hits"] == 0

    def test_get_stats_includes_cache_hits(self):
        a = make_assistant(groq_api_key="g")
        a._try_groq = MagicMock(return_value="x")
        a.get_response("q")
        a.get_response("q")
        assert a.get_stats()["cache_hits"] == 1

    def test_reset_stats(self):
        a = make_assistant(groq_api_key="g")
        a._try_groq = MagicMock(return_value="x")
        a.get_response("q")
        a.reset_stats()
        assert a.stats["total_requests"] == 0
        assert a.stats["cache_hits"] == 0

    def test_status_message_ready_states(self):
        assert "Groq" in make_assistant(groq_api_key="g").get_status_message()
        assert "Rules" in make_assistant().get_status_message()

    def test_status_message_active_primary(self):
        a = make_assistant(groq_api_key="g")
        a._try_groq = MagicMock(return_value="x")
        a.get_response("q1")
        a.get_response("q2")
        assert "Groq" in a.get_status_message()
