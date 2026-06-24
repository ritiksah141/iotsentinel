#!/usr/bin/env python3
"""
Hybrid AI Assistant for IoTSentinel

Multi-tier intelligent fallback system:
1. OpenAI API     (cloud, paid — business tier)
2. Anthropic API  (cloud, paid — Claude Haiku)
3. Groq API       (cloud, free tier — 14,400 requests/day)
4. Google Gemini  (cloud, free tier — ~250 requests/day)
5. Ollama gemma2:2b (local Pi server)
6. Rule-based responses (offline fallback)

Optimized for Raspberry Pi 4GB RAM.
"""

import hashlib
import os
import logging
import threading
import time
from collections import OrderedDict
import requests
from typing import Optional, Tuple, List, Dict

logger = logging.getLogger(__name__)

# Provider failures are logged at WARNING at most once per provider per this
# interval; every individual failure is still logged at DEBUG.
_WARN_INTERVAL_SECONDS = 600

# Window used by get_status_level() to decide whether a provider is
# "currently failing" (an error more recent than its last success).
_FAILING_WINDOW_SECONDS = 600


def _as_bool(value, default: bool = False) -> bool:
    """Parse config/env values that may arrive as strings ('true', '1', ...)."""
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ('1', 'true', 'yes', 'on')


class HybridAIAssistant:
    """
    Smart AI assistant with automatic fallback and source tracking.

    Prioritizes speed and availability:
    - OpenAI/Groq for best quality (2-3s responses)
    - Local LLM when offline (5-10s responses)
    - Rules when both fail (instant responses)
    """

    def __init__(self,
                 ollama_url: str = "http://localhost:11434/api/generate",
                 ollama_model: str = "gemma2:2b",
                 groq_api_key: Optional[str] = None,
                 openai_api_key: Optional[str] = None,
                 ollama_enabled: bool = True,
                 ollama_timeout: int = 15,
                 privacy_mode: bool = False,
                 groq_model: str = "llama-3.1-8b-instant",
                 openai_model: str = "gpt-4o-mini",
                 anthropic_api_key: Optional[str] = None,
                 anthropic_model: str = "claude-haiku-4-5",
                 gemini_api_key: Optional[str] = None,
                 gemini_model: str = "gemini-2.5-flash",
                 cache_ttl: int = 600,
                 cache_max_entries: int = 100):
        self.ollama_url = ollama_url
        self.ollama_model = ollama_model
        self.ollama_enabled = ollama_enabled
        self.ollama_timeout = ollama_timeout
        self.groq_api_key = groq_api_key or os.getenv("GROQ_API_KEY")
        self.openai_api_key = openai_api_key or os.getenv("OPENAI_API_KEY")
        self.anthropic_api_key = anthropic_api_key or os.getenv("ANTHROPIC_API_KEY")
        self.gemini_api_key = gemini_api_key or os.getenv("GEMINI_API_KEY")
        self.groq_model = groq_model
        self.openai_model = openai_model
        self.anthropic_model = anthropic_model
        self.gemini_model = gemini_model
        # When True: Ollama is tried before cloud providers — all AI stays on-device.
        self.privacy_mode = privacy_mode

        self._groq_client = None
        self._openai_client = None
        self._anthropic_client = None

        # Response cache: identical prompts within the TTL are answered from
        # memory instead of burning provider quota. Chat turns (history) are
        # never cached. Thread-safe — used from Dash callbacks and the
        # orchestrator's background threads.
        self.cache_ttl = max(0, int(cache_ttl))
        self.cache_max_entries = max(1, int(cache_max_entries))
        self._cache: "OrderedDict[str, Tuple[float, str, str]]" = OrderedDict()
        self._cache_lock = threading.Lock()

        # Per-provider health for the admin AI Engine panel and status chip.
        self.provider_health = {
            name: {"last_error": None, "last_error_time": None, "last_success_time": None}
            for name in ("openai", "anthropic", "groq", "gemini", "ollama")
        }
        self._health_lock = threading.Lock()
        self._last_warn_time: Dict[str, float] = {}

        self.stats = self._fresh_stats()

    @staticmethod
    def _fresh_stats() -> dict:
        return {
            "total_requests": 0,
            "openai_requests": 0,
            "anthropic_requests": 0,
            "groq_requests": 0,
            "gemini_requests": 0,
            "ollama_requests": 0,
            "rule_requests": 0,
            "openai_failures": 0,
            "anthropic_failures": 0,
            "groq_failures": 0,
            "gemini_failures": 0,
            "ollama_failures": 0,
            "cache_hits": 0
        }

    @classmethod
    def from_config(cls, config, privacy_mode: bool = False) -> "HybridAIAssistant":
        """Build an assistant from the `ai_assistant` config section.

        Every key falls back to a safe default so installs whose JSON predates
        a key keep working. Env vars take precedence over config for API keys.
        """
        def _get(key, default=None):
            try:
                return config.get('ai_assistant', key, default)
            except Exception:
                return default

        return cls(
            groq_api_key=os.getenv("GROQ_API_KEY") or _get('groq_api_key', '') or None,
            openai_api_key=os.getenv("OPENAI_API_KEY") or _get('openai_api_key', '') or None,
            anthropic_api_key=os.getenv("ANTHROPIC_API_KEY") or _get('anthropic_api_key', '') or None,
            gemini_api_key=os.getenv("GEMINI_API_KEY") or _get('gemini_api_key', '') or None,
            ollama_url=_get('ollama_url', "http://localhost:11434/api/generate"),
            ollama_model=_get('ollama_model', "gemma2:2b"),
            ollama_enabled=_as_bool(_get('ollama_enabled', True), True),
            ollama_timeout=int(_get('ollama_timeout', 15)),
            groq_model=_get('groq_model', "llama-3.1-8b-instant"),
            openai_model=_get('openai_model', "gpt-4o-mini"),
            anthropic_model=_get('anthropic_model', "claude-haiku-4-5"),
            gemini_model=_get('gemini_model', "gemini-2.5-flash"),
            cache_ttl=int(_get('cache_ttl_seconds', 600)),
            cache_max_entries=int(_get('cache_max_entries', 100)),
            privacy_mode=privacy_mode,
        )

    @property
    def groq_available(self) -> bool:
        return self.groq_api_key is not None

    @property
    def openai_available(self) -> bool:
        return self.openai_api_key is not None

    @property
    def anthropic_available(self) -> bool:
        return self.anthropic_api_key is not None

    @property
    def gemini_available(self) -> bool:
        return self.gemini_api_key is not None

    def has_llm_provider(self) -> bool:
        """Return True if at least one real LLM provider is configured.

        Used by the background plain-English rewrite worker to skip rewriting
        when only the rule-based fallback is available (overwriting a MITRE
        template with a canned rule string is no improvement).
        """
        if (self.openai_available or self.anthropic_available
                or self.groq_available or self.gemini_available):
            return True
        if self.ollama_enabled:
            # Quick connectivity check — Ollama may or may not be running.
            try:
                import requests as _req
                _req.get(self.ollama_url.replace("/api/generate", "/"), timeout=1)
                return True
            except Exception:
                pass
        return False

    # ------------------------------------------------------------------
    # Health tracking
    # ------------------------------------------------------------------

    def _record_success(self, provider: str):
        with self._health_lock:
            health = self.provider_health.get(provider)
            if health is not None:
                health["last_success_time"] = time.time()

    def _note_error(self, provider: str, message, warn: bool = True):
        """Record a provider failure and surface it at WARNING (rate-limited)."""
        text = str(message)[:200]
        logger.debug(f"{provider} failed: {text}")
        now = time.time()
        should_warn = False
        with self._health_lock:
            health = self.provider_health.get(provider)
            if health is not None:
                health["last_error"] = text
                health["last_error_time"] = now
            if warn and now - self._last_warn_time.get(provider, 0) >= _WARN_INTERVAL_SECONDS:
                self._last_warn_time[provider] = now
                should_warn = True
        if should_warn:
            logger.warning(f"AI provider '{provider}' is failing: {text}")

    def _provider_configured(self, provider: str) -> bool:
        if provider == "openai":
            return self.openai_available
        if provider == "anthropic":
            return self.anthropic_available
        if provider == "groq":
            return self.groq_available
        if provider == "gemini":
            return self.gemini_available
        if provider == "ollama":
            return self.ollama_enabled
        return False

    def get_health(self) -> dict:
        """Per-provider health snapshot for the admin AI Engine panel."""
        with self._health_lock:
            providers = {name: dict(state) for name, state in self.provider_health.items()}
        for name, state in providers.items():
            state["configured"] = self._provider_configured(name)
        with self._cache_lock:
            cache_entries = len(self._cache)
        return {
            "providers": providers,
            "privacy_mode": self.privacy_mode,
            "status_level": self.get_status_level(),
            "cache": {
                "entries": cache_entries,
                "hits": self.stats.get("cache_hits", 0),
                "ttl_seconds": self.cache_ttl,
            },
        }

    # Fallback order: paid tier (OpenAI, Claude) before free tier (Groq, Gemini).
    _CLOUD_ORDER = ("openai", "anthropic", "groq", "gemini")

    def _cloud_provider_names(self) -> List[str]:
        return [name for name in self._CLOUD_ORDER if self._provider_configured(name)]

    def get_status_level(self) -> str:
        """Overall AI engine state: 'ok', 'degraded' or 'local-only'.

        degraded   — at least one configured cloud provider is currently failing
        local-only — every configured cloud provider is currently failing
        """
        cloud = self._cloud_provider_names()
        if not cloud:
            return "ok"  # rules/Ollama-only installs are healthy by design

        now = time.time()

        def _failing(name: str) -> bool:
            with self._health_lock:
                state = self.provider_health.get(name, {})
                err_time = state.get("last_error_time")
                ok_time = state.get("last_success_time")
            if not err_time or now - err_time > _FAILING_WINDOW_SECONDS:
                return False
            return ok_time is None or ok_time < err_time

        failing = [name for name in cloud if _failing(name)]
        if not failing:
            return "ok"
        if len(failing) == len(cloud):
            return "local-only"
        return "degraded"

    # ------------------------------------------------------------------
    # Response cache
    # ------------------------------------------------------------------

    def _cache_key(self, prompt: str, context: str, max_tokens: int,
                   temperature: float, use_local_first: bool) -> str:
        raw = f"{prompt}\x1f{context}\x1f{max_tokens}\x1f{temperature}\x1f{use_local_first}"
        return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()

    def _cache_get(self, key: str) -> Optional[Tuple[str, str]]:
        now = time.time()
        with self._cache_lock:
            entry = self._cache.get(key)
            if entry is None:
                return None
            stored_at, text, source = entry
            if now - stored_at > self.cache_ttl:
                self._cache.pop(key, None)
                return None
            self._cache.move_to_end(key)
            return text, source

    def _cache_put(self, key: str, text: str, source: str):
        now = time.time()
        with self._cache_lock:
            self._cache[key] = (now, text, source)
            self._cache.move_to_end(key)
            while len(self._cache) > self.cache_max_entries:
                self._cache.popitem(last=False)

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def get_response(self,
                     prompt: str,
                     context: str = "",
                     history: Optional[List[Dict]] = None,
                     max_tokens: int = 300,
                     temperature: float = 0.7,
                     prefer_local: bool = False) -> Tuple[str, str]:
        """
        Get AI response with automatic fallback.

        Args:
            prompt: User's question/message
            context: System context (network status, alerts, etc.)
            history: Prior conversation turns [{role, content}, ...]
            max_tokens: Maximum response length
            temperature: Creativity (0.0 = deterministic, 1.0 = creative)
            prefer_local: Skip cloud providers and go straight to Ollama/rules

        Returns:
            Tuple of (response_text, source_name)
            source_name: 'openai', 'groq', 'ollama', or 'rules'
        """
        self.stats["total_requests"] += 1

        use_local_first = prefer_local or self.privacy_mode

        # Cache lookup — chat turns (history) are never cached.
        cache_key = None
        if not history and self.cache_ttl > 0:
            cache_key = self._cache_key(prompt, context, max_tokens, temperature, use_local_first)
            cached = self._cache_get(cache_key)
            if cached is not None:
                self.stats["cache_hits"] += 1
                return cached

        def _finish(text: str, source: str) -> Tuple[str, str]:
            if cache_key is not None:
                self._cache_put(cache_key, text, source)
            return text, source

        cloud_order = [
            ("openai", self._try_openai),
            ("anthropic", self._try_anthropic),
            ("groq", self._try_groq),
            ("gemini", self._try_gemini),
        ]

        if use_local_first and self.ollama_enabled:
            # Privacy / local-first mode: Ollama before cloud providers.
            # AI never leaves your network unless Ollama is unavailable.
            response = self._try_ollama(prompt, context, history, max_tokens, temperature)
            if response:
                self.stats["ollama_requests"] += 1
                self._record_success("ollama")
                return _finish(response, "ollama")
            else:
                self.stats["ollama_failures"] += 1

        for name, attempt in cloud_order:
            if not self._provider_configured(name):
                continue
            response = attempt(prompt, context, history, max_tokens, temperature)
            if response:
                self.stats[f"{name}_requests"] += 1
                self._record_success(name)
                return _finish(response, name)
            else:
                self.stats[f"{name}_failures"] += 1

        # Try Ollama as last resort in default (non-privacy) mode
        if not use_local_first and self.ollama_enabled:
            response = self._try_ollama(prompt, context, history, max_tokens, temperature)
            if response:
                self.stats["ollama_requests"] += 1
                self._record_success("ollama")
                return _finish(response, "ollama")
            else:
                self.stats["ollama_failures"] += 1

        # Final fallback: rule-based (always works). Never cached so a
        # transient outage cannot pin template text for the full TTL.
        response = self._rule_based_response(prompt)
        self.stats["rule_requests"] += 1
        return response, "rules"

    def _build_messages(self, prompt: str, context: str,
                        history: Optional[List[Dict]]) -> List[Dict]:
        """Build the messages list for chat-style APIs (OpenAI / Groq)."""
        messages = []
        if context:
            messages.append({"role": "system", "content": context})
        if history:
            for turn in history:
                role = turn.get("role", "user")
                content = turn.get("content", "")
                if role in ("user", "assistant") and content:
                    messages.append({"role": role, "content": content})
        messages.append({"role": "user", "content": prompt})
        return messages

    def _build_ollama_prompt(self, prompt: str, context: str,
                             history: Optional[List[Dict]]) -> str:
        """Build a single-string prompt for Ollama (non-chat API)."""
        parts = []
        if context:
            parts.append(context)
        if history:
            for turn in history:
                role = turn.get("role", "user")
                content = turn.get("content", "")
                if content:
                    label = "User" if role == "user" else "Assistant"
                    parts.append(f"{label}: {content}")
        parts.append(f"User: {prompt}")
        parts.append("Assistant:")
        return "\n\n".join(parts)

    def _try_openai(self, prompt: str, context: str, history: Optional[List[Dict]],
                    max_tokens: int, temperature: float) -> Optional[str]:
        """Try OpenAI cloud API (paid, business tier)."""
        try:
            if self._openai_client is None:
                from openai import OpenAI
                self._openai_client = OpenAI(api_key=self.openai_api_key)

            messages = self._build_messages(prompt, context, history)
            completion = self._openai_client.chat.completions.create(
                model=self.openai_model,
                messages=messages,
                max_tokens=max_tokens,
                temperature=temperature,
                timeout=8,
            )
            response = completion.choices[0].message.content
            return response.strip() if response else None

        except ImportError:
            self._note_error("openai", "openai library not installed (pip install openai)")
            return None
        except Exception as e:
            self._note_error("openai", e)
            return None

    def _try_anthropic(self, prompt: str, context: str, history: Optional[List[Dict]],
                       max_tokens: int, temperature: float) -> Optional[str]:
        """Try Anthropic Claude cloud API (paid).

        Context is passed via the top-level `system` parameter — the Messages
        API does not accept a system-role entry in `messages`.
        """
        try:
            if self._anthropic_client is None:
                import anthropic
                # max_retries=0: a failing provider should fall through to the
                # next tier fast instead of retrying internally.
                self._anthropic_client = anthropic.Anthropic(
                    api_key=self.anthropic_api_key, timeout=8.0, max_retries=0,
                )

            messages = self._build_messages(prompt, "", history)
            kwargs = {
                "model": self.anthropic_model,
                "max_tokens": max_tokens,
                "temperature": temperature,
                "messages": messages,
            }
            if context:
                kwargs["system"] = context
            response = self._anthropic_client.messages.create(**kwargs)
            text = next((b.text for b in response.content if getattr(b, "type", "") == "text"), None)
            return text.strip() if text else None

        except ImportError:
            self._note_error("anthropic", "anthropic library not installed (pip install anthropic)")
            return None
        except Exception as e:
            self._note_error("anthropic", e)
            return None

    def _try_gemini(self, prompt: str, context: str, history: Optional[List[Dict]],
                    max_tokens: int, temperature: float) -> Optional[str]:
        """Try Google Gemini cloud API (free tier — roughly 250 requests/day).

        Plain REST via `requests` so no extra dependency ships to the Pi. The
        key travels in the x-goog-api-key header, never in the URL, so it
        cannot leak into logs.
        """
        try:
            contents = []
            for turn in (history or []):
                content = turn.get("content", "")
                if not content:
                    continue
                role = "user" if turn.get("role", "user") == "user" else "model"
                contents.append({"role": role, "parts": [{"text": content}]})
            contents.append({"role": "user", "parts": [{"text": prompt}]})

            body = {
                "contents": contents,
                "generationConfig": {
                    "maxOutputTokens": max_tokens,
                    "temperature": temperature,
                },
            }
            if context:
                body["system_instruction"] = {"parts": [{"text": context}]}

            response = requests.post(
                f"https://generativelanguage.googleapis.com/v1beta/models/{self.gemini_model}:generateContent",
                headers={
                    "x-goog-api-key": self.gemini_api_key,
                    "Content-Type": "application/json",
                },
                json=body,
                timeout=8,
            )
            if response.status_code != 200:
                self._note_error("gemini", f"Gemini returned status {response.status_code}")
                return None

            candidates = response.json().get("candidates") or []
            if not candidates:
                # Safety block or empty result — fall through quietly.
                logger.debug("Gemini returned no candidates")
                return None
            parts = (candidates[0].get("content") or {}).get("parts") or []
            text = "".join(p.get("text", "") for p in parts).strip()
            return text if text else None

        except requests.exceptions.Timeout:
            self._note_error("gemini", "Gemini request timed out (>8s)")
            return None
        except Exception as e:
            self._note_error("gemini", e)
            return None

    def _try_groq(self, prompt: str, context: str, history: Optional[List[Dict]],
                  max_tokens: int, temperature: float) -> Optional[str]:
        """
        Try Groq cloud API.

        Free tier limits: 14,400 requests/day (~1 request per 6 seconds)
        Average response time: 2-3 seconds
        """
        try:
            if self._groq_client is None:
                from groq import Groq
                self._groq_client = Groq(api_key=self.groq_api_key)

            messages = self._build_messages(prompt, context, history)
            completion = self._groq_client.chat.completions.create(
                model=self.groq_model,
                messages=messages,
                max_tokens=max_tokens,
                temperature=temperature,
                timeout=5,
            )
            response = completion.choices[0].message.content
            return response.strip() if response else None

        except ImportError:
            self._note_error("groq", "groq library not installed (pip install groq)")
            return None
        except Exception as e:
            self._note_error("groq", e)
            return None

    def _try_ollama(self, prompt: str, context: str, history: Optional[List[Dict]],
                    max_tokens: int, temperature: float) -> Optional[str]:
        """
        Try local Ollama server.

        Model: gemma2:2b (~1.6GB Q4, optimized for Pi 5)
        Average response time: 4-8 seconds on Pi 5
        RAM usage: ~1.6GB during inference
        """
        try:
            full_prompt = self._build_ollama_prompt(prompt, context, history)
            response = requests.post(
                self.ollama_url,
                json={
                    'model': self.ollama_model,
                    'prompt': full_prompt,
                    'stream': False,
                    'options': {
                        'temperature': temperature,
                        'num_predict': max_tokens,
                    }
                },
                timeout=self.ollama_timeout,
            )
            if response.status_code == 200:
                answer = response.json().get('response', '').strip()
                return answer if answer else None
            else:
                self._note_error("ollama", f"Ollama returned status {response.status_code}")
                return None

        except requests.exceptions.ConnectionError:
            # Expected on installs without Ollama — health is recorded but the
            # WARNING is suppressed to keep LAN-only Pi logs quiet.
            self._note_error("ollama", "Ollama not reachable (is it running? `ollama serve`)", warn=False)
            return None
        except requests.exceptions.Timeout:
            self._note_error("ollama", f"Ollama request timed out (>{self.ollama_timeout}s)")
            return None
        except Exception as e:
            self._note_error("ollama", e)
            return None

    def _rule_based_response(self, prompt: str) -> str:
        """
        Rule-based offline fallback.  Returns short, plain-English answers that
        point to the right panel — no technical bullet dumps.  Includes an
        off-topic guard so out-of-scope questions are declined consistently with
        the LLM scope prompt.
        """
        prompt_lower = prompt.lower()

        if any(word in prompt_lower for word in ['device', 'connected', 'how many', 'where', 'find', 'look']):
            return ("Head to the **Devices** panel to see everything on your network. "
                    "Tap any device to review its traffic, trust level, and security details.")

        elif any(word in prompt_lower for word in ['alert', 'warning', 'detected', 'anomaly', 'threat']):
            return ("Each alert in the **Alerts** panel includes a plain-English explanation "
                    "and suggested next steps — click any alert to see the full detail.")

        elif any(word in prompt_lower for word in ['safe', 'secure', 'protected', 'risk', 'status']):
            return ("Open the **Alerts** panel to see your current security status — "
                    "any active threats will be listed there with plain-English explanations.")

        elif any(word in prompt_lower for word in ['lockdown', 'block', 'firewall', 'emergency']):
            return ("You can block a device or trigger Lockdown Mode from **Settings → Firewall**. "
                    "Mark your trusted devices first so you don't lose access.")

        elif any(word in prompt_lower for word in ['bandwidth', 'traffic', 'usage', 'speed', 'data']):
            return ("Check the **Analytics** panel for bandwidth usage, traffic patterns, "
                    "and historical data across your devices.")

        elif any(word in prompt_lower for word in ['alert', 'notification', 'email', 'notify']):
            return ("You can configure alert notifications in **Settings → Alerts** — "
                    "set thresholds for severity levels and choose how you're notified.")

        elif any(word in prompt_lower for word in ['hello', 'hi', 'hey', 'help']):
            return ("Hi! Ask me anything about your network — devices, alerts, security status, "
                    "or how to use any feature in the dashboard.")

        else:
            return ("I'm not sure about that offline, but you can check the relevant "
                    "panel in the dashboard, or try rephrasing and I'll do my best to help.")

    def get_stats(self) -> dict:
        total = self.stats["total_requests"]
        if total == 0:
            return {
                "total_requests": 0,
                "groq_available": self.groq_available,
                "openai_available": self.openai_available,
                "anthropic_available": self.anthropic_available,
                "gemini_available": self.gemini_available,
                "ollama_enabled": self.ollama_enabled,
                "cache_hits": self.stats.get("cache_hits", 0)
            }

        return {
            "total_requests": total,
            "openai_percent": round(self.stats["openai_requests"] / total * 100, 1),
            "anthropic_percent": round(self.stats["anthropic_requests"] / total * 100, 1),
            "groq_percent": round(self.stats["groq_requests"] / total * 100, 1),
            "gemini_percent": round(self.stats["gemini_requests"] / total * 100, 1),
            "ollama_percent": round(self.stats["ollama_requests"] / total * 100, 1),
            "rules_percent": round(self.stats["rule_requests"] / total * 100, 1),
            "groq_success_rate": round(
                (self.stats["groq_requests"] / (self.stats["groq_requests"] + self.stats["groq_failures"]) * 100)
                if (self.stats["groq_requests"] + self.stats["groq_failures"]) > 0 else 0, 1
            ),
            "ollama_success_rate": round(
                (self.stats["ollama_requests"] / (self.stats["ollama_requests"] + self.stats["ollama_failures"]) * 100)
                if (self.stats["ollama_requests"] + self.stats["ollama_failures"]) > 0 else 0, 1
            ),
            "groq_available": self.groq_available,
            "openai_available": self.openai_available,
            "anthropic_available": self.anthropic_available,
            "gemini_available": self.gemini_available,
            "ollama_enabled": self.ollama_enabled,
            "cache_hits": self.stats.get("cache_hits", 0)
        }

    def _ollama_reachable(self) -> bool:
        """Cached (~30 s) probe of the local Ollama server. Reports whether it is
        ACTUALLY answering — not merely enabled in config — so the status never claims
        'Local Ready' while the model is still provisioning on first boot."""
        if not self.ollama_enabled:
            return False
        now = time.time()
        cached = getattr(self, "_ollama_probe_cache", None)
        if cached and now - cached[0] < 30:
            return cached[1]
        ok = False
        try:
            import requests
            ok = requests.get("http://localhost:11434/api/tags", timeout=1).status_code == 200
        except Exception:
            ok = False
        self._ollama_probe_cache = (now, ok)
        return ok

    def get_status_message(self) -> str:
        stats = self.get_stats()

        if stats["total_requests"] == 0:
            if self.openai_available:
                return "AI: OpenAI Ready"
            elif self.anthropic_available:
                return "AI: Claude Ready"
            elif self.groq_available:
                return "AI: Groq Ready"
            elif self.gemini_available:
                return "AI: Gemini Ready"
            elif self.ollama_enabled:
                # Honest: only "Ready" once Ollama actually answers; otherwise it's still
                # being installed/pulled in the background on first online boot.
                return "AI: Local Ready" if self._ollama_reachable() else "AI: Local AI starting…"
            else:
                return "AI: Rules Ready"

        if stats.get("openai_percent", 0) > 50:
            primary = "OpenAI"
        elif stats.get("anthropic_percent", 0) > 50:
            primary = "Claude"
        elif stats.get("groq_percent", 0) > 50:
            primary = "Groq"
        elif stats.get("gemini_percent", 0) > 50:
            primary = "Gemini"
        elif stats.get("ollama_percent", 0) > 50:
            primary = "Local"
        else:
            primary = "Hybrid"

        return f"AI: {primary} Active"

    def reset_stats(self):
        self.stats = self._fresh_stats()


# Convenience function for simple usage
def get_ai_response(prompt: str,
                   context: str = "",
                   ollama_url: str = "http://localhost:11434/api/generate",
                   ollama_model: str = "gemma2:2b") -> str:
    assistant = HybridAIAssistant(
        ollama_url=ollama_url,
        ollama_model=ollama_model
    )
    response, _ = assistant.get_response(prompt, context)
    return response
