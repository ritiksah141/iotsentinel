#!/usr/bin/env python3
"""
Hybrid AI Assistant for IoTSentinel

3-tier intelligent fallback system:
1. Groq API (cloud, free tier - 14,400 requests/day)
2. Ollama phi3.5:mini (local Pi server)
3. Rule-based responses (offline fallback)

Optimized for Raspberry Pi 4GB RAM.
"""

import os
import logging
import requests
from typing import Optional, Tuple
from collections import defaultdict

logger = logging.getLogger(__name__)


class HybridAIAssistant:
    """
    Smart AI assistant with automatic fallback and source tracking.

    Prioritizes speed and availability:
    - Cloud API for best quality (2-3s responses)
    - Local LLM when offline (5-10s responses)
    - Rules when both fail (instant responses)
    """

    def __init__(self,
                 ollama_url: str = "http://localhost:11434/api/generate",
                 ollama_model: str = "phi3.5:mini",
                 groq_api_key: Optional[str] = None,
                 ollama_enabled: bool = True):
        """
        Initialize hybrid AI assistant.

        Args:
            ollama_url: Ollama API endpoint (default: localhost)
            ollama_model: Model to use (default: phi3.5:mini for Pi)
            groq_api_key: Groq API key (optional, from env if not provided)
            ollama_enabled: Whether to use Ollama (disable for pure cloud/rules)
        """
        self.ollama_url = ollama_url
        self.ollama_model = ollama_model
        self.ollama_enabled = ollama_enabled
        self.groq_api_key = groq_api_key or os.getenv("GROQ_API_KEY")

        # Groq client (lazy load)
        self._groq_client = None

        # Usage statistics
        self.stats = {
            "total_requests": 0,
            "groq_requests": 0,
            "ollama_requests": 0,
            "rule_requests": 0,
            "groq_failures": 0,
            "ollama_failures": 0
        }

    @property
    def groq_available(self) -> bool:
        """Check if Groq API is available."""
        return self.groq_api_key is not None

    def get_response(self,
                     prompt: str,
                     context: str = "",
                     max_tokens: int = 300,
                     temperature: float = 0.7) -> Tuple[str, str]:
        """
        Get AI response with automatic fallback.

        Args:
            prompt: User's question/message
            context: System context (network status, alerts, etc.)
            max_tokens: Maximum response length
            temperature: Creativity (0.0 = deterministic, 1.0 = creative)

        Returns:
            Tuple of (response_text, source_name)
            source_name: 'groq', 'ollama', or 'rules'
        """
        self.stats["total_requests"] += 1

        # 1. Try Groq first (fastest, best quality)
        if self.groq_available:
            response = self._try_groq(prompt, context, max_tokens, temperature)
            if response:
                self.stats["groq_requests"] += 1
                return response, "groq"
            else:
                self.stats["groq_failures"] += 1

        # 2. Fall back to Ollama (slower but local)
        if self.ollama_enabled:
            response = self._try_ollama(prompt, context, max_tokens, temperature)
            if response:
                self.stats["ollama_requests"] += 1
                return response, "ollama"
            else:
                self.stats["ollama_failures"] += 1

        # 3. Final fallback: rule-based (always works)
        response = self._rule_based_response(prompt)
        self.stats["rule_requests"] += 1
        return response, "rules"

    def _try_groq(self, prompt: str, context: str, max_tokens: int, temperature: float) -> Optional[str]:
        """
        Try Groq cloud API.

        Free tier limits: 14,400 requests/day (~1 request per 6 seconds)
        Average response time: 2-3 seconds
        """
        try:
            # Lazy load Groq client
            if self._groq_client is None:
                from groq import Groq
                self._groq_client = Groq(api_key=self.groq_api_key)

            # Build messages
            messages = []
            if context:
                messages.append({"role": "system", "content": context})
            messages.append({"role": "user", "content": prompt})

            # Call API with timeout
            completion = self._groq_client.chat.completions.create(
                model="llama3-8b-8192",  # Fast, high quality, free
                messages=messages,
                max_tokens=max_tokens,
                temperature=temperature,
                timeout=5  # Fail fast if slow
            )

            response = completion.choices[0].message.content
            return response.strip() if response else None

        except ImportError:
            logger.debug("Groq library not installed. Install with: pip install groq")
            return None
        except Exception as e:
            logger.debug(f"Groq API failed: {e}")
            return None

    def _try_ollama(self, prompt: str, context: str, max_tokens: int, temperature: float) -> Optional[str]:
        """
        Try local Ollama server.

        Model: phi3.5:mini (2.7GB, optimized for Pi)
        Average response time: 5-10 seconds on Pi
        RAM usage: ~1.5GB during inference
        """
        try:
            # Build full prompt
            full_prompt = f"{context}\n\nUser: {prompt}\n\nAssistant:" if context else f"User: {prompt}\n\nAssistant:"

            # Call Ollama API
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
                timeout=15  # Pi can be slow, allow 15s
            )

            if response.status_code == 200:
                result = response.json()
                answer = result.get('response', '').strip()
                return answer if answer else None
            else:
                logger.debug(f"Ollama returned status {response.status_code}")
                return None

        except requests.exceptions.ConnectionError:
            logger.debug("Ollama not available. Is it running? (ollama serve)")
            return None
        except requests.exceptions.Timeout:
            logger.debug("Ollama request timed out (>15s)")
            return None
        except Exception as e:
            logger.debug(f"Ollama request failed: {e}")
            return None

    def _rule_based_response(self, prompt: str) -> str:
        """
        Rule-based fallback responses.

        Always works, instant responses.
        Covers common IoT security questions.
        """
        prompt_lower = prompt.lower()

        # Security status queries
        if any(word in prompt_lower for word in ['safe', 'secure', 'protected', 'risk', 'status']):
            return ("Your network security status depends on active alerts. "
                   "Check the Alerts panel for any issues requiring attention. "
                   "IoTSentinel uses adaptive baselines to detect anomalies in real-time.")

        # Device queries
        elif any(word in prompt_lower for word in ['device', 'connected', 'how many']):
            return ("View all connected devices in the Devices panel. "
                   "Click any device for detailed information, traffic statistics, and trust settings. "
                   "Untrusted devices are monitored more closely for suspicious behavior.")

        # Alert explanation
        elif any(word in prompt_lower for word in ['alert', 'warning', 'detected', 'anomaly']):
            return ("Alerts indicate unusual network behavior detected by machine learning models. "
                   "Each alert shows:\n"
                   "• Severity level (Critical/High/Medium/Low)\n"
                   "• Plain English explanation\n"
                   "• Recommended actions\n"
                   "Click any alert for detailed analysis and remediation steps.")

        # How it works
        elif any(word in prompt_lower for word in ['how', 'works', 'explain', 'what is']):
            return ("IoTSentinel monitors your network using:\n"
                   "• Traffic analysis (patterns, protocols, destinations)\n"
                   "• Machine learning (adaptive anomaly detection)\n"
                   "• Threat intelligence (known malicious IPs)\n"
                   "• Device fingerprinting (manufacturer, type, behavior)\n\n"
                   "It learns normal patterns and alerts on deviations.")

        # Lockdown mode
        elif any(word in prompt_lower for word in ['lockdown', 'block', 'firewall', 'emergency']):
            return ("🔐 Lockdown Mode blocks all untrusted devices from network access. "
                   "Enable it in Settings → Firewall Control. "
                   "⚠️ Important: Mark critical devices as 'Trusted' first to avoid losing access!")

        # Predicted threats
        elif any(word in prompt_lower for word in ['predict', 'forecast', 'future', 'next', 'coming']):
            return ("IoTSentinel predicts threats by:\n"
                   "• Learning traffic baselines per device\n"
                   "• Detecting attack sequences (port scan → brute force)\n"
                   "• Forecasting bandwidth anomalies\n"
                   "• Identifying device failure risk\n\n"
                   "Check the 'Predicted Threats' widget for upcoming risks.")

        # Privacy
        elif any(word in prompt_lower for word in ['privacy', 'data', 'tracking', 'spy']):
            return ("Privacy features:\n"
                   "• Cloud upload monitoring (what's being sent where)\n"
                   "• Tracker detection (advertising, analytics)\n"
                   "• Data flow visualization (inbound vs outbound)\n"
                   "• Smart home ecosystem mapping\n\n"
                   "View your Privacy Score in the dashboard.")

        # Smart home
        elif any(word in prompt_lower for word in ['smart home', 'alexa', 'google home', 'hub']):
            return ("Smart Home features:\n"
                   "• Hub detection (Alexa, Google, HomeKit)\n"
                   "• Ecosystem grouping (devices by platform)\n"
                   "• Room organization\n"
                   "• Automation tracking\n\n"
                   "Helps you understand and secure your IoT ecosystem.")

        # Firmware
        elif any(word in prompt_lower for word in ['firmware', 'update', 'eol', 'end of life']):
            return ("Firmware monitoring:\n"
                   "• Update status tracking\n"
                   "• EOL device detection\n"
                   "• Security patch recommendations\n"
                   "• Replacement suggestions\n\n"
                   "Outdated firmware is a major security risk - keep devices updated!")

        # Greeting
        elif any(word in prompt_lower for word in ['hello', 'hi', 'hey', 'help']):
            return ("👋 Hello! I'm your IoTSentinel AI Assistant. I can help with:\n\n"
                   "• Network security status\n"
                   "• Device information\n"
                   "• Alert explanations\n"
                   "• Threat predictions\n"
                   "• Privacy concerns\n"
                   "• Smart home setup\n"
                   "• Firmware updates\n\n"
                   "What would you like to know?")

        # Default
        else:
            return ("I can help with network security questions. Try asking about:\n\n"
                   "• 'Is my network safe?'\n"
                   "• 'What devices are connected?'\n"
                   "• 'Explain this alert'\n"
                   "• 'How does IoTSentinel work?'\n"
                   "• 'What threats are predicted?'\n"
                   "• 'Show my privacy score'\n\n"
                   "Or ask anything about your IoT security!")

    def get_stats(self) -> dict:
        """
        Get usage statistics.

        Returns:
            Dict with request counts and percentages
        """
        total = self.stats["total_requests"]
        if total == 0:
            return {
                "total_requests": 0,
                "groq_available": self.groq_available,
                "ollama_enabled": self.ollama_enabled
            }

        return {
            "total_requests": total,
            "groq_percent": round(self.stats["groq_requests"] / total * 100, 1),
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
            "ollama_enabled": self.ollama_enabled
        }

    def get_status_message(self) -> str:
        """
        Get human-readable status message.

        Returns:
            Status string (e.g., "AI: Cloud ✅ (89% Groq, 8% Local, 3% Rules)")
        """
        stats = self.get_stats()

        if stats["total_requests"] == 0:
            if self.groq_available:
                return "AI: Cloud ✅ Ready"
            elif self.ollama_enabled:
                return "AI: Local ✅ Ready"
            else:
                return "AI: Rules ✅ Ready"

        # Determine primary source
        if stats["groq_percent"] > 50:
            primary = "Cloud"
        elif stats["ollama_percent"] > 50:
            primary = "Local"
        else:
            primary = "Hybrid"

        # Build detailed breakdown
        breakdown = f"{stats['groq_percent']}% Cloud, {stats['ollama_percent']}% Local, {stats['rules_percent']}% Rules"

        return f"AI: {primary} ✅ ({breakdown})"

    def reset_stats(self):
        """Reset usage statistics."""
        self.stats = {
            "total_requests": 0,
            "groq_requests": 0,
            "ollama_requests": 0,
            "rule_requests": 0,
            "groq_failures": 0,
            "ollama_failures": 0
        }


# Convenience function for simple usage
def get_ai_response(prompt: str,
                   context: str = "",
                   ollama_url: str = "http://localhost:11434/api/generate",
                   ollama_model: str = "phi3.5:mini") -> str:
    """
    Quick AI response without managing assistant instance.

    Args:
        prompt: User's question
        context: Optional system context
        ollama_url: Ollama server URL
        ollama_model: Model name

    Returns:
        AI response text (source info not included)
    """
    assistant = HybridAIAssistant(
        ollama_url=ollama_url,
        ollama_model=ollama_model
    )
    response, _ = assistant.get_response(prompt, context)
    return response
