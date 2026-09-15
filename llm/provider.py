"""LLM provider abstraction layer.

Providers:
  * heuristic  - offline, no API key. Deterministic rule-based planning/analysis
                 so the platform is fully functional with zero configuration.
  * openai     - uses the `openai` SDK if installed and a key is configured.
  * anthropic  - uses the `anthropic` SDK if installed and a key is configured.

Rules enforced here:
  - API keys are never hardcoded and never logged.
  - The LLM is advisory only; it can never execute shell commands or bypass the
    safety layer. It only returns text used to *rank/suggest* tests.
"""
from __future__ import annotations

from typing import List, Optional

from config import CONFIG, get_logger

log = get_logger(__name__)


class LLMProvider:
    """Base interface."""

    name = "base"

    def complete(self, prompt: str, system: str = "", max_tokens: int = 512) -> str:
        raise NotImplementedError

    def available(self) -> bool:
        return True


class HeuristicProvider(LLMProvider):
    """Offline provider: no network, no keys, deterministic.

    Provides just enough 'reasoning' to prioritise test categories based on
    discovered capabilities. This keeps the whole platform runnable and
    reproducible without any external dependency.
    """

    name = "heuristic"

    PRIORITY = [
        "prompt_injection",
        "instruction_disclosure",
        "tool_security",
        "excessive_agency",
        "authz",
        "memory_security",
        "rag_security",
        "mcp_security",
        "data_exposure",
        "guardrails",
    ]

    def complete(self, prompt: str, system: str = "", max_tokens: int = 512) -> str:
        # Return a compact, deterministic "plan" ordering. The orchestrator only
        # consumes this as a hint; real detection is signal-based, not LLM-based.
        caps = [c for c in self.PRIORITY if c in prompt]
        ordered = caps or self.PRIORITY
        return "PLAN:" + ",".join(ordered)


class OpenAIProvider(LLMProvider):
    name = "openai"

    def __init__(self) -> None:
        self._client = None
        self._model = CONFIG.llm_model or "gpt-4o-mini"

    def available(self) -> bool:
        return bool(CONFIG.get_secret("OPENAI_API_KEY"))

    def _client_or_none(self):
        if self._client is not None:
            return self._client
        try:
            from openai import OpenAI  # lazy import

            key = CONFIG.get_secret("OPENAI_API_KEY")
            if not key:
                return None
            self._client = OpenAI(api_key=key)
            return self._client
        except Exception as exc:  # pragma: no cover
            log.warning("OpenAI client unavailable: %s", type(exc).__name__)
            return None

    def complete(self, prompt: str, system: str = "", max_tokens: int = 512) -> str:
        client = self._client_or_none()
        if client is None:
            return HeuristicProvider().complete(prompt, system, max_tokens)
        try:
            resp = client.chat.completions.create(
                model=self._model,
                messages=[
                    {"role": "system", "content": system or "You are a security test planner."},
                    {"role": "user", "content": prompt},
                ],
                max_tokens=max_tokens,
                temperature=0.2,
            )
            return resp.choices[0].message.content or ""
        except Exception as exc:  # pragma: no cover
            log.warning("OpenAI completion failed (%s); using heuristic", type(exc).__name__)
            return HeuristicProvider().complete(prompt, system, max_tokens)


class AnthropicProvider(LLMProvider):
    name = "anthropic"

    def __init__(self) -> None:
        self._client = None
        self._model = CONFIG.llm_model or "claude-sonnet-5"

    def available(self) -> bool:
        return bool(CONFIG.get_secret("ANTHROPIC_API_KEY"))

    def _client_or_none(self):
        if self._client is not None:
            return self._client
        try:
            import anthropic  # lazy import

            key = CONFIG.get_secret("ANTHROPIC_API_KEY")
            if not key:
                return None
            self._client = anthropic.Anthropic(api_key=key)
            return self._client
        except Exception as exc:  # pragma: no cover
            log.warning("Anthropic client unavailable: %s", type(exc).__name__)
            return None

    def complete(self, prompt: str, system: str = "", max_tokens: int = 512) -> str:
        client = self._client_or_none()
        if client is None:
            return HeuristicProvider().complete(prompt, system, max_tokens)
        try:
            resp = client.messages.create(
                model=self._model,
                max_tokens=max_tokens,
                system=system or "You are a security test planner.",
                messages=[{"role": "user", "content": prompt}],
            )
            parts = [b.text for b in resp.content if getattr(b, "type", "") == "text"]
            return "".join(parts)
        except Exception as exc:  # pragma: no cover
            log.warning("Anthropic completion failed (%s); using heuristic", type(exc).__name__)
            return HeuristicProvider().complete(prompt, system, max_tokens)


def get_provider(name: Optional[str] = None) -> LLMProvider:
    name = (name or CONFIG.llm_provider or "heuristic").lower()
    if name == "openai":
        p = OpenAIProvider()
        if p.available():
            return p
        log.info("OpenAI key not configured; falling back to heuristic provider")
        return HeuristicProvider()
    if name == "anthropic":
        p = AnthropicProvider()
        if p.available():
            return p
        log.info("Anthropic key not configured; falling back to heuristic provider")
        return HeuristicProvider()
    return HeuristicProvider()
