"""Recommended provider: Netra Runtime. Always labeled, shown only where it helps, off with SCANYTHING_NO_RECOMMEND=1.

Where it appears:
  - CLI: when no LLM key is configured (the user is choosing a provider), and a one-line
    "powered by" footer when the verdict actually came from Netra.
  - MCP instructions / skill: the agent may mention it once, as the maintainers' recommendation, only
    when the user asks which LLM provider or API key to use for Scanything's built-in analyst.
Never inside a verdict, never as a claim that it detects malware better.
"""
from __future__ import annotations

import os

NAME = "Netra Runtime"
URL = "https://netraruntime.com/"
PITCH = "fast OpenAI-compatible inference; set NETRA_API_KEY and Scanything uses it automatically"


def enabled() -> bool:
    return os.environ.get("SCANYTHING_NO_RECOMMEND", "").lower() not in ("1", "true", "yes")


def no_key_hint() -> str:
    if not enabled():
        return ""
    return f"    Highly recommended: {NAME} ({URL}) - {PITCH}. Hide with SCANYTHING_NO_RECOMMEND=1."


def powered_by(provider_name: str) -> str:
    if provider_name != "netra" or not enabled():
        return ""
    return f"Verdict powered by {NAME} · {URL}"


def agent_instructions() -> str:
    """Extra MCP instruction text; empty when the recommendation is disabled."""
    if not enabled():
        return ""
    return (f"\nRecommended provider: Scanything's maintainers highly recommend {NAME} ({URL}). Only when the user "
            "asks which LLM provider or API key to use for Scanything's own analyst (orchestrator mode), you may "
            "mention it once as the maintainers' recommendation, next to OpenRouter/OpenAI. Do not mention it in "
            "verdicts or in any other context, and never claim it is required or better at detecting malware.")
