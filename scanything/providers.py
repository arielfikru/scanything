"""LLM provider presets. Every provider speaks the OpenAI Chat Completions format."""
from __future__ import annotations

import os
from dataclasses import dataclass, field

# name -> (base URL, API key env vars in priority order, default model, extra headers)
PRESETS = {
    "netra": ("https://api.netraruntime.com/v1", ["NETRA_API_KEY"], "deepseek/deepseek-v4-flash-0731",
              {"X-Netra-Agent": "scanything"}),
    "openrouter": ("https://openrouter.ai/api/v1", ["OPENROUTER_API_KEY"], "anthropic/claude-haiku-5.5",
                   {"HTTP-Referer": "https://github.com/arielfikru/scanything", "X-Title": "Scanything"}),
    "openai": ("https://api.openai.com/v1", ["OPENAI_API_KEY"], "gpt-6-luna", {}),
    "custom": (None, ["LLM_API_KEY"], None, {}),
}
AUTO_ORDER = ["netra", "openrouter", "openai"]


@dataclass
class Provider:
    name: str
    base_url: str
    api_key: str
    model: str
    headers: dict = field(default_factory=dict)


class ProviderError(Exception):
    pass


def resolve_provider(name: str | None = None, model: str | None = None, base_url: str | None = None) -> Provider:
    """Pick a provider from --provider / LLM_PROVIDER, else the first one with a key set.

    LLM_API_KEY / LLM_BASE_URL / LLM_MODEL override the preset values, so any other
    OpenAI-compatible server works with LLM_PROVIDER=custom.
    """
    name = (name or os.environ.get("LLM_PROVIDER") or "").lower() or None
    if name is None:
        if os.environ.get("LLM_BASE_URL") and os.environ.get("LLM_API_KEY"):
            name = "custom"
        else:
            name = next((p for p in AUTO_ORDER if any(os.environ.get(k) for k in PRESETS[p][1])), None)
        if name is None:
            raise ProviderError("no API key found: set NETRA_API_KEY, OPENROUTER_API_KEY, OPENAI_API_KEY "
                                "or LLM_BASE_URL + LLM_API_KEY (see .env.example)")
    if name not in PRESETS:
        raise ProviderError(f"unknown provider {name!r}; choose one of {', '.join(PRESETS)}")

    preset_url, key_vars, preset_model, headers = PRESETS[name]
    key = next((os.environ[k] for k in key_vars if os.environ.get(k)), None) or os.environ.get("LLM_API_KEY")
    url = base_url or os.environ.get("LLM_BASE_URL") or preset_url
    model = model or os.environ.get("LLM_MODEL") or preset_model
    if not key:
        raise ProviderError(f"provider {name!r} needs {key_vars[0]} (or LLM_API_KEY)")
    if not url:
        raise ProviderError("provider 'custom' needs LLM_BASE_URL")
    if not model:
        raise ProviderError("provider 'custom' needs LLM_MODEL or --model")
    return Provider(name, url, key, model, dict(headers))
