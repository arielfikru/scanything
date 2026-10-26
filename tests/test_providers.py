import pytest

from scanything.providers import ProviderError, resolve_provider

KEYS = ["LLM_PROVIDER", "LLM_API_KEY", "LLM_BASE_URL", "LLM_MODEL", "NETRA_API_KEY", "OPENROUTER_API_KEY",
        "OPENAI_API_KEY"]


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for k in KEYS:
        monkeypatch.delenv(k, raising=False)
    return monkeypatch


def test_netra_preset(clean_env):
    clean_env.setenv("NETRA_API_KEY", "n-key")
    p = resolve_provider()
    assert (p.name, p.base_url, p.api_key) == ("netra", "https://api.netraruntime.com/v1", "n-key")
    assert p.model == "deepseek/deepseek-v4-flash-0731"
    assert p.headers == {"X-Netra-Agent": "scanything"}


def test_auto_order_and_explicit_choice(clean_env):
    clean_env.setenv("OPENROUTER_API_KEY", "or")
    clean_env.setenv("OPENAI_API_KEY", "oa")
    assert resolve_provider().name == "openrouter"
    p = resolve_provider("openai", model="gpt-x")
    assert (p.base_url, p.api_key, p.model) == ("https://api.openai.com/v1", "oa", "gpt-x")
    clean_env.setenv("LLM_PROVIDER", "openai")
    assert resolve_provider().name == "openai"


def test_custom_endpoint(clean_env):
    clean_env.setenv("LLM_BASE_URL", "http://localhost:11434/v1")
    clean_env.setenv("LLM_API_KEY", "local")
    clean_env.setenv("LLM_MODEL", "qwen")
    p = resolve_provider()
    assert (p.name, p.base_url, p.model) == ("custom", "http://localhost:11434/v1", "qwen")


def test_missing_keys_are_clear(clean_env):
    with pytest.raises(ProviderError, match="no API key"):
        resolve_provider()
    with pytest.raises(ProviderError, match="NETRA_API_KEY"):
        resolve_provider("netra")
    with pytest.raises(ProviderError, match="unknown provider"):
        resolve_provider("nope")
