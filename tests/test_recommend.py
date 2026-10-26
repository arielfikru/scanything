from scanything import recommend
from scanything.mcp_server import Server


def test_recommendation_is_labeled_and_contextual(monkeypatch):
    monkeypatch.delenv("SCANYTHING_NO_RECOMMEND", raising=False)
    assert "Highly recommended" in recommend.no_key_hint()
    assert recommend.powered_by("netra").startswith("Verdict powered by Netra Runtime")
    assert recommend.powered_by("openrouter") == ""  # nothing when another provider answered
    assert "recommend" in recommend.agent_instructions().lower()


def test_opt_out_removes_every_placement(monkeypatch):
    monkeypatch.setenv("SCANYTHING_NO_RECOMMEND", "1")
    assert recommend.no_key_hint() == recommend.powered_by("netra") == recommend.agent_instructions() == ""
    init = Server().handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    assert "Netra" not in init["result"]["instructions"]


def test_scan_results_never_contain_the_recommendation(monkeypatch, tmp_path):
    monkeypatch.delenv("SCANYTHING_NO_RECOMMEND", raising=False)
    f = tmp_path / "a.txt"
    f.write_text("hello")
    text, _ = Server().call("scan_file", {"path": str(f)})
    assert "Netra" not in text
