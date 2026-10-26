"""Agent loop against a local mock OpenAI-compatible server (no network, no API key)."""
import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from scanything.agent import LLMClient, Orchestrator, ToolBox, resolve_path
from tests.conftest import scan_bytes
from tests.fixtures import make_pe, make_zip


class MockLLM(BaseHTTPRequestHandler):
    """Round 1: asks for a tool. Round 2: answers, quoting the tool result it got."""
    requests: list = []
    reject_tools = False

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        MockLLM.requests.append({"auth": self.headers.get("Authorization"), "body": body})
        if MockLLM.reject_tools and "tools" in body:
            return self._send(400, {"error": {"message": "This model does not support tools"}})
        last = body["messages"][-1]
        if "tools" in body and last["role"] == "user":
            msg = {"role": "assistant", "content": None, "tool_calls": [{
                "id": "call_1", "type": "function",
                "function": {"name": "search_strings", "arguments": json.dumps(
                    {"file_index": 1, "pattern": "vssadmin"})}}]}
        else:
            seen = last["content"] if last["role"] == "tool" else "no tools"
            msg = {"role": "assistant", "content": f"## Verdict: MALICIOUS (confidence 90%)\nevidence: {seen}"}
        self._send(200, {"choices": [{"message": msg}]})

    def _send(self, code, obj):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


@pytest.fixture
def server():
    MockLLM.requests, MockLLM.reject_tools = [], False
    srv = HTTPServer(("127.0.0.1", 0), MockLLM)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}/v1"
    srv.shutdown()


@pytest.fixture
def report():
    return scan_bytes("m.zip", make_zip({"a.exe": make_pe(strings=b"\x00vssadmin delete shadows /all\x00")}))


def make_orch(url, report, tools=True):
    scan = report["_scan"]
    return Orchestrator(LLMClient(url, "test-key", "mock-model", 0.2), ToolBox(report, scan.strings, None),
                        tools, "en", verbose=False)


def test_tool_loop_runs_tool_and_returns_answer(server, report):
    answer = make_orch(server, report).ask("verdict?")
    assert answer.startswith("## Verdict: MALICIOUS")
    assert "vssadmin delete shadows" in answer  # the tool result reached the model
    assert MockLLM.requests[0]["auth"] == "Bearer test-key"
    assert {t["function"]["name"] for t in MockLLM.requests[0]["body"]["tools"]} == {
        "get_report_section", "search_strings", "list_files"}  # no vt_lookup without a key


def test_falls_back_when_provider_rejects_tools(server, report):
    MockLLM.reject_tools = True
    orch = make_orch(server, report)
    assert "no tools" in orch.ask("verdict?")
    assert orch.use_tools is False


def test_resolve_path_and_errors(report):
    assert resolve_path(report, "files[1].type") == "pe"
    assert resolve_path(report, "files.1.name") == "a.exe"
    with pytest.raises(KeyError):
        resolve_path(report, "files[0].nope")
    tb = ToolBox(report, report["_scan"].strings, None)
    assert "error" in tb.run("search_strings", '{"file_index": 1, "pattern": "("}')
    assert "error" in tb.run("vt_lookup", '{"sha256": "x"}')


def test_cli_offline_writes_json(tmp_path):
    sample = tmp_path / "s.zip"
    sample.write_bytes(make_zip({"readme.txt": b"hi"}))
    out = tmp_path / "r.json"
    p = subprocess.run([sys.executable, "-m", "scanything", str(sample), "--no-llm", "--json-out", str(out)],
                       capture_output=True, text=True, cwd=tmp_path)
    assert p.returncode == 0, p.stderr
    assert json.loads(out.read_text())["summary"]["heuristic_verdict"] == "no_static_indicators"
    assert "scanything: s.zip" in p.stdout


def test_cli_verdict_gets_ids(server, tmp_path):
    sample = tmp_path / "m.zip"
    sample.write_bytes(make_zip({"a.exe": make_pe(strings=b"\x00vssadmin delete shadows /all\x00")}))
    out, md = tmp_path / "r.json", tmp_path / "v.md"
    # Keep the OS env (Windows needs SYSTEMROOT to start Python); point HOME away from the real config.
    env = {**os.environ, "HOME": str(tmp_path), "USERPROFILE": str(tmp_path), "LLM_PROVIDER": "custom",
           "LLM_BASE_URL": server, "LLM_API_KEY": "k", "LLM_MODEL": "mock-model"}
    p = subprocess.run([sys.executable, "-m", "scanything", str(sample), "--json-out", str(out), "--md-out", str(md)],
                       capture_output=True, text=True, cwd=tmp_path, env=env)
    assert p.returncode == 0, p.stderr
    report = json.loads(out.read_text())
    v = report["verdict"]
    assert (v["label"], v["confidence"], v["scan_id"]) == ("MALICIOUS", 90, report["ids"]["scan_id"])
    assert v["verdict_id"] in p.stderr and v["verdict_id"] in md.read_text()


def test_cli_survives_a_cp1252_console(tmp_path):
    sample = tmp_path / "s.zip"
    sample.write_bytes(make_zip({"readme.txt": b"hi"}))
    env = {**os.environ, "PYTHONIOENCODING": "cp1252"}  # what a default Windows console gives us
    p = subprocess.run([sys.executable, "-m", "scanything", str(sample), "--no-llm"], capture_output=True,
                       cwd=tmp_path, env=env)
    assert p.returncode == 0, p.stderr.decode("cp1252", "replace")
