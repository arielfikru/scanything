"""MCP server over real stdio, the way Claude Code / Codex start it."""
import json
import os
import subprocess
import sys

import pytest

from tests.fixtures import make_pe, make_zip


class MCP:
    def __init__(self, env=None):
        self.p = subprocess.Popen([sys.executable, "-m", "scanything", "mcp"], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8",
                                  env={**os.environ, **(env or {})})
        self.next_id = 0

    def request(self, method, params=None):
        self.next_id += 1
        self.send({"jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params or {}})
        reply = json.loads(self.p.stdout.readline())
        assert reply["id"] == self.next_id
        return reply

    def send(self, msg):
        self.p.stdin.write(json.dumps(msg) + "\n")
        self.p.stdin.flush()

    def call(self, name, **args):
        return self.request("tools/call", {"name": name, "arguments": args})["result"]

    def close(self):
        self.p.stdin.close()
        self.p.wait(timeout=10)


@pytest.fixture
def mcp():
    server = MCP(env={"VT_API_KEY": ""})
    init = server.request("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                         "clientInfo": {"name": "test", "version": "0"}})
    server.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
    server.init = init["result"]
    yield server
    server.close()


def test_handshake_and_tool_list(mcp):
    assert mcp.init["serverInfo"]["name"] == "scanything"
    assert mcp.init["protocolVersion"] == "2025-06-18"
    assert "never" in mcp.init["instructions"].lower()
    tools = {t["name"]: t for t in mcp.request("tools/list")["result"]["tools"]}
    assert set(tools) == {"scan_file", "scan_github", "get_report_section", "search_strings", "list_files"}
    assert "scan_id" in tools["search_strings"]["inputSchema"]["required"]


def test_scan_then_follow_up(mcp, tmp_path):
    sample = tmp_path / "mail.zip"
    sample.write_bytes(make_zip({"invoice.pdf.exe": make_pe(strings=b"\x00vssadmin delete shadows /all\x00")}))
    res = mcp.call("scan_file", path=str(sample))
    assert res["isError"] is False
    body = json.loads(res["content"][0]["text"])
    assert body["summary"]["heuristic_verdict"] == "likely_malicious"
    rid = body["scan_id"]

    hits = json.loads(mcp.call("search_strings", scan_id=rid, file_index=1, pattern="vssadmin")["content"][0]["text"])
    assert hits["total_matches"] == 1
    section = mcp.call("get_report_section", scan_id=rid, path="files[1].type")
    assert section["content"][0]["text"] == '"pe"'


def test_errors_are_tool_errors_not_crashes(mcp, tmp_path):
    assert mcp.call("scan_file", path=str(tmp_path / "missing.exe"))["isError"] is True
    assert mcp.call("list_files", scan_id="nope")["isError"] is True
    assert mcp.request("does/not/exist")["error"]["code"] == -32601
    assert mcp.request("ping")["result"] == {}  # still alive


def test_setup_dry_run_prints_both_agents():
    p = subprocess.run([sys.executable, "-m", "scanything", "setup", "--dry-run"], capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    assert "claude mcp add" in p.stdout and "codex" in p.stdout.lower()
    assert "nothing changed" in p.stdout


def test_setup_rejects_unknown_agent():
    p = subprocess.run([sys.executable, "-m", "scanything", "setup", "vim", "--dry-run"], capture_output=True, text=True)
    assert p.returncode == 2 and "unknown agent" in p.stderr


def test_mcp_speaks_utf8_even_with_a_cp1252_locale(tmp_path):
    server = MCP(env={"PYTHONIOENCODING": "cp1252", "VT_API_KEY": ""})
    try:
        server.request("initialize", {"protocolVersion": "2025-06-18"})
        f = tmp_path / "résumé.txt"
        f.write_text("naïve ünïcode café")
        res = server.call("scan_file", path=str(f))
        assert res["isError"] is False and "résumé.txt" in res["content"][0]["text"]
    finally:
        server.close()
