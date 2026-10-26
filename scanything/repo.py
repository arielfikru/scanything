"""GitHub repository scanning: URL parsing, pinned fetch, metadata and source-code rules.

The only network access is `_get` (stdlib urllib). The fetched zip is returned as bytes for the
normal archive scanner to read; nothing is executed, imported or unpacked here.
"""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

from scanything.util import sig

API = "https://api.github.com"
CODELOAD = "https://codeload.github.com"
TIMEOUT = 30
MAX_REPO_BYTES = 512 * 1024**2

NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
URL_RE = re.compile(r"^https?://(?:www\.)?github\.com/([^/\s?#]+)/([^/\s?#]+?)(?:\.git)?/?(?:/tree/(\S+?))?/?$")
SHORT_RE = re.compile(r"^github:([^@\s]+)(?:@(\S+))?$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")

WORKFLOW_PATH = r"(^|/)\.github/workflows/[^/]+\.ya?ml$"
CODE_EXT = r"\.(?:py|pyw|js|mjs|cjs|jsx|ts|mts|cts|tsx|cs|java|go|rs|php|rb|sh|ps1|json)$"


class RepoError(Exception):
    """A repository could not be fetched or resolved. The message is shown to the user."""


def _valid_name(name: str) -> bool:
    return bool(NAME_RE.match(name)) and name not in (".", "..")


def parse_github(target: str) -> tuple[str, str, str | None] | None:
    """Parse a GitHub URL or `github:OWNER/REPO[@REF]` into (owner, repo, ref). None if invalid."""
    t = (target or "").strip()
    if m := SHORT_RE.match(t):
        parts = m.group(1).split("/")
        if len(parts) != 2:
            return None
        owner, repo, ref = parts[0], parts[1], m.group(2)
    elif m := URL_RE.match(t):
        owner, repo, ref = m.group(1), m.group(2), m.group(3)
    else:
        return None
    if not (_valid_name(owner) and _valid_name(repo)):
        return None
    return owner, repo, ref


def _http_error_message(url: str, e: urllib.error.HTTPError) -> str:
    headers = getattr(e, "headers", None) or {}
    remaining = headers.get("X-RateLimit-Remaining")
    if e.code == 429 or remaining == "0":
        return (f"GitHub rate limit reached (HTTP {e.code}) for {url}. "
                "Set GITHUB_TOKEN to a token with read access to raise the limit.")
    if e.code == 404:
        return (f"not found: {url}. Check the owner, repo and ref spelling; "
                "private repositories also need GITHUB_TOKEN.")
    if e.code == 403:
        return f"access denied (HTTP 403) for {url}. Set GITHUB_TOKEN if the repository is private."
    return f"HTTP {e.code} from {url}: {e.reason}"


def _get(url: str, binary: bool = False, limit: int | None = None):
    """GET a GitHub URL. Returns parsed JSON, or raw bytes when binary (at most limit+1 bytes)."""
    headers = {"User-Agent": "scanything",
               "Accept": "*/*" if binary else "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            data = resp.read() if limit is None else resp.read(limit + 1)
    except urllib.error.HTTPError as e:
        raise RepoError(_http_error_message(url, e)) from None
    except OSError as e:  # URLError and TimeoutError are OSError subclasses
        raise RepoError(f"network error while fetching {url}: {e}") from None
    if binary:
        return data
    try:
        return json.loads(data)
    except ValueError:
        raise RepoError(f"unexpected non-JSON response from {url}") from None


def fetch_repo(owner: str, repo: str, ref: str | None = None,
               max_bytes: int = MAX_REPO_BYTES) -> tuple[bytes, dict]:
    """Fetch a repo archive pinned to a commit. Returns (zip_bytes, info)."""
    base = f"{API}/repos/{owner}/{repo}"
    meta = _get(base)
    if not isinstance(meta, dict):
        raise RepoError(f"unexpected repository metadata for {owner}/{repo}")
    ref = ref or meta.get("default_branch")
    if not ref:
        raise RepoError(f"could not determine a branch to scan for {owner}/{repo}")

    commit = _get(f"{base}/commits/{urllib.parse.quote(ref, safe='/')}")
    sha = commit.get("sha") if isinstance(commit, dict) else None
    if not sha or not SHA_RE.match(sha):
        raise RepoError(f"could not resolve ref {ref!r} to a commit in {owner}/{repo}")

    owner_login = (meta.get("owner") or {}).get("login") or owner
    owner_info: dict = {}
    try:
        user = _get(f"{API}/users/{urllib.parse.quote(owner_login)}")
        if isinstance(user, dict):
            owner_info = user
    except RepoError:
        pass  # owner metadata is best effort

    data = _get(f"{CODELOAD}/{owner}/{repo}/zip/{sha}", binary=True, limit=max_bytes)
    if len(data) > max_bytes:
        raise RepoError(f"repository archive is larger than {max_bytes} bytes; refusing to scan it")

    license_id = (meta.get("license") or {}).get("spdx_id")
    if license_id == "NOASSERTION":
        license_id = None
    info = {
        "repo": meta.get("full_name") or f"{owner}/{repo}",
        "url": meta.get("html_url") or f"https://github.com/{owner}/{repo}",
        "ref": ref,
        "commit": sha,
        "default_branch": meta.get("default_branch"),
        "stars": meta.get("stargazers_count"),
        "forks": meta.get("forks_count"),
        "watchers": meta.get("watchers_count"),
        "open_issues": meta.get("open_issues_count"),
        "created_at": meta.get("created_at"),
        "pushed_at": meta.get("pushed_at"),
        "size_kb": meta.get("size"),
        "archived": bool(meta.get("archived")),
        "fork": bool(meta.get("fork")),
        "license": license_id,
        "owner": owner_login,
        "owner_type": (meta.get("owner") or {}).get("type"),
        "owner_created_at": owner_info.get("created_at"),
    }
    return data, info


def _ts(value) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def metadata_signals(info: dict, now: datetime | None = None) -> list[dict]:
    """Signals from repository metadata (see fetch_repo for the info keys)."""
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    out: list[dict] = []
    stars = info.get("stars") or 0
    owner = info.get("owner") or "?"

    owner_created = _ts(info.get("owner_created_at"))
    if owner_created and now - owner_created < timedelta(days=30) and stars >= 50:
        days = (now - owner_created).days
        out.append(sig("star_farming_suspect", "medium",
                       f"owner {owner} account is {days} days old and the repo has {stars} stars",
                       "Genuinely viral new projects exist; check stargazer profiles"))

    created = _ts(info.get("created_at"))
    if created and now - created < timedelta(days=7):
        out.append(sig("new_repo", "info",
                       f"repository created {created.date().isoformat()} (under 7 days ago)",
                       "New repositories are normal; meaningful only together with other signals"))

    if info.get("stars") == 0 and info.get("forks") == 0:
        out.append(sig("no_community", "info", "no stars and no forks",
                       "Most legitimate small projects have no stars either"))
    if info.get("archived"):
        out.append(sig("archived_repo", "info", "repository is archived (read-only upstream)",
                       "Archived projects are common and often stable"))
    if info.get("fork"):
        out.append(sig("forked_repo", "info", "repository is a fork",
                       "Forks of popular tools are sometimes trojanized; informational only"))
    return out


# (id, severity, label, path regex, content regex or tuple that must ALL match, fp_note)
CODE_RULES: list[tuple] = [
    ("npm_install_hook", "medium", "npm install script fetches or runs something",
     r"(^|/)package\.json$",
     r"\"(pre|post)?install\"\s*:\s*\"[^\"]*(curl|wget|powershell|node\s+-e|bash\s+-c|\|\s*sh\b|https?://)",
     "Native modules use install scripts (node-gyp) but do not fetch URLs"),
    ("python_setup_exec", "high", "setup.py executes code and decodes or downloads a payload",
     r"(^|/)setup\.py$",
     (r"\b(exec|eval)\s*\(",
      r"(b64decode|zlib|marshal|urllib|requests\.get|urlopen)"),
     "Some packages build metadata dynamically; check what the decoded or downloaded data is"),
    ("python_obfuscated_exec", "high", "exec of base64, zlib, marshal or hex data",
     r"\.pyw?$",
     r"\bexec\s*\(\s*(__import__\(\s*['\"](base64|zlib|marshal)|base64\.b64decode|zlib\.decompress|marshal\.loads|bytes\.fromhex)",
     "Rare in legitimate code; a few packaging and test tools do this for generated code"),
    ("js_obfuscated_eval", "high", "eval of decoded data",
     r"\.(m|c)?(j|t)sx?$",
     r"(eval|new\s+Function)\s*\(\s*(atob|Buffer\.from|unescape)\s*\(",
     "Some bundlers and polyfills emit eval of encoded strings; check the decoded content"),
    ("vscode_autorun", "high", "VS Code task runs automatically when the folder opens",
     r"(^|/)\.vscode/tasks\.json$",
     r"\"runOn\"\s*:\s*\"folderOpen\"",
     "Some projects start watchers or dev servers on open; read the command"),
    ("msbuild_event", "high", "MSBuild pre or post build event downloads or runs tools",
     r"\.(cs|vb|fs|vcx)proj$|\.targets$|\.props$",
     r"<(Pre|Post)BuildEvent>[^<]*(powershell|cmd(\.exe)?\s*/c|curl|bitsadmin|certutil|mshta)",
     "Copy and xcopy build steps are normal; downloads and script hosts are not"),
    ("gha_secret_exfil", "high", "workflow sends a secret to a command-line HTTP tool",
     WORKFLOW_PATH,
     r"(curl|wget|Invoke-WebRequest)[^\n]*\$\{\{\s*secrets\.",
     "Some workflows pass secrets to deployment APIs on purpose; check the destination host"),
    ("gha_pwn_request", "medium", "risky workflow (untrusted PR code with secrets)",
     WORKFLOW_PATH,
     (r"pull_request_target",
      r"ref:\s*\$\{\{\s*github\.event\.pull_request\.head"),
     "This is usually a vulnerability rather than malware; it lets fork PRs run with repo secrets"),
    ("curl_pipe_shell", "low", "download piped straight into a shell",
     r"^(?!.*\.(?:md|rst|txt)$)",
     r"(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(ba|z)?sh\b",
     "Common in install scripts of legitimate tools; check the host"),
    ("hidden_far_right_code", "high", "code hidden far to the right after a long run of whitespace",
     CODE_EXT,
     r"\S[ \t]{150,}\S",
     "Rare but some generated files and aligned tables do this; look at the text after the gap"),
    ("trojan_source_bidi", "medium", "bidirectional control characters in source",
     CODE_EXT,
     r"[‪-‮⁦-⁩]",
     "Right-to-left language text inside strings is legitimate"),
    ("build_rs_command", "medium", "Rust build script runs a shell or download tool",
     r"(^|/)build\.rs$",
     r"Command::new\(\s*\"(curl|wget|powershell|cmd|sh|bash)\"",
     "Some crates call git or pkg-config; shells and downloaders are the suspicious part"),
]

_SOURCE_PATHS = [r"(^|/)package\.json$", r"(^|/)setup\.py$", r"(^|/)\.vscode/tasks\.json$",
                 WORKFLOW_PATH, r"\.(cs|vb|fs|vcx)proj$|\.targets$|\.props$", r"(^|/)build\.rs$"]


def _norm(path: str) -> str:
    return path.replace("\\", "/")


def is_source_path(path: str) -> bool:
    """True when `code_signals` could fire on this path, so the caller should decode its text."""
    p = _norm(path)
    return any(re.search(rx, p, re.I) for rx in _SOURCE_PATHS) or bool(re.search(CODE_EXT, p, re.I))


def code_signals(path: str, text: str) -> list[dict]:
    """Apply CODE_RULES to one file. At most one signal per rule per file."""
    p = _norm(path)
    out: list[dict] = []
    for sid, severity, label, path_rx, content_rx, fp_note in CODE_RULES:
        if not re.search(path_rx, p, re.I):
            continue
        patterns = (content_rx,) if isinstance(content_rx, str) else content_rx
        matches = [re.search(rx, text, re.I | re.M) for rx in patterns]
        if not all(matches):
            continue
        out.append(sig(sid, severity, f"{label}: {path}: {matches[0].group(0)[:120]!r}", fp_note))
    return out

