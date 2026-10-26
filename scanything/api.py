"""One call to scan a file on disk; shared by the CLI and the MCP server."""
from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace
from typing import Callable

from . import attack, repo
from .engines import run_clamav, vt_lookup, vt_signals
from .report import build_report
from .scanner import Scan, analyze_blob
from .util import MAX_FILE, SEV_WEIGHT, human

VT_TYPES = {"pe", "script", "lnk", "ole", "elf", "macho", "zip"}
REPO_MAX_FILES = 3000      # a repository has far more files than a typical download
REPO_MAX_ENTRIES = 10000


class ScanError(Exception):
    pass


def scan_path(path: str | Path, password: str | None = None, vt: bool = False, vt_max: int = 4,
              clamav: bool = False, yara: str | None = None,
              log: Callable[[str], None] = lambda _msg: None) -> tuple[dict, Scan]:
    """Statically analyze `path` (never executed). Returns (full report, scan state with strings)."""
    target = Path(path).expanduser()
    if not target.is_file():
        raise ScanError(f"{target} is not a file")
    size = target.stat().st_size
    if size > MAX_FILE:
        raise ScanError(f"{human(size)} is above the {human(MAX_FILE)} limit")
    log(f"[*] Static analysis of {target.name} ({human(size)}) - the file is NOT executed")

    scan = Scan(SimpleNamespace(password=password, yara=yara))
    analyze_blob(scan, target.name, target.read_bytes(), 0, None, disk_path=target)

    engines = {}
    if vt:
        _virustotal(scan, vt_max, log)
    if clamav:
        engines["clamav"] = run_clamav(target)
    return build_report(target, scan, engines), scan


def _virustotal(scan: Scan, vt_max: int, log: Callable[[str], None]) -> None:
    key = os.environ.get("VT_API_KEY")
    if not key:
        log("[!] VirusTotal lookup needs VT_API_KEY - skipped")
        return
    seen = set()
    for f in scan.files:
        if len(seen) >= vt_max:
            break
        if f["type"] in VT_TYPES and f["sha256"] not in seen:
            seen.add(f["sha256"])
            log(f"[*] VirusTotal lookup #{f['index']} {f['name']}")
            f["virustotal"] = vt_lookup(f["sha256"], key)
            f["signals"] += vt_signals(f["virustotal"])
            f["score"] = sum(SEV_WEIGHT[s["severity"]] for s in f["signals"])


def scan_github(target: str, vt: bool = False, vt_max: int = 4, yara: str | None = None,
                log: Callable[[str], None] = lambda _msg: None) -> tuple[dict, Scan]:
    """Download a GitHub repository archive pinned to one commit and scan it in memory. Nothing is run or built."""
    parsed = repo.parse_github(target)
    if parsed is None:
        raise ScanError(f"not a GitHub repository: {target!r} (use https://github.com/OWNER/REPO or "
                        "github:OWNER/REPO@REF)")
    owner, name, ref = parsed
    log(f"[*] Fetching github.com/{owner}/{name}{'@' + ref if ref else ''} (download only, nothing is run)")
    try:
        data, info = repo.fetch_repo(owner, name, ref)
    except repo.RepoError as e:
        raise ScanError(str(e)) from None
    log(f"[*] Static analysis of {info['repo']} at commit {info['commit'][:12]} ({human(len(data))})")

    scan = Scan(SimpleNamespace(password=None, yara=yara, max_files=REPO_MAX_FILES, max_entries=REPO_MAX_ENTRIES,
                                source_tree=True))
    archive = f"{info['repo'].replace('/', '_')}@{info['commit']}.zip"
    root = scan.files[analyze_blob(scan, archive, data, 0, None)]
    meta = repo.metadata_signals(info)
    attack.annotate(meta)
    root["signals"] += meta
    root["score"] = sum(SEV_WEIGHT[s["severity"]] for s in root["signals"])
    if vt:
        _virustotal(scan, vt_max, log)
    target_info = {"name": f"{info['repo']}@{info['commit'][:12]}", "path": info["url"], "kind": "github",
                   "commit": info["commit"]}
    return build_report(target_info, scan, {"github": info}), scan


def scan_target(target: str, password: str | None = None, vt: bool = False, vt_max: int = 4,
                clamav: bool = False, yara: str | None = None,
                log: Callable[[str], None] = lambda _msg: None) -> tuple[dict, Scan]:
    """A local file, or a GitHub repository URL / github:OWNER/REPO[@REF] (a local file of that name wins)."""
    if repo.parse_github(str(target)) and not Path(str(target)).expanduser().is_file():
        return scan_github(str(target), vt=vt, vt_max=vt_max, yara=yara, log=log)
    return scan_path(target, password=password, vt=vt, vt_max=vt_max, clamav=clamav, yara=yara, log=log)
