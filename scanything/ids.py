"""Deterministic identifiers, like the hash-based IDs of malware scanning platforms.

file_id     SHA-256 of the scanned file's bytes. Same bytes -> same id, on any machine. Matches VirusTotal.
ruleset     hash of every detection rule table. Changes whenever a rule is added or edited.
scan_id     content hash of the STATIC analysis: engine version + ruleset + the analysis itself.
            Same file + same name + same Scanything version/ruleset/parser -> same scan_id. Volatile parts
            (timestamps, local path, VirusTotal/ClamAV results, signature-verify output) are left out.
            Anyone can recompute it from the JSON report with `scan_id_of(report)`.
verdict_id  hash of scan_id + provider + model + the AI answer. Unique per AI answer: an LLM is not
            deterministic, so the verdict gets its own id that points back to the scan it judged.
"""
from __future__ import annotations

import hashlib
import json
import re

from . import attack, deobf, engines, repo, signatures, static
from .util import VERSION

VOLATILE_FILE_KEYS = {"virustotal", "signature_check", "yara_error", "score"}
VOLATILE_SIGNAL_PREFIXES = ("vt_",)
# repository metadata (stars, age) changes over time; the code itself is pinned by commit
VOLATILE_SIGNAL_IDS = {"star_farming_suspect", "new_repo", "no_community", "archived_repo", "forked_repo"}


def _digest(obj) -> str:
    canonical = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def ruleset_id() -> str:
    tables = {
        "patterns": [(i, s, l, r) for i, s, l, r, _fp in static.SUS_PATTERNS],
        "imports": {k: sorted(v) for k, v in static.SUS_IMPORTS.items()},
        "signatures": [{k: [x.decode("latin-1") if isinstance(x, bytes) else x for x in v] if isinstance(v, list)
                        else v for k, v in entry.items()} for entry in signatures.SIGNATURES],
        "deobf": [[p.decode("latin-1") for p in deobf.XOR_PROBES], deobf.STACK_SIGNAL_MIN, deobf.TEXT_MAX],
        "code_rules": [list(r) for r in repo.CODE_RULES],
        "url_rules": [static.BENIGN_URL_RE.pattern, static.SHADY_HOST_RE.pattern],
        "vt_rules": [engines.GENERIC_DET_RE.pattern, engines.PUA_DET_RE.pattern],
        "attack": attack.SIGNAL_MAP,
    }
    return "rs_" + _digest(tables)[:12]


RULESET = ruleset_id()


def static_view(files: list[dict], notes: list[str]) -> dict:
    """The deterministic part of a scan: what scan_id is computed over."""
    clean = []
    for f in files:
        rec = {k: v for k, v in f.items() if k not in VOLATILE_FILE_KEYS}
        rec["signals"] = [s for s in f.get("signals", []) if not s["id"].startswith(VOLATILE_SIGNAL_PREFIXES)
                          and s["id"] not in VOLATILE_SIGNAL_IDS]
        clean.append(rec)
    return {"files": clean, "notes": notes}


def scan_id_of(report: dict) -> str:
    """Recompute a report's scan_id (verifiable by anyone holding the JSON report)."""
    ids = report["ids"]
    body = {"engine": ids["engine"], "ruleset": ids["ruleset"],
            "static": static_view(report["files"], report.get("notes", []))}
    return "scn_" + _digest(body)[:24]


def make_ids(files: list[dict], notes: list[str]) -> dict:
    ids = {"file_id": files[0]["sha256"] if files else None, "engine": VERSION, "ruleset": RULESET}
    ids["scan_id"] = scan_id_of({"ids": ids, "files": files, "notes": notes})
    return ids


VERDICT_RE = re.compile(r"verdict\s*:\s*\**\s*([A-Z][A-Z /_-]+?)\s*\**\s*\(\s*confidence\s*(\d{1,3})\s*%", re.I)


def make_verdict(scan_id: str, provider: str, model: str, text: str, created: str) -> dict:
    m = VERDICT_RE.search(text or "")
    label = re.sub(r"\s+", "_", m.group(1).strip().upper()).replace("/", "_") if m else None
    return {
        "verdict_id": "vrd_" + _digest({"scan_id": scan_id, "provider": provider, "model": model,
                                        "text": text})[:24],
        "scan_id": scan_id,
        "label": label,
        "confidence": int(m.group(2)) if m else None,
        "provider": provider,
        "model": model,
        "created": created,
    }
