"""Optional third-party engines: VirusTotal (hash lookup only) and ClamAV."""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import urllib.error
import urllib.request
from pathlib import Path

from .util import sig, ts_iso


GENERIC_DET_RE = re.compile(
    r"(?i)(generic|heur|\bml\b|machine ?learning|static ?ai|\bai\b|confidence|score|unsafe|suspicious|"
    r"wacatac|presenoker|artemis|sabsik|tiggre|kcloud|cloud|lowfi|susgen|behaveslike|reputation|"
    r"attribute|\.gen\b|gen:|!ml|malware\.ai|deepscan|ulise|razy|zusy|trojan\.win(32|64)\.agent)")
PUA_DET_RE = re.compile(r"(?i)(pua|pup|riskware|hacktool|not-a-virus|adware|unwanted|crack|keygen|patcher|"
                        r"bitcoinminer|coinminer|application\.)")


def vt_lookup(sha256: str, key: str) -> dict:
    req = urllib.request.Request(f"https://www.virustotal.com/api/v3/files/{sha256}", headers={"x-apikey": key})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            attrs = json.load(resp)["data"]["attributes"]
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"found": False}
        return {"error": f"HTTP {e.code}: {e.read()[:200].decode('utf-8', 'replace')}"}
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, KeyError) as e:
        return {"error": str(e)}
    dets = {eng: r.get("result") for eng, r in attrs.get("last_analysis_results", {}).items()
            if r.get("category") in ("malicious", "suspicious")}
    stats = attrs.get("last_analysis_stats", {})
    names = list(dets.values())
    return {
        "found": True,
        "stats": stats,
        "malicious": stats.get("malicious", 0),
        "engines_total": sum(stats.get(k, 0) for k in ("malicious", "suspicious", "undetected", "harmless")),
        "detections": dict(list(dets.items())[:40]),
        "generic_detections": sum(bool(GENERIC_DET_RE.search(n or "")) for n in names),
        "pua_detections": sum(bool(PUA_DET_RE.search(n or "")) for n in names),
        "threat_label": (attrs.get("popular_threat_classification") or {}).get("suggested_threat_label"),
        "names": attrs.get("names", [])[:10],
        "tags": attrs.get("tags", [])[:20],
        "first_seen": ts_iso(attrs.get("first_submission_date")),
        "last_analysis": ts_iso(attrs.get("last_analysis_date")),
        "times_submitted": attrs.get("times_submitted"),
        "reputation": attrs.get("reputation"),
        "signature_info": attrs.get("signature_info"),
        "link": f"https://www.virustotal.com/gui/file/{sha256}",
    }


def vt_signals(vt: dict) -> list[dict]:
    if not vt.get("found"):
        return [] if vt.get("error") else [sig("vt_unknown", "info", "Hash never seen on VirusTotal (new or rare "
                                                 "file - not proof either way)")]
    mal, total = vt["malicious"], vt["engines_total"]
    flagged = len(vt["detections"])
    if flagged == 0:
        return [sig("vt_clean", "info", f"VirusTotal: 0/{total} engines flag it")]
    if flagged <= 3 and vt["generic_detections"] == flagged:
        return [sig("vt_low_generic", "low", f"VirusTotal {mal}/{total}, only generic/ML names: "
                    f"{list(vt['detections'].values())}", "Few engines + generic/heuristic names is the typical "
                    "false-positive pattern")]
    if vt["pua_detections"] >= max(1, flagged // 2):
        return [sig("vt_pua", "medium", f"VirusTotal {mal}/{total}, mostly PUA/HackTool/RiskWare names",
                    "Grey area (cracks, cheats, miners, bundleware): unwanted rather than a classic virus")]
    sev = "high" if mal >= 5 else "medium"
    return [sig("vt_detected", sev, f"VirusTotal {mal}/{total} malicious; label: {vt.get('threat_label')}")]


def run_clamav(path: Path) -> dict:
    exe = shutil.which("clamscan")
    if not exe:
        return {"available": False, "hint": "brew install clamav && freshclam"}
    try:
        p = subprocess.run([exe, "--no-summary", "--infected", str(path)], capture_output=True, text=True,
                           timeout=900)
    except subprocess.TimeoutExpired:
        return {"available": True, "error": "timeout"}
    hits = [ln.strip() for ln in p.stdout.splitlines() if ln.rstrip().endswith("FOUND")]
    return {"available": True, "infected": p.returncode == 1, "detections": hits,
            "error": p.stderr.strip()[:500] if p.returncode == 2 else None}
