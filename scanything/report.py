"""Report assembly, compact LLM view and terminal summary."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from .attack import summarize as attack_summary
from .ids import make_ids
from .util import SEV_WEIGHT, VERSION, human

if TYPE_CHECKING:
    from .scanner import Scan


def build_report(target: Path | dict, scan: Scan, engines: dict) -> dict:
    files = scan.files
    highs = [(f["index"], s) for f in files for s in f["signals"] if s["severity"] == "high"]
    total = sum(f["score"] for f in files)
    vt_heavy = any((f.get("virustotal") or {}).get("malicious", 0) >= 10 for f in files)
    clam_hit = bool((engines.get("clamav") or {}).get("infected"))
    if vt_heavy or len(highs) >= 2 or (highs and total >= 12) or (clam_hit and highs):
        verdict = "likely_malicious"
    elif highs or clam_hit or total >= 6:
        verdict = "suspicious"
    elif total >= 3:
        verdict = "low_risk_indicators"
    else:
        verdict = "no_static_indicators"
    fp_ids = {"signed", "vt_low_generic", "vt_clean", "vt_pua", "framework_installer", "framework_runtime",
              "framework_packer", "framework_protector", "framework_sfx", "framework_obfuscator"}
    fp_factors = [f"#{f['index']} {s['id']}: {s['detail']} -> {s.get('fp_note', '')}"
                  for f in files for s in f["signals"] if s["id"] in fp_ids]
    ranked = sorted(((f["index"], s) for f in files for s in f["signals"] if s["severity"] != "info"),
                    key=lambda x: -SEV_WEIGHT[x[1]["severity"]])
    return {
        "ids": make_ids(files, scan.notes),
        "tool": f"scanything {VERSION}",
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "target": target if isinstance(target, dict) else {"name": target.name, "path": str(target)},
        "summary": {
            "heuristic_verdict": verdict,
            "heuristic_score": total,
            "files_analyzed": len(files),
            "high_signals": len(highs),
            "top_signals": [{"file": i, **s} for i, s in ranked[:12]],
            "false_positive_factors": fp_factors[:15],
            "attack_techniques": attack_summary(files),
        },
        "files": files,
        "engines": engines,
        "notes": scan.notes,
        "limits": [
            "Static analysis only: the file was never executed, so runtime behaviour is unknown.",
            "Signature presence is not signature validity unless signature_check.ok is true.",
            "Heuristic verdict/score is a rough hint, not ground truth.",
        ],
    }


def compact_report(report: dict) -> dict:
    """Smaller view for the LLM's first look; details come through tools."""
    files = []
    for f in report["files"][:60]:
        c = {k: f[k] for k in ("index", "name", "parent", "type", "size", "sha256", "entropy", "score") if k in f}
        c["signals"] = f["signals"]
        pe = f.get("pe")
        if pe:
            c["pe"] = {k: pe[k] for k in ("error", "machine", "is_64bit", "is_dll", "is_dotnet", "subsystem",
                                          "compile_time", "ep_section", "signature_present", "certificate_names",
                                          "version_info", "import_count", "imported_dlls", "suspicious_imports",
                                          "overlay") if k in pe}
            c["pe"]["sections"] = [f'{s["name"]} ent={s["entropy"]} {"W" if s["writable"] else ""}'
                                   f'{"X" if s["executable"] else ""}' for s in pe.get("sections", [])]
        if f.get("frameworks"):
            c["frameworks"] = f["frameworks"]
        io_ = f["iocs"]
        c["iocs"] = {"url_count": io_["url_count"], "notable_urls": io_["notable_urls"][:15],
                     "ip_like": io_["ip_like"][:15], "registry": io_["registry"][:10]}
        if f.get("archive") and "error" not in f["archive"]:
            a = f["archive"]
            c["archive"] = {"entry_count": a["entry_count"], "encrypted_entries": a["encrypted_entries"],
                            "password_used": a["password_used"],
                            "skipped": [{"name": e["name"], "why": e["skipped"]} for e in a["entries"]
                                        if e.get("skipped")][:20]}
        for k in ("virustotal", "signature_check", "yara"):
            if f.get(k):
                c[k] = f[k]
        files.append(c)
    return {"ids": report["ids"], "target": report["target"], "summary": report["summary"], "files": files,
            "files_omitted": max(0, len(report["files"]) - 60), "engines": report["engines"],
            "notes": report["notes"], "limits": report["limits"]}


def print_summary(report: dict) -> None:
    s = report["summary"]
    print(f"\n== scanything: {report['target']['name']} ==")
    ids = report["ids"]
    print(f"scan_id {ids['scan_id']}  ·  file_id (sha256) {ids['file_id']}  ·  ruleset {ids['ruleset']}")
    print(f"Heuristic verdict: {s['heuristic_verdict'].upper()}  (score {s['heuristic_score']}, "
          f"{s['files_analyzed']} file(s), static only)\n")
    print(f"{'#':>3}  {'type':<7}{'size':>10}  {'score':>5}  name")
    for f in report["files"]:
        indent = "  " * f["depth"] + ("└ " if f["depth"] else "")
        print(f"{f['index']:>3}  {f['type']:<7}{human(f['size']):>10}  {f['score']:>5}  {indent}{f['name']}")
    if s["top_signals"]:
        print("\nTop signals:")
        for t in s["top_signals"][:8]:
            print(f"  [{t['severity']}] #{t['file']} {t['id']}: {t['detail'][:140]}")
    if s["attack_techniques"]:
        print("\nMITRE ATT&CK (likely, from static evidence):")
        for t in s["attack_techniques"][:10]:
            print(f"  {t['id']:<10} {t['name']} [{t['tactic']}]  <- {', '.join(t['evidence'][:3])}")
    if s["false_positive_factors"]:
        print("\nFalse-positive factors:")
        for x in s["false_positive_factors"][:6]:
            print(f"  - {x[:180]}")
    for f in report["files"]:
        vt = f.get("virustotal")
        if vt and vt.get("found"):
            print(f"\nVirusTotal #{f['index']}: {vt['malicious']}/{vt['engines_total']}  {vt['link']}")
    clam = report["engines"].get("clamav")
    if clam and clam.get("available"):
        print(f"\nClamAV: {'INFECTED ' + str(clam['detections']) if clam.get('infected') else 'no detection'}")
    for n in report["notes"]:
        print(f"[note] {n}")
