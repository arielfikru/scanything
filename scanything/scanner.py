"""Recursive scan of a file and the archives inside it."""
from __future__ import annotations

import io
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
import zlib
from pathlib import Path

try:
    import yara  # optional: pip install yara-python
except ImportError:
    yara = None

from . import attack, deobf, repo, signatures
from .static import analyze_pe, detect_type, extract_strings, find_iocs, ioc_signals, name_signals, pe_signals
from .util import (BOMB_RATIO, BOMB_TOTAL, DEFAULT_ZIP_PASSWORDS, ENTROPY_SAMPLE, EXEC_EXT, LURE_EXT, MAX_DEPTH,
                   MAX_ENTRIES, MAX_FILES, MAX_INNER, SCRIPT_EXT, SEV_WEIGHT, STRINGS_SCAN, entropy, hashes, human,
                   sig)


CONTAINER_TYPES = {"zip", "7z", "rar", "cab", "iso"}
RECOVERED_KEEP = 20          # recovered strings kept per kind in the report (all go to search_strings)
CODE_SCAN = 2 * 1024**2      # bytes of a source file checked by the code rules
DOC_EXT = {".md", ".rst", ".adoc"}  # documentation: URLs in it are references, not IOCs


def read_entry(zf: zipfile.ZipFile, zi: zipfile.ZipInfo, passwords: list):
    last = "encrypted (password unknown - pass --password)"
    for pwd in passwords:
        try:
            with zf.open(zi, pwd=pwd.encode() if pwd else None) as f:
                return f.read(MAX_INNER), None, pwd
        except RuntimeError:  # bad password
            continue
        except NotImplementedError as e:  # e.g. AES-encrypted zips
            return None, f"unsupported compression/encryption ({e}); unpack with 7-Zip and scan the files", None
        except (zipfile.BadZipFile, zlib.error, EOFError, OSError) as e:
            if pwd:  # wrong password that passed the 1-byte check ends as a CRC error
                last = f"encrypted (password unknown): {e}"
                continue
            return None, f"corrupt entry: {e}", None
    return None, last, None


def analyze_zip(scan: "Scan", data: bytes, depth: int, parent: int) -> tuple[dict, list[dict]]:
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, OSError, ValueError) as e:
        return {"error": f"cannot open archive: {e}"}, [sig("archive_corrupt", "low", f"Archive unreadable: {e}")]
    infos = zf.infolist()
    arc = {"entry_count": len(infos), "total_uncompressed": sum(i.file_size for i in infos),
           "encrypted_entries": 0, "password_used": None, "entries": []}
    signals = []
    if len(infos) > scan.max_entries:
        signals.append(sig("many_entries", "low", f"{len(infos)} entries, only first {scan.max_entries} analyzed"))
        infos = infos[:scan.max_entries]
    if arc["total_uncompressed"] > BOMB_TOTAL:
        signals.append(sig("zip_bomb", "high", f"Declared uncompressed size {human(arc['total_uncompressed'])}"))

    risky_encrypted = []
    for zi in infos:
        e = {"name": zi.filename, "size": zi.file_size, "compressed": zi.compress_size,
             "encrypted": bool(zi.flag_bits & 0x1)}
        arc["entries"].append(e)
        norm = zi.filename.replace("\\", "/")
        if norm.startswith("/") or re.match(r"^[A-Za-z]:", norm) or ".." in norm.split("/"):
            signals.append(sig("zip_slip", "high", f"Path traversal entry name: {zi.filename!r}"))
        if zi.is_dir():
            continue
        ext = Path(norm).suffix.lower()
        if e["encrypted"]:
            arc["encrypted_entries"] += 1
            if ext in EXEC_EXT | SCRIPT_EXT | LURE_EXT:
                risky_encrypted.append(zi.filename)
        if ext in SCRIPT_EXT | LURE_EXT:
            sev = "info" if scan.source_tree and ext in SCRIPT_EXT else "medium"
            signals.append(sig("script_or_lure_in_archive", sev, f"Script/shortcut/disk image: {zi.filename!r}",
                               "Some tools ship .bat/.cmd helper scripts; source repositories are full of them"))
        if zi.file_size > MAX_INNER:
            e["skipped"] = f"too large ({human(zi.file_size)})"
            continue
        if zi.file_size > 10 * 1024**2 and zi.file_size / max(zi.compress_size, 1) > BOMB_RATIO:
            e["skipped"] = "compression ratio looks like a zip bomb"
            signals.append(sig("zip_bomb", "high", f"Ratio >{BOMB_RATIO}x on {zi.filename!r}"))
            continue
        content, err, pwd = read_entry(zf, zi, scan.passwords if e["encrypted"] else [None])
        if err:
            e["skipped"] = err
            continue
        if pwd:
            arc["password_used"] = pwd
        e["file_index"] = analyze_blob(scan, zi.filename, content, depth, parent)

    if risky_encrypted:
        signals.append(sig("encrypted_executable", "medium",
                           f"Password-protected archive hides executables/scripts: {risky_encrypted[:5]}",
                           "Classic AV-evasion in malspam; also used to share samples or by some download sites"))
    if arc["password_used"] in DEFAULT_ZIP_PASSWORDS:
        signals.append(sig("sample_password", "info", f"Archive password is {arc['password_used']!r} - the "
                           "usual convention for sharing known malware samples"))
    return arc, signals


# ----------------------------------------------------------------- scanning core

class Scan:
    def __init__(self, args):
        self.args = args
        self.files: list[dict] = []
        self.strings: dict[int, list[str]] = {}
        self.notes: list[str] = []
        self.passwords = ([args.password] if args.password else []) + DEFAULT_ZIP_PASSWORDS
        self.yara_rules = load_yara(args.yara) if args.yara else None
        self.max_files = getattr(args, "max_files", None) or MAX_FILES
        self.max_entries = getattr(args, "max_entries", None) or MAX_ENTRIES
        self.source_tree = bool(getattr(args, "source_tree", False))  # a repository: scripts are expected


def analyze_blob(scan: Scan, name: str, data: bytes, depth: int, parent: int | None,
                 disk_path: Path | None = None) -> int | None:
    if len(scan.files) >= scan.max_files:
        if "file limit" not in " ".join(scan.notes):
            scan.notes.append(f"file limit reached: only the first {scan.max_files} files were analyzed")
        return None
    idx = len(scan.files)
    rec = {"index": idx, "name": name, "parent": parent, "depth": depth, "size": len(data), **hashes(data),
           "type": detect_type(data, name), "entropy": entropy(data[:ENTROPY_SAMPLE]), "signals": []}
    scan.files.append(rec)
    strings = extract_strings(data[:STRINGS_SCAN])
    scan.strings[idx] = strings
    rec["strings_count"] = len(strings)
    t = rec["type"]
    decoded = []
    if t not in CONTAINER_TYPES:
        found = deobf.recover(data)
        decoded = deobf.recovered_strings(found)
        if decoded:
            rec["recovered"] = {k: v[:RECOVERED_KEEP] for k, v in found.items() if v}
            rec["recovered"]["counts"] = {k: len(v) for k, v in found.items() if v}
            scan.strings[idx] = strings + [f"[decoded] {d}" for d in decoded]
        rec["signals"] += deobf.signals(found)
    rec["iocs"] = find_iocs(strings + decoded)
    rec["signals"] += name_signals(name) + ioc_signals(rec["iocs"], urls=Path(name).suffix.lower() not in DOC_EXT)
    if t in ("text", "script", "data") and repo.is_source_path(name):
        rec["signals"] += repo.code_signals(name, data[:CODE_SCAN].decode("utf-8", errors="replace"))

    if t == "pe":
        rec["pe"] = analyze_pe(data)
        rec["frameworks"] = signatures.detect(data, rec["pe"])
        rec["signals"] += pe_signals(rec)
        if data.count(b"This program cannot be run in DOS mode") > 1:
            rec["signals"].append(sig("embedded_pe", "low", "Contains additional embedded PE files",
                                      "Installers, SFX archives and apps bundling DLLs do this"))
        if rec["pe"].get("signature_present") and shutil.which("osslsigncode"):
            rec["signature_check"] = verify_signature(data, disk_path)
    elif t == "zip":
        if depth >= MAX_DEPTH:
            rec["signals"].append(sig("deep_nesting", "medium", f"Archive nested deeper than {MAX_DEPTH} levels"))
        else:
            rec["archive"], arc_sigs = analyze_zip(scan, data, depth + 1, idx)
            rec["signals"] += arc_sigs
            if depth >= 1:
                rec["signals"].append(sig("nested_archive", "low", "Archive inside an archive",
                                          "Common for bundles and backups"))
    elif t in ("7z", "rar", "cab", "iso"):
        rec["signals"].append(sig("unsupported_container", "low", f"{t} container not unpacked; extract it "
                                  "(without running anything) and scan the files inside"))
    elif t in ("script", "lnk"):
        sev = "info" if scan.source_tree and t == "script" else "medium"
        rec["signals"].append(sig(f"{t}_file", sev, f"{t} file - runs code when opened",
                                  "Harmless if it is a known helper script; read its content"))

    if scan.yara_rules is not None:
        try:
            hits = [m.rule for m in scan.yara_rules.match(data=data, timeout=60)]
        except Exception as e:
            hits, rec["yara_error"] = [], str(e)
        if hits:
            rec["yara"] = hits
            rec["signals"].append(sig("yara_match", "high", f"YARA rules matched: {hits[:10]}",
                                      "Depends on rule quality; generic rules can over-match"))
    attack.annotate(rec["signals"])
    rec["score"] = sum(SEV_WEIGHT[s["severity"]] for s in rec["signals"])
    return idx


def verify_signature(data: bytes, disk_path: Path | None) -> dict:
    exe = shutil.which("osslsigncode")
    with tempfile.TemporaryDirectory() as td:
        path = disk_path
        if path is None:
            path = Path(td) / "sample.bin"
            path.write_bytes(data)
        try:
            p = subprocess.run([exe, "verify", "-in", str(path)], capture_output=True, text=True, timeout=120)
        except subprocess.TimeoutExpired:
            return {"tool": "osslsigncode", "ok": None, "output": "timeout"}
    out = p.stdout + p.stderr
    return {"tool": "osslsigncode", "ok": p.returncode == 0, "output": out[-1500:]}


def load_yara(path: str):
    if yara is None:
        print("[!] --yara given but yara-python is not installed (pip install yara-python)", file=sys.stderr)
        return None
    p = Path(path)
    files = {f"r{i}": str(f) for i, f in enumerate(sorted(p.rglob("*.yar*")))} if p.is_dir() else {"r0": str(p)}
    try:
        return yara.compile(filepaths=files)
    except Exception as e:
        print(f"[!] YARA compile failed: {e}", file=sys.stderr)
        return None
