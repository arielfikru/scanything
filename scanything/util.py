"""Shared limits, constants and small helpers."""
from __future__ import annotations

import hashlib
import math
import os
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

VERSION = "0.1.0"

MAX_FILE = 512 * 1024**2        # top-level file read limit
MAX_INNER = 128 * 1024**2       # per archive entry read limit
MAX_ENTRIES = 1000              # entries per archive
MAX_DEPTH = 3                   # nested archive depth
MAX_FILES = 300                 # analyzed files in total
BOMB_RATIO = 100
BOMB_TOTAL = 2 * 1024**3
STRINGS_SCAN = 64 * 1024**2
ENTROPY_SAMPLE = 32 * 1024**2
DEFAULT_ZIP_PASSWORDS = ["infected", "malware", "virus"]
SEV_WEIGHT = {"high": 3, "medium": 2, "low": 1, "info": 0}

EXEC_EXT = {".exe", ".dll", ".scr", ".com", ".pif", ".cpl", ".sys", ".msi", ".ocx"}
SCRIPT_EXT = {".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta"}
LURE_EXT = {".lnk", ".iso", ".img", ".vhd", ".vhdx", ".url", ".chm"}
DECOY_EXT = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".jpg", ".jpeg",
             ".png", ".gif", ".txt", ".mp3", ".mp4", ".avi", ".mkv", ".zip", ".rar"}



def load_dotenv(path: Path) -> None:
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        key = key.strip().removeprefix("export ").strip()
        os.environ.setdefault(key, val.strip().strip('"').strip("'"))


def ts_iso(ts):
    try:
        return datetime.fromtimestamp(int(ts), timezone.utc).isoformat(timespec="seconds")
    except (ValueError, OSError, OverflowError, TypeError):
        return None


def human(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return str(n)


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return round(-sum(c / n * math.log2(c / n) for c in Counter(data).values()), 3)


def hashes(data: bytes) -> dict:
    return {"md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest()}


def uniq(items):
    return list(dict.fromkeys(items))


def sig(sid: str, severity: str, detail: str, fp_note: str | None = None) -> dict:
    s = {"id": sid, "severity": severity, "detail": detail}
    if fp_note:
        s["fp_note"] = fp_note
    return s


def clip(text: str, limit: int = 12000) -> str:
    return text if len(text) <= limit else text[:limit] + f"\n... [truncated, {len(text) - limit} more chars]"
