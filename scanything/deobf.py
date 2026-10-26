"""FLOSS-style static recovery of hidden strings.

Covers x86 stack strings, single-byte XOR, base64 blobs and encoded PowerShell.
Reads bytes only: nothing here executes, emulates or imports the sample.
"""
from __future__ import annotations

import base64
import binascii
import re
from itertools import islice

from .util import sig

SCAN_LIMIT = 64 * 1024 * 1024
TEXT_MAX = 300
STACK_GAP = 16              # max bytes between two stack-slot writes that still belong to one string
MAX_STACK_WRITES = 200_000  # per instruction form
MAX_B64_TOKENS = 20_000
PER_PROBE_HITS = 16         # per (key, probe) pair
STACK_SIGNAL_MIN = 3        # stack strings needed before it is a signal (short hits are often noise)

XOR_PROBES = [
    b"http://", b"https://", b"This program cannot", b"powershell", b"cmd.exe", b"kernel32",
    b"CreateProcess", b"VirtualAlloc", b".onion", b"HKEY_",
    b"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
]

# Printable ASCII only (0x20-0x7e); everything else is deleted when counting ratios.
_NON_PRINT = bytes(c for c in range(256) if not 0x20 <= c <= 0x7E)
_PRINTABLE = re.compile(rb"[\x20-\x7e]+")
_RUN = re.compile(rb"[\x20-\x7e]{6,}")
_B64_RE = re.compile(rb"[A-Za-z0-9+/]{24,}={0,2}")
_PS_RE = re.compile(r"(?<!\S)-e(?:ncodedcommand|nc)?\s+([A-Za-z0-9+/=]{16,})", re.IGNORECASE)

# Immediate bytes are group 1, in memory order (imm32 is already little-endian bytes).
_STACK_RES = [
    re.compile(rb"\xC6\x45.(.)", re.DOTALL),         # mov byte [ebp+disp8], imm8
    re.compile(rb"\xC6\x85.{4}(.)", re.DOTALL),      # mov byte [ebp+disp32], imm8
    re.compile(rb"\xC6\x44\x24.(.)", re.DOTALL),     # mov byte [esp+disp8], imm8
    re.compile(rb"\xC7\x45.(.{4})", re.DOTALL),      # mov dword [ebp+disp8], imm32
    re.compile(rb"\xC7\x44\x24.(.{4})", re.DOTALL),  # mov dword [esp+disp8], imm32
]


def _clip(text: str) -> str:
    return text[:TEXT_MAX]


def _ascii_ratio(b: bytes) -> float:
    if not b:
        return 0.0
    return len(b.translate(None, _NON_PRINT)) / len(b)


def _utf16_like(b: bytes) -> bool:
    odd = b[1::2]
    return len(b) >= 8 and len(odd) > 0 and odd.count(0) >= 0.9 * len(odd)


def _b64decode(tok: bytes) -> bytes | None:
    """Fix padding (drop a dangling char, re-pad) and decode strictly."""
    s = tok.rstrip(b"=")
    if len(s) % 4 == 1:
        s = s[:-1]
    s += b"=" * (-len(s) % 4)
    try:
        return base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        return None


# --- 1. stack strings -------------------------------------------------------

def _stack_candidates(stream: bytes):
    if _utf16_like(stream):
        stream = stream[0::2]
    for seg in stream.split(b"\x00"):
        for m in _RUN.finditer(seg):
            yield m.group().decode("ascii")


def _stack_strings(data: bytes, max_items: int) -> list[dict]:
    writes = []
    for rx in _STACK_RES:
        for m in islice(rx.finditer(data), MAX_STACK_WRITES):
            writes.append((m.start(), m.end(), m.group(1)))
    writes.sort(key=lambda w: w[0])

    groups: list[list] = []
    for start, end, imm in writes:
        if groups and start - groups[-1][1] <= STACK_GAP:
            groups[-1][1] = end
            groups[-1][2].append(imm)
        else:
            groups.append([start, end, [imm]])

    out: list[dict] = []
    seen: set[str] = set()
    for start, _end, parts in groups:
        for text in _stack_candidates(b"".join(parts)):
            if text in seen:
                continue
            seen.add(text)
            out.append({"offset": start, "text": _clip(text)})
            if len(out) >= max_items:
                return out
    return out


# --- 2. single-byte XOR -----------------------------------------------------

def _adjacent_xor(b: bytes) -> bytes:
    """byte i = b[i] ^ b[i+1]. Single-byte XOR cancels out here, so one search covers all 255 keys."""
    n = len(b)
    x = int.from_bytes(b, "big") ^ int.from_bytes(b[1:] + b"\0", "big")
    return x.to_bytes(n, "big")


def _xor_strings(data: bytes, max_items: int) -> list[dict]:
    found: list[tuple[int, int, str]] = []
    if len(data) < 2:
        return []
    diff = _adjacent_xor(data)
    for probe in XOR_PROBES:
        pattern = _adjacent_xor(probe)[:-1]
        hits: dict[int, int] = {}
        pos = diff.find(pattern)
        while pos != -1:
            key = data[pos] ^ probe[0]
            if key and hits.get(key, 0) < PER_PROBE_HITS:
                hits[key] = hits.get(key, 0) + 1
                table = bytes(i ^ key for i in range(256))
                raw = data[pos:pos + TEXT_MAX]
                raw = raw[:raw.find(b"\0")] if b"\0" in raw else raw  # unencoded padding is not part of it
                window = raw.translate(table)
                if window.startswith(probe):
                    run = _PRINTABLE.match(window)
                    if run:
                        found.append((pos, key, run.group().decode("ascii")))
            pos = diff.find(pattern, pos + 1)

    found.sort()
    out: list[dict] = []
    seen: set[str] = set()
    for pos, key, text in found:
        text = _clip(text)
        if text in seen:
            continue
        seen.add(text)
        out.append({"key": key, "offset": pos, "text": text})
        if len(out) >= max_items:
            break
    return out


# --- 3. base64 ----------------------------------------------------------------

def _classify(raw: bytes) -> tuple[str, str] | None:
    if raw[:2] == b"MZ":
        return "pe", f"embedded PE, {len(raw)} bytes"
    if _utf16_like(raw):
        if _ascii_ratio(raw[0::2]) >= 0.9:
            return "utf16", raw.decode("utf-16-le", errors="replace")
        return None
    if len(raw) >= 12 and _ascii_ratio(raw) >= 0.9:
        return "text", raw.decode("ascii", errors="replace")
    return None


def _base64_items(data: bytes, max_items: int) -> list[dict]:
    out: list[dict] = []
    seen: set[str] = set()
    for n, m in enumerate(_B64_RE.finditer(data)):
        if n >= MAX_B64_TOKENS or len(out) >= max_items:
            break
        tok = m.group()
        raw = _b64decode(tok)
        if not raw:
            continue
        verdict = _classify(raw)
        if verdict is None:
            continue
        kind, text = verdict
        text = _clip(text)
        if text in seen:
            continue
        seen.add(text)
        out.append({"source": tok[:60].decode("ascii"), "text": text, "kind": kind})
    return out


# --- 4. PowerShell -E / -EncodedCommand ----------------------------------------

def _powershell_items(data: bytes, max_items: int) -> list[dict]:
    out: list[dict] = []
    seen: set[str] = set()
    for m in _PS_RE.finditer(data.decode("latin-1")):
        if len(out) >= max_items:
            break
        raw = _b64decode(m.group(1).encode("ascii"))
        if not raw:
            continue
        text = raw.decode("utf-16-le", errors="replace")
        if not text or sum(1 for c in text if c.isprintable() or c in "\r\n\t") < 0.9 * len(text):
            continue
        text = _clip(text)
        if text in seen:
            continue
        seen.add(text)
        out.append({"text": text})
    return out


# --- public API ---------------------------------------------------------------

def recover(data: bytes, max_items: int = 200) -> dict:
    """Recover hidden strings from the first 64 MiB of ``data``. Each list is capped at ``max_items``."""
    blob = bytes(data[:SCAN_LIMIT])
    return {
        "stack_strings": _stack_strings(blob, max_items),
        "xor": _xor_strings(blob, max_items),
        "base64": _base64_items(blob, max_items),
        "powershell": _powershell_items(blob, max_items),
    }


def recovered_strings(result: dict) -> list[str]:
    """Flatten every recovered text in a fixed order, deduplicated, for IOC scanning."""
    out: list[str] = []
    seen: set[str] = set()
    for key in ("stack_strings", "xor", "base64", "powershell"):
        for item in result.get(key, []):
            text = item["text"]
            if text and text not in seen:
                seen.add(text)
                out.append(text)
    return out


def signals(result: dict) -> list[dict]:
    """Signals from a recover() result. Decoded text itself goes through the normal IOC rules too."""
    out = []
    stack = result.get("stack_strings", [])
    if len(stack) >= STACK_SIGNAL_MIN:
        out.append(sig("stack_strings", "low", f"{len(stack)} strings built on the stack, e.g. "
                       f"{[s['text'] for s in stack[:3]]}",
                       "Compilers sometimes inline small constant arrays this way; meaningful when the "
                       "strings are URLs, API names or commands"))
    if xor := result.get("xor"):
        out.append(sig("xor_encoded_strings", "medium", f"{len(xor)} single-byte-XOR strings, e.g. key "
                       f"0x{xor[0]['key']:02x}: {xor[0]['text'][:80]!r}",
                       "A few games, DRM and license checks XOR their strings; hiding URLs or an embedded "
                       "PE this way is typical of malware"))
    pes = [b for b in result.get("base64", []) if b["kind"] == "pe"]
    if pes:
        out.append(sig("base64_payload", "medium", f"{len(pes)} base64-encoded PE file(s) embedded",
                       "Some installers and test suites embed binaries as base64; rare elsewhere"))
    if ps := result.get("powershell"):
        out.append(sig("encoded_powershell", "medium", f"PowerShell -EncodedCommand decodes to: "
                       f"{ps[0]['text'][:120]!r}",
                       "Admin and deployment tools sometimes use -EncodedCommand to avoid quoting issues; "
                       "read the decoded command"))
    return out
