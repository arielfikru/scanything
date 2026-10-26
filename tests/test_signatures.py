"""Signature database tests. Synthetic harmless bytes only."""
from __future__ import annotations

import re
import struct

from scanything.signatures import KIND_FP, KINDS, SIGNATURES, detect, rich_header
from tests.fixtures import make_pe


def names(found):
    return [r["name"] for r in found]


def test_upx_sections_detected():
    sections = [{"name": "UPX0"}, {"name": "UPX1"}]
    found = detect(b"MZ" + b"\x00" * 62, {"sections": sections})
    assert "UPX" in names(found)
    assert next(r for r in found if r["name"] == "UPX")["kind"] == "packer"


def test_nsis_marker_in_pe_bytes():
    data = make_pe(strings=b"Nullsoft Install System v3.08")
    found = detect(data, None)
    assert "NSIS installer" in names(found)
    assert next(r for r in found if r["name"] == "NSIS installer")["kind"] == "installer"


def test_pyinstaller_marker():
    data = make_pe(strings=b"_MEIPASS\x00pyi-runtime-tmpdir")
    assert "PyInstaller" in names(detect(data, None))


def test_vb6_import_case_insensitive():
    found = detect(make_pe(), {"imported_dlls": ["MSVBVM60.DLL"]})
    assert "Visual Basic 6" in names(found)
    assert "Visual Basic 6" not in names(detect(make_pe(), {"imported_dlls": ["kernel32.dll"]}))


def test_dotnet_from_pe_dict():
    found = detect(make_pe(), {"is_dotnet": True})
    dotnet = [r for r in found if r["name"] == ".NET"]
    assert len(dotnet) == 1
    assert dotnet[0]["kind"] == "runtime"
    assert "CLR" in dotnet[0]["evidence"]


def test_dotnet_dedup_with_mscoree_import():
    found = detect(make_pe(), {"is_dotnet": True, "imported_dlls": ["mscoree.dll"]})
    assert names(found).count(".NET") == 1


def make_rich_pe(entries, key=0x12345678) -> bytes:
    """Hand-built file: MZ, e_lfanew=0x100, Rich header at 0x80, PE signature at 0x100."""
    buf = bytearray(0x200)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x100)
    struct.pack_into("<I", buf, 0x80, struct.unpack("<I", b"DanS")[0] ^ key)
    for off in (0x84, 0x88, 0x8C):
        struct.pack_into("<I", buf, off, key)
    off = 0x90
    for prod_id, build, count in entries:
        struct.pack_into("<I", buf, off, ((prod_id << 16) | build) ^ key)
        struct.pack_into("<I", buf, off + 4, count ^ key)
        off += 8
    buf[off:off + 4] = b"Rich"
    struct.pack_into("<I", buf, off + 4, key)
    buf[0x100:0x104] = b"PE\x00\x00"
    return bytes(buf)


def test_rich_header_parsed_and_msvc_detected():
    data = make_rich_pe([(0x0103, 0x7A1B, 7)], key=0x12345678)
    rich = rich_header(data)
    assert rich == {"key": "12345678", "entries": [{"prod_id": 0x0103, "build": 0x7A1B, "count": 7}]}
    found = detect(data, None)
    msvc = [r for r in found if r["name"] == "Microsoft Visual C++"]
    assert msvc == [{"name": "Microsoft Visual C++", "kind": "compiler", "evidence": "Rich header (1 entries)"}]


def test_rich_header_absent_returns_none():
    assert rich_header(make_pe()) is None
    assert rich_header(b"not a pe at all") is None


def test_rich_header_truncated_is_safe():
    data = make_rich_pe([(0x0103, 0x7A1B, 7)])
    for cut in (10, 0x40, 0x90, 0x9C):
        assert rich_header(data[:cut]) is None


def test_plain_text_yields_nothing():
    assert detect(b"hello world, just a plain text file.\n" * 20, None) == []
    assert detect(b"hello", {}) == []


def test_each_marker_is_listed_once():
    data = make_pe(sections=[(".ndata", b"\x00" * 16, 0xC0000040)],
                   strings=b"Nullsoft Install System")
    found = detect(data, {"sections": [{"name": ".ndata"}]})
    assert names(found).count("NSIS installer") == 1


def test_signature_database_is_well_formed():
    assert len(SIGNATURES) >= 40
    seen = set()
    for sig in SIGNATURES:
        assert sig["name"] not in seen, sig["name"]
        seen.add(sig["name"])
        assert sig["kind"] in KINDS, sig["name"]
        indicators = sig.get("bytes", []) + sig.get("sections", []) + sig.get("dlls", [])
        assert indicators, sig["name"]
        for rx in sig.get("bytes", []):
            assert isinstance(rx, bytes), sig["name"]
            re.compile(rx)
        for dll in sig.get("dlls", []):
            assert dll == dll.lower(), sig["name"]
    assert set(KIND_FP) >= set(KINDS)
