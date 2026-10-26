"""Harmless fixture builders (no pytest dependency, also used by scripts/)."""
from __future__ import annotations

import io
import struct
import zipfile

DOS_STUB = b"This program cannot be run in DOS mode.\r\r\n$"


def make_pe(sections=None, strings: bytes = b"", timestamp: int = 1_700_000_000,
            cert: bytes | None = None, overlay: bytes = b"") -> bytes:
    """Minimal valid PE32 (no imports). `sections` = [(name, data, characteristics)]."""
    sections = sections or [(".text", b"\xc3" + strings, 0x60000020)]
    falign, salign = 0x200, 0x1000
    headers = bytearray(0x400)
    headers[0:2] = b"MZ"
    struct.pack_into("<I", headers, 0x3C, 0x80)
    headers[0x40:0x40 + len(DOS_STUB)] = DOS_STUB
    headers[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", headers, 0x84, 0x14C, len(sections), timestamp, 0, 0, 224, 0x0102)

    raw, rawptr, va = [], 0x400, 0x1000
    sec_table = []
    for name, data, chars in sections:
        size = (len(data) + falign - 1) // falign * falign or falign
        sec_table.append((name.encode()[:8].ljust(8, b"\x00"), len(data), va, size, rawptr, chars))
        raw.append(data.ljust(size, b"\x00"))
        rawptr += size
        va += (len(data) + salign - 1) // salign * salign or salign
    body = b"".join(raw)
    cert_off = 0x400 + len(body) + len(overlay)

    opt = struct.pack("<HBB" + "I" * 9 + "H" * 6 + "I" * 4 + "HH" + "I" * 6,
                      0x10B, 14, 0, len(sections[0][1]), 0, 0, 0x1000, 0x1000, 0, 0x400000, salign, falign,
                      6, 0, 0, 0, 6, 0, 0, va, 0x400, 0, 2, 0, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    dirs = bytearray(16 * 8)
    if cert:
        struct.pack_into("<II", dirs, 4 * 8, cert_off, len(cert))
    headers[0x98:0x98 + 96] = opt
    headers[0x98 + 96:0x98 + 224] = dirs
    off = 0x98 + 224
    for name, vsize, sva, rsize, rptr, chars in sec_table:
        struct.pack_into("<8sIIIIIIHHI", headers, off, name, vsize, sva, rsize, rptr, 0, 0, 0, 0, chars)
        off += 40
    return bytes(headers) + body + overlay + (cert or b"")


def make_zip(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buf.getvalue()
