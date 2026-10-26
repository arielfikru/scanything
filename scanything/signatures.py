"""Detect-It-Easy style signature database: compilers, runtimes, installers, packers, protectors.

Pure matching, never executes anything. Byte regexes run over the first 64 MiB of the file only.
Each entry matches if ANY of its indicators matches:
  bytes    - regex searched in the raw file bytes
  sections - exact PE section names
  dlls     - lower-case imported DLL names
"""
from __future__ import annotations

import re
import struct

SCAN_LIMIT = 64 * 1024 * 1024
KINDS = ("compiler", "runtime", "installer", "sfx", "packer", "protector", "obfuscator")

SIGNATURES: list[dict] = [
    # --- installers / archives ---
    {"name": "NSIS installer", "kind": "installer",  # source: NSIS stub strings and .ndata section
     "bytes": [rb"Nullsoft Install System|NullsoftInst"], "sections": [".ndata"]},
    {"name": "Inno Setup installer", "kind": "installer",  # source: Inno Setup setup loader string
     "bytes": [rb"Inno Setup"]},
    {"name": "InstallShield", "kind": "installer",  # source: InstallShield runtime string
     "bytes": [rb"InstallShield"]},
    {"name": "Squirrel installer", "kind": "installer",  # source: Squirrel.Windows setup stub
     "bytes": [rb"SquirrelSetup|Squirrel\.Windows"]},
    {"name": "WiX burn bundle", "kind": "installer",  # source: WiX bundle engine (.wixburn section)
     "bytes": [rb"WixBundle|WixStdBA"], "sections": [".wixburn"]},
    {"name": "Advanced Installer", "kind": "installer",  # source: Advanced Installer stub string (medium confidence)
     "bytes": [rb"Advanced Installer"]},
    {"name": "7-Zip SFX", "kind": "sfx",  # source: 7-Zip SFX config header ";!@Install@!UTF-8!"
     "bytes": [rb";!@Install@!UTF-8!"]},

    # --- runtimes / bootloaders / languages ---
    {"name": "PyInstaller", "kind": "runtime",  # source: PyInstaller bootloader strings
     "bytes": [rb"_MEIPASS|pyi-runtime-tmpdir|PyInstaller"]},
    {"name": "Nuitka", "kind": "runtime",  # source: Nuitka onefile launcher strings
     "bytes": [rb"NUITKA_ONEFILE|nuitka"]},
    {"name": "AutoIt", "kind": "runtime",  # source: AutoIt compiled script header / version string
     "bytes": [rb"AU3!EA06|AutoIt v3"]},
    {"name": "AutoHotkey", "kind": "runtime",  # source: AutoHotkey compiled script marker
     "bytes": [rb">AUTOHOTKEY SCRIPT<"]},
    {"name": "Electron", "kind": "runtime",  # source: Electron runtime file names
     "bytes": [rb"electron\.asar|Electron Framework"]},
    {"name": "Go", "kind": "runtime",  # source: Go build ID string and buildinfo magic (Go 1.18+)
     "bytes": [rb"Go build ID: \"", rb"\xff Go buildinf:"]},
    {"name": "Rust", "kind": "runtime",  # source: rustc panic/source paths embed a 40-hex commit hash
     "bytes": [rb"/rustc/[0-9a-f]{40}"]},
    {"name": "Visual Basic 6", "kind": "compiler",  # source: VB6 runtime DLL import
     "dlls": ["msvbvm60.dll"]},
    {"name": "Delphi/Borland", "kind": "compiler",  # source: Borland/Delphi strings, FastMM memory manager, Delphi registry key
     "bytes": [rb"Borland|FastMM|SOFTWARE\\Borland\\Delphi"]},
    {"name": "Free Pascal", "kind": "compiler",  # source: FPC runtime string (medium confidence)
     "bytes": [rb"Free Pascal"]},
    {"name": "MinGW/GCC", "kind": "compiler",  # source: GCC version string and MinGW runtime symbols
     "bytes": [rb"GCC: \(", rb"mingw"]},
    {"name": ".NET", "kind": "runtime",  # source: mscoree.dll import (_CorExeMain/_CorDllMain); also CLR header via detect()
     "dlls": ["mscoree.dll"]},
    {"name": "Qt", "kind": "runtime",  # source: Qt core DLL import names (Qt5/Qt6)
     "dlls": ["qt5core.dll", "qt6core.dll"]},
    {"name": "CEF (Chromium Embedded)", "kind": "runtime",  # source: libcef.dll import
     "dlls": ["libcef.dll"]},
    {"name": "Python (embedded runtime)", "kind": "runtime",  # source: CPython stable-ABI and versioned DLL imports
     "dlls": ["python3.dll"] + [f"python3{m}.dll" for m in range(6, 15)]},

    # --- packers ---
    {"name": "UPX", "kind": "packer",  # source: UPX magic and default section names
     "bytes": [rb"UPX!"], "sections": ["UPX0", "UPX1"]},
    {"name": "ASPack", "kind": "packer",  # source: ASPack section names
     "sections": [".aspack", ".adata"]},
    {"name": "PECompact", "kind": "packer",  # source: PECompact stub marker and section name (medium confidence)
     "bytes": [rb"PECompact2"], "sections": ["pec1", "pec2"]},
    {"name": "MPRESS", "kind": "packer",  # source: MPRESS section names
     "sections": [".MPRESS1", ".MPRESS2", "MPRESS1"]},
    {"name": "Petite", "kind": "packer",  # source: Petite section name
     "sections": [".petite"]},
    {"name": "NsPack", "kind": "packer",  # source: NsPack section names
     "sections": [".nsp0", ".nsp1", ".nsp2"]},
    {"name": "FSG", "kind": "packer",  # source: FSG stub marker (medium confidence)
     "bytes": [rb"FSG!"]},
    {"name": "MEW", "kind": "packer",  # source: MEW section name (medium confidence)
     "sections": ["MEW"]},

    # --- protectors ---
    {"name": "Themida/WinLicense", "kind": "protector",  # source: Themida/WinLicense strings and section names
     "bytes": [rb"Themida|WinLicense"], "sections": [".themida", ".winlice"]},
    {"name": "VMProtect", "kind": "protector",  # source: VMProtect section names
     "sections": [".vmp0", ".vmp1", ".vmp2"]},
    {"name": "Enigma Protector", "kind": "protector",  # source: Enigma Protector section names
     "sections": [".enigma1", ".enigma2"]},
    {"name": "Armadillo", "kind": "protector",  # source: Armadillo stub strings (medium confidence)
     "bytes": [rb"Armadillo"]},
    {"name": "ConfuserEx", "kind": "protector",  # source: ConfuserEx / Confuser.Core attribute strings
     "bytes": [rb"ConfuserEx|Confuser\.Core"]},

    # --- .NET obfuscators ---
    {"name": "Eazfuscator.NET", "kind": "obfuscator",  # source: Eazfuscator attribute string
     "bytes": [rb"Eazfuscator"]},
    {"name": "SmartAssembly", "kind": "obfuscator",  # source: SmartAssembly attribute type name
     "bytes": [rb"SmartAssembly\.Attributes"]},
    {"name": "Babel.NET", "kind": "obfuscator",  # source: Babel obfuscator attribute name (medium confidence)
     "bytes": [rb"BabelAttribute"]},
    {"name": "Dotfuscator", "kind": "obfuscator",  # source: Dotfuscator attribute type name
     "bytes": [rb"DotfuscatorAttribute"]},
    {"name": "PyArmor", "kind": "obfuscator",  # source: PyArmor runtime module names (medium confidence)
     "bytes": [rb"pyarmor_runtime|PyArmor"]},
]

KIND_FP: dict[str, str] = {
    "compiler": "Informational only: the toolchain says nothing about intent; most legitimate and malicious "
                "binaries share the same compiler",
    "installer": "Installer stub: the verdict depends on the payload it installs; some AVs flag NSIS/Inno generically",
    "sfx": "Self-extracting archives are a common delivery format for both installers and droppers; "
           "the verdict depends on the payload",
    "runtime": "PyInstaller/Nuitka/AutoIt/Go binaries are often flagged generically because malware uses the same "
               "runtime/bootloader - a classic false-positive source",
    "packer": "Legit tools use UPX & co., but packing alone triggers heuristic/ML detections",
    "protector": "Commercial apps & games use protectors (anti-piracy/anti-cheat); malware uses them too",
    "obfuscator": "Commercial .NET apps obfuscate to protect their IP, so an obfuscator alone is not malicious; "
                  "malware uses the same tools",
}

_DANS = struct.unpack("<I", b"DanS")[0]


def rich_header(data: bytes) -> dict | None:
    """Parse the MSVC 'Rich' header between the DOS stub and the PE header. Returns None if absent or malformed."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    limit = min(e_lfanew, len(data))
    end = limit
    while True:
        pos = data.rfind(b"Rich", 0, end)
        if pos < 0:
            return None
        if pos + 8 > limit:  # key would run past the PE header; try an earlier marker
            end = pos
            continue
        key = struct.unpack_from("<I", data, pos + 4)[0]
        # Walk backwards from the 'Rich' marker looking for the XOR-encoded 'DanS' start marker.
        dans = None
        for off in range(pos - 4, 0x3F, -4):
            if struct.unpack_from("<I", data, off)[0] ^ key == _DANS:
                dans = off
                break
        if dans is not None and dans + 16 <= pos:
            entries = []
            for off in range(dans + 16, pos, 8):
                comp = struct.unpack_from("<I", data, off)[0] ^ key
                count = struct.unpack_from("<I", data, off + 4)[0] ^ key
                entries.append({"prod_id": comp >> 16, "build": comp & 0xFFFF, "count": count})
            return {"key": f"{key:08x}", "entries": entries}
        end = pos  # not a valid header at this 'Rich'; keep looking further back


def detect(data: bytes, pe: dict | None) -> list[dict]:
    """Return [{"name", "kind", "evidence"}], deduplicated by name, in SIGNATURES order."""
    pe = pe or {}
    window = data[:SCAN_LIMIT]
    sections = {s.get("name") for s in pe.get("sections", []) or []}
    dlls = {d.lower() for d in pe.get("imported_dlls", []) or []}
    found: dict[str, dict] = {}

    for sig in SIGNATURES:
        evidence = None
        for rx in sig.get("bytes", []):
            m = re.search(rx, window)
            if m:
                evidence = f"bytes {m.group(0)[:40]!r}"
                break
        if evidence is None:
            hit = [s for s in sig.get("sections", []) if s in sections]
            if hit:
                evidence = f"section {hit[0]}"
        if evidence is None:
            hit = [d for d in sig.get("dlls", []) if d in dlls]
            if hit:
                evidence = f"import {hit[0]}"
        if evidence is not None:
            found[sig["name"]] = {"name": sig["name"], "kind": sig["kind"], "evidence": evidence}

    if pe.get("is_dotnet"):
        found[".NET"] = {"name": ".NET", "kind": "runtime", "evidence": "CLR header (COM descriptor directory)"}

    order = {sig["name"]: i for i, sig in enumerate(SIGNATURES)}
    results = sorted(found.values(), key=lambda r: order.get(r["name"], len(order)))

    rich = rich_header(data)
    if rich is not None:
        results.append({"name": "Microsoft Visual C++", "kind": "compiler",
                        "evidence": f"Rich header ({len(rich['entries'])} entries)"})
    return results
