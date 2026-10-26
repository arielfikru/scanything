"""Static analyzers: file type, strings/IOCs, PE structure. Nothing here executes the sample."""
from __future__ import annotations

import ipaddress
import re
import struct
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    import pefile  # recommended: pip install pefile
except ImportError:
    pefile = None

from .signatures import KIND_FP
from .util import (DECOY_EXT, ENTROPY_SAMPLE, EXEC_EXT, LURE_EXT, SCRIPT_EXT, entropy, human,
                   sig, ts_iso, uniq)


def detect_type(data: bytes, name: str) -> str:
    ext = Path(name).suffix.lower()
    head = data[:8]
    if head[:2] == b"MZ":
        return "pe"
    if head[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
        return "zip"
    if head[:6] == b"7z\xbc\xaf\x27\x1c":
        return "7z"
    if head[:4] == b"Rar!":
        return "rar"
    if head[:4] == b"\x7fELF":
        return "elf"
    if head[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
        return "macho"
    if head[:4] == b"%PDF":
        return "pdf"
    if head == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "ole"  # .msi or legacy Office
    if head[:4] == b"L\x00\x00\x00":
        return "lnk"
    if head[:4] == b"MSCF":
        return "cab"
    if data[0x8001:0x8006] == b"CD001":
        return "iso"
    if ext in SCRIPT_EXT:
        return "script"
    sample = data[:4096]
    if sample and sum(32 <= b < 127 or b in (9, 10, 13) for b in sample) / len(sample) > 0.95:
        return "text"
    return "data"


# ----------------------------------------------------------------- strings & IOCs

ASCII_RE = re.compile(rb"[\x20-\x7e]{5,}")
UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){5,}")
URL_RE = re.compile(r"(?i)\b(?:https?|ftp)://[^\s\"'<>()\\^`{}|]{4,200}")
IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
REG_RE = re.compile(r"(?i)\b(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS)|HKLM|HKCU)\\[^\s\"']{3,200}")
BENIGN_URL_RE = re.compile(r"(?i)(digicert|verisign|symantec|sectigo|comodoca|usertrust|globalsign|"
                           r"godaddy|entrust|thawte|letsencrypt|ocsp\.|crl\.|schemas\.microsoft\.com|"
                           r"www\.microsoft\.com/pki|w3\.org|xmlsoap\.org|purl\.org|adobe\.com/xap|"
                           r"nsis\.sf\.net|jrsoftware\.org|apache\.org/licenses|gnu\.org)")
SHADY_HOST_RE = re.compile(r"(?i)(pastebin\.com|paste\.ee|hastebin|rentry\.co|transfer\.sh|"
                           r"anonfiles|gofile\.io|mediafire\.com|cdn\.discordapp\.com|"
                           r"discord(app)?\.com/api/webhooks|api\.telegram\.org|ngrok|trycloudflare\.com|"
                           r"raw\.githubusercontent\.com|bit\.ly|tinyurl|iplogger|duckdns|no-ip|\.onion\b)")

# (id, severity, label, regex, false-positive note)
SUS_PATTERNS = [
    ("powershell_obfuscated", "high", "PowerShell hidden/encoded/download cradle",
     r"(?i)powershell[^\n]{0,80}(-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{16}|-w(indowstyle)?\s+hid|"
     r"downloadstring|downloadfile|iex\b|invoke-expression|frombase64string)",
     "Admin/deployment tools sometimes embed PowerShell, but hidden+encoded is rare in legit apps"),
    ("lolbin_download", "high", "LOLBin download/execute (certutil/bitsadmin/mshta/regsvr32)",
     r"(?i)(certutil[^\n]{0,40}-urlcache|bitsadmin[^\n]{0,40}/transfer|mshta(\.exe)?\s+(https?:|vbscript:|javascript:)|"
     r"regsvr32[^\n]{0,40}/i:https?)", None),
    ("shadow_copy_delete", "high", "Shadow copy / recovery deletion (ransomware behaviour)",
     r"(?i)(vssadmin[^\n]{0,30}delete\s+shadows|wmic[^\n]{0,30}shadowcopy\s+delete|"
     r"bcdedit[^\n]{0,40}recoveryenabled\s+no|wbadmin[^\n]{0,20}delete\s+catalog)",
     "Backup/disk tools may reference vssadmin, but deletion + recovery-disable is a ransomware hallmark"),
    ("defender_tamper", "high", "Windows Defender tampering / exclusions",
     r"(?i)(Set-MpPreference[^\n]{0,80}Disable|Add-MpPreference[^\n]{0,40}Exclusion|DisableAntiSpyware|"
     r"DisableRealtimeMonitoring)",
     "Game cheats/cracks often ask to disable AV too - still a red flag"),
    ("ransom_note", "high", "Ransom-note language",
     r"(?i)(your (important )?files (have been|are|were) encrypted|decrypt(ion)? (key|tool)|"
     r"pay[^\n]{0,30}bitcoin|bitcoin wallet|tor browser[^\n]{0,40}\.onion)", None),
    ("stealer_targets", "medium", "Browser / wallet / messenger credential paths (stealer pattern)",
     r"(?i)(\\Login Data\b|\\Local State\b|\\Web Data\b|wallet\.dat|\\Telegram Desktop\\tdata|"
     r"\\discord\\Local Storage|\\Exodus\\|\\Electrum\\|\\MetaMask|Coinomi)",
     "Password managers / browser migration tools read these legitimately"),
    ("exfil_channel", "medium", "Exfiltration channel (Discord webhook / Telegram bot API)",
     r"(?i)(discord(app)?\.com/api/webhooks/\d+|api\.telegram\.org/bot\d+)", None),
    ("miner", "medium", "Crypto-miner indicators",
     r"(?i)(stratum\+(tcp|ssl)://|xmrig|cryptonight|--donate-level|nicehash)",
     "Legit mining software contains these too (then it is PUA, not a virus)"),
    ("persistence", "medium", "Persistence (Run key / scheduled task / startup folder)",
     r"(?i)(\\CurrentVersion\\Run(Once)?\b|schtasks[^\n]{0,20}/create|\\Start Menu\\Programs\\Startup)",
     "Many legit apps register autostart (updaters, tray apps)"),
    ("uac_bypass", "medium", "UAC bypass tricks",
     r"(?i)(fodhelper\.exe|computerdefaults\.exe|eventvwr\.exe[^\n]{0,40}mscfile|ms-settings\\shell\\open\\command)",
     None),
    ("anti_vm", "low", "Anti-VM / sandbox checks",
     r"(?i)(vboxservice|vboxtray|vmtoolsd|sbiedll\.dll|wine_get_unix_file_name|qemu-ga|"
     r"\bwireshark\.exe|procmon|x64dbg|ollydbg)",
     "Anti-cheat, DRM and license protectors also detect VMs/debuggers"),
    ("eicar_test_file", "medium", "EICAR antivirus test string",
     r"EICAR-STANDARD-ANTIVIRUS-TEST-FILE",
     "EICAR is the industry-standard HARMLESS test file: every AV is supposed to flag it; it does nothing"),
    ("prompt_injection", "medium", "Text that tries to instruct an AI/analyst",
     r"(?i)(ignore (all |the )?(previous|prior) instructions|you are (an? )?(ai|assistant|language model)|"
     r"this file is (safe|clean|not malware)|report (this|it) as (safe|clean))",
     None),
]
SUS_COMPILED = [(i, s, l, re.compile(r), fp) for i, s, l, r, fp in SUS_PATTERNS]


def extract_strings(data: bytes, cap: int = 200_000) -> list[str]:
    out = []
    for rx, enc in ((ASCII_RE, "ascii"), (UTF16_RE, "utf-16-le")):
        for m in rx.finditer(data):
            out.append(m.group().decode(enc, "replace")[:500])
            if len(out) >= cap:
                break
    return uniq(out)


def find_iocs(strings: list[str]) -> dict:
    text = "\n".join(strings)
    urls = uniq(u.rstrip(".,;") for u in URL_RE.findall(text))
    notable = [u for u in urls if not BENIGN_URL_RE.search(u)]
    ips = [ip for ip in uniq(IP_RE.findall(text))
           if not ip.startswith(("0.", "127.", "255.")) and max(map(int, ip.split("."))) >= 20]
    hits = []
    for sid, sev, label, rx, fp in SUS_COMPILED:
        samples = uniq(m.group(0)[:120] for m in rx.finditer(text))[:3]
        if samples:
            hits.append({"id": sid, "severity": sev, "label": label, "samples": samples, "fp_note": fp})
    return {
        "url_count": len(urls),
        "notable_urls": notable[:40],
        "shady_urls": [u for u in notable if SHADY_HOST_RE.search(u)][:20],
        "ip_like": ips[:30],
        "registry": uniq(REG_RE.findall(text))[:30],
        "suspicious_strings": hits,
    }


def _public_ip(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_global
    except ValueError:
        return False


def ioc_signals(iocs: dict, urls: bool = True) -> list[dict]:
    """`urls=False` skips URL signals (documentation files link everywhere)."""
    out = [sig(h["id"], h["severity"], f'{h["label"]}: {h["samples"][0]!r}', h["fp_note"])
           for h in iocs["suspicious_strings"]]
    if not urls:
        return out
    if iocs["shady_urls"]:
        out.append(sig("shady_url", "medium", f"Paste/file-hosting/tunnel URLs: {iocs['shady_urls'][:3]}",
                       "Updaters sometimes pull from GitHub raw; context matters"))
    hosts = [(u, u.split("/")[2].rsplit("@", 1)[-1].split(":")[0] if u.count("/") >= 2 else "")
             for u in iocs["notable_urls"]]
    raw_ip_urls = [u for u, h in hosts if IP_RE.fullmatch(h) and _public_ip(h)]  # LAN/loopback IPs are not C2
    if raw_ip_urls:
        out.append(sig("raw_ip_url", "medium", f"URLs pointing to raw IP addresses: {raw_ip_urls[:3]}"))
    return out


def name_signals(name: str) -> list[dict]:
    base = name.replace("\\", "/").rsplit("/", 1)[-1]
    out = []
    if "‮" in base:
        out.append(sig("rlo_filename", "high", f"Right-to-left override char hides the real extension: {base!r}"))
    parts = base.lower().split(".")
    if len(parts) >= 3 and "." + parts[-1] in EXEC_EXT | SCRIPT_EXT | LURE_EXT \
            and "." + parts[-2].strip() in DECOY_EXT:
        out.append(sig("double_extension", "high", f"Decoy double extension: {base!r}"))
    if re.search(r"\s{5,}\.\w{2,4}$", base):
        out.append(sig("padded_extension", "high", f"Whitespace padding hides the extension: {base!r}"))
    return out


# ----------------------------------------------------------------- PE analysis

MACHINES = {0x14C: "x86", 0x8664: "x64", 0x1C0: "ARM", 0xAA64: "ARM64", 0x200: "IA64"}
SUBSYSTEMS = {1: "native", 2: "windows_gui", 3: "windows_console", 9: "wince_gui", 10: "efi_app"}
SEC_DIR, COM_DIR = 4, 14
VERSION_KEYS = {"CompanyName", "ProductName", "FileDescription", "OriginalFilename",
                "InternalName", "LegalCopyright", "FileVersion", "ProductVersion"}
NORMAL_EP_SECTIONS = {".text", "CODE", ".code", "text", ".itext", ""}

SUS_IMPORTS = {
    "process_injection": {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "CreateRemoteThreadEx",
                          "NtCreateThreadEx", "QueueUserAPC", "NtQueueApcThread", "SetThreadContext",
                          "NtUnmapViewOfSection", "ZwUnmapViewOfSection", "RtlCreateUserThread",
                          "NtWriteVirtualMemory"},
    "keylogging": {"SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState", "GetKeyboardState",
                   "GetKeyState", "RegisterRawInputDevices"},
    "screen_capture": {"BitBlt", "GetDC", "CreateCompatibleBitmap"},
    "download_exec": {"URLDownloadToFileA", "URLDownloadToFileW", "URLDownloadToCacheFileA",
                      "URLDownloadToCacheFileW"},
    "network": {"InternetOpenA", "InternetOpenW", "InternetOpenUrlA", "InternetOpenUrlW", "WinHttpOpen",
                "WSAStartup", "HttpSendRequestA", "HttpSendRequestW", "InternetReadFile"},
    "anti_debug": {"IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
                   "OutputDebugStringA", "NtSetInformationThread"},
    "crypto": {"CryptEncrypt", "CryptGenKey", "BCryptEncrypt", "CryptAcquireContextA", "CryptAcquireContextW",
               "CryptImportKey"},
    "service_or_registry": {"CreateServiceA", "CreateServiceW", "RegSetValueExA", "RegSetValueExW",
                            "RegCreateKeyExA", "RegCreateKeyExW"},
    "privilege": {"AdjustTokenPrivileges", "OpenProcessToken", "LookupPrivilegeValueA", "LookupPrivilegeValueW"},
    "process_enum": {"CreateToolhelp32Snapshot", "Process32First", "Process32FirstW", "Process32Next",
                     "Process32NextW", "EnumProcesses"},
}

def cert_names(blob: bytes) -> list[str]:
    """CommonName values from a PKCS#7 blob (subjects and issuers). Not a verification."""
    names = []
    for m in re.finditer(rb"\x06\x03\x55\x04\x03([\x0c\x13\x14\x16\x1e])(.)", blob, re.S):
        tag, ln = m.group(1), m.group(2)[0]
        if ln & 0x80:
            continue
        raw = blob[m.end():m.end() + ln]
        try:
            names.append(raw.decode("utf-16-be" if tag == b"\x1e" else "utf-8"))
        except UnicodeDecodeError:
            continue
    return uniq(names)[:10]


def version_info(pe) -> dict:
    out = {}
    for fi in getattr(pe, "FileInfo", None) or []:
        for entry in (fi if isinstance(fi, list) else [fi]):
            for table in getattr(entry, "StringTable", None) or []:
                for k, v in table.entries.items():
                    k = k.decode("utf-8", "replace") if isinstance(k, bytes) else k
                    v = v.decode("utf-8", "replace") if isinstance(v, bytes) else v
                    if k in VERSION_KEYS and v:
                        out[k] = v[:200]
    return out


def classify_imports(imports: dict) -> dict:
    names = {n for funcs in imports.values() for n in funcs}
    return {cat: sorted(names & fns) for cat, fns in SUS_IMPORTS.items() if names & fns}


def analyze_pe(data: bytes) -> dict:
    if pefile is None:
        return pe_minimal(data)
    try:
        pe = pefile.PE(data=data, fast_load=False)
    except Exception as e:  # pefile raises PEFormatError and assorted struct errors
        return {"error": f"PE parse failed: {e}"}
    try:
        fh, oh = pe.FILE_HEADER, pe.OPTIONAL_HEADER
        dd = oh.DATA_DIRECTORY
        r = {
            "parser": "pefile",
            "machine": MACHINES.get(fh.Machine, hex(fh.Machine)),
            "is_64bit": oh.Magic == 0x20B,
            "is_dll": bool(fh.Characteristics & 0x2000),
            "subsystem": SUBSYSTEMS.get(oh.Subsystem, oh.Subsystem),
            "timestamp_raw": fh.TimeDateStamp,
            "compile_time": ts_iso(fh.TimeDateStamp),
            "is_dotnet": len(dd) > COM_DIR and dd[COM_DIR].VirtualAddress != 0,
            "sections": [],
        }
        ep = oh.AddressOfEntryPoint
        r["ep_section"] = None
        for s in pe.sections:
            name = s.Name.rstrip(b"\x00").decode("latin-1")
            ch = s.Characteristics
            r["sections"].append({"name": name, "virtual_size": s.Misc_VirtualSize, "raw_size": s.SizeOfRawData,
                                  "entropy": round(s.get_entropy(), 3), "writable": bool(ch & 0x80000000),
                                  "executable": bool(ch & 0x20000000)})
            if s.contains_rva(ep):
                r["ep_section"] = name

        imports = {}
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", None) or []:
            dll = entry.dll.decode("latin-1") if entry.dll else "?"
            imports.setdefault(dll, []).extend(
                i.name.decode("latin-1") if i.name else f"ord{i.ordinal}" for i in entry.imports)
        r["imports"] = imports
        r["imported_dlls"] = list(imports)
        r["import_count"] = sum(len(v) for v in imports.values())
        r["suspicious_imports"] = classify_imports(imports)
        try:
            r["imphash"] = pe.get_imphash() or None
        except Exception:
            r["imphash"] = None
        exp = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
        r["exports"] = [e.name.decode("latin-1") for e in exp.symbols if e.name][:50] if exp else []

        sec_off = sec_end = None
        if len(dd) > SEC_DIR and dd[SEC_DIR].VirtualAddress and dd[SEC_DIR].Size:
            sec_off, sec_end = dd[SEC_DIR].VirtualAddress, dd[SEC_DIR].VirtualAddress + dd[SEC_DIR].Size
            r["signature_present"] = True
            r["certificate_names"] = cert_names(data[sec_off:sec_end])
        else:
            r["signature_present"] = False
        r["version_info"] = version_info(pe)

        ov_off = pe.get_overlay_data_start_offset()
        if ov_off:
            ov = data[ov_off:]
            if sec_off is not None and sec_off >= ov_off:  # don't count the certificate as overlay
                ov = data[ov_off:sec_off] + data[sec_end:]
            if ov:
                r["overlay"] = {"offset": ov_off, "size": len(ov), "entropy": entropy(ov[:ENTROPY_SAMPLE])}
        return r
    finally:
        pe.close()


def pe_minimal(data: bytes) -> dict:
    """Header/section parser used when pefile is not installed (no imports/version info)."""
    try:
        lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if data[lfanew:lfanew + 4] != b"PE\x00\x00":
            return {"error": "MZ header without a valid PE signature"}
        machine, nsec, ts, _, _, opt_size, chars = struct.unpack_from("<HHIIIHH", data, lfanew + 4)
        opt = lfanew + 24
        magic, = struct.unpack_from("<H", data, opt)
        ep, = struct.unpack_from("<I", data, opt + 16)
        subsystem, = struct.unpack_from("<H", data, opt + 68)
        dd_off = opt + (96 if magic == 0x10B else 112)
        n_dirs, = struct.unpack_from("<I", data, dd_off - 4)

        def directory(i):
            return struct.unpack_from("<II", data, dd_off + 8 * i) if i < n_dirs else (0, 0)

        r = {"parser": "minimal (pip install pefile for imports & version info)",
             "machine": MACHINES.get(machine, hex(machine)), "is_64bit": magic == 0x20B,
             "is_dll": bool(chars & 0x2000), "subsystem": SUBSYSTEMS.get(subsystem, subsystem),
             "timestamp_raw": ts, "compile_time": ts_iso(ts), "is_dotnet": directory(COM_DIR)[0] != 0,
             "sections": [], "ep_section": None}
        sec_tab = opt + opt_size
        last_end = 0
        for i in range(min(nsec, 96)):
            off = sec_tab + 40 * i
            name, vsize, va, rsize, rptr = struct.unpack_from("<8sIIII", data, off)
            ch, = struct.unpack_from("<I", data, off + 36)
            name = name.rstrip(b"\x00").decode("latin-1")
            r["sections"].append({"name": name, "virtual_size": vsize, "raw_size": rsize,
                                  "entropy": entropy(data[rptr:rptr + rsize]),
                                  "writable": bool(ch & 0x80000000), "executable": bool(ch & 0x20000000)})
            if va <= ep < va + max(vsize, rsize):
                r["ep_section"] = name
            last_end = max(last_end, rptr + rsize)
        sva, ssize = directory(SEC_DIR)
        r["signature_present"] = bool(sva and ssize)
        if r["signature_present"]:
            r["certificate_names"] = cert_names(data[sva:sva + ssize])
        if 0 < last_end < len(data):
            ov = data[last_end:sva] + data[sva + ssize:] if r["signature_present"] and sva >= last_end \
                else data[last_end:]
            if ov:
                r["overlay"] = {"offset": last_end, "size": len(ov), "entropy": entropy(ov[:ENTROPY_SAMPLE])}
        return r
    except struct.error as e:
        return {"error": f"truncated/malformed PE header: {e}"}


def pe_signals(rec: dict) -> list[dict]:
    pe, out = rec.get("pe") or {}, []
    if pe.get("error"):
        return [sig("pe_malformed", "medium", pe["error"],
                    "Can be a truncated download; malformed headers are also an anti-analysis trick")]
    if pe.get("signature_present"):
        out.append(sig("signed", "info", "Authenticode signature present (NOT verified here); cert names: "
                       f"{pe.get('certificate_names') or '?'}",
                       "Signed by a known publisher strongly favours a false positive - but stolen/leaked certs exist"))
    else:
        out.append(sig("unsigned", "low", "No Authenticode signature",
                       "Many legitimate open-source / indie tools are unsigned"))

    hot = [f'{s["name"] or "?"}={s["entropy"]}' for s in pe.get("sections", [])
           if s["entropy"] > 7.2 and s["raw_size"] > 1024]
    if hot:
        out.append(sig("high_entropy_section", "medium", f"Packed/encrypted-looking sections: {hot}",
                       "Compressed resources and packers (UPX) in legit apps also look like this"))
    wx = [s["name"] or "?" for s in pe.get("sections", []) if s["writable"] and s["executable"]]
    if wx:
        out.append(sig("wx_section", "medium", f"Writable+executable sections: {wx}",
                       "Packers, protectors and some old compilers produce W+X sections"))
    if pe.get("ep_section") not in NORMAL_EP_SECTIONS and pe.get("sections"):
        out.append(sig("odd_entry_point", "low", f"Entry point in section {pe.get('ep_section')!r}",
                       "Normal for UPX/protected binaries and some installers"))

    cats = pe.get("suspicious_imports", {})
    if len(cats.get("process_injection", [])) >= 2:
        out.append(sig("injection_imports", "high", f"Process-injection API combo: {cats['process_injection']}",
                       "Debuggers, game trainers and some security tools use these legitimately"))
    if cats.get("keylogging") and ({"SetWindowsHookExA", "SetWindowsHookExW"} & set(cats["keylogging"])
                                   or "GetAsyncKeyState" in cats["keylogging"]):
        out.append(sig("keylog_imports", "medium", f"Keyboard hooking/polling APIs: {cats['keylogging']}",
                       "Hotkey tools, games and accessibility apps use these"))
    if cats.get("download_exec"):
        out.append(sig("download_imports", "medium", f"Direct download APIs: {cats['download_exec']}",
                       "Updaters use these"))
    if cats.get("anti_debug"):
        out.append(sig("anti_debug_imports", "low", f"Anti-debug APIs: {cats['anti_debug']}",
                       "Very common in normal MSVC runtime code (IsDebuggerPresent)"))
    if "import_count" in pe and pe["import_count"] < 10 and not pe.get("is_dotnet"):
        out.append(sig("few_imports", "medium", f"Only {pe['import_count']} imports (typical for packed loaders)",
                       "Tiny utilities, installers and packed-but-benign apps also import little"))

    raw = pe.get("timestamp_raw")
    if raw is not None:
        year = datetime.fromtimestamp(raw, timezone.utc).year if raw else 0
        if raw == 0 or year < 1995 or raw > time.time() + 86400:
            out.append(sig("timestamp_anomaly", "low", f"Odd compile timestamp: {pe.get('compile_time')}",
                           "Reproducible builds (Delphi, Go, Rust, MSVC /Brepro) zero or fake the timestamp"))
    vi = pe.get("version_info")
    if vi is not None and not vi:
        out.append(sig("no_version_info", "low", "No version info resource",
                       "Common in small open-source tools"))
    orig = (vi or {}).get("OriginalFilename", "")
    me = Path(rec["name"].replace("\\", "/")).stem.lower()
    if orig and Path(orig).stem.lower() not in me and me not in Path(orig).stem.lower():
        out.append(sig("original_name_mismatch", "low", f"OriginalFilename {orig!r} vs actual {rec['name']!r}",
                       "Browsers rename duplicates (setup (1).exe); renamed tools are common"))

    ov = pe.get("overlay")
    if ov and ov["size"] > 50 * 1024**2 and ov["entropy"] < 1.0:
        out.append(sig("padded_overlay", "high", f"{human(ov['size'])} low-entropy overlay - padding to exceed "
                       "AV/sandbox upload size limits", "Rare in legit software"))
    elif ov and ov["size"] > 1024**2 and ov["entropy"] > 7.5:
        out.append(sig("overlay_payload", "info", f"{human(ov['size'])} high-entropy overlay (embedded payload)",
                       "Normal for installers and self-extractors"))

    for fw in rec.get("frameworks", []):
        if fw["kind"] == "compiler":  # toolchain only: kept in rec["frameworks"], not a signal
            continue
        sev = "low" if fw["kind"] in ("packer", "protector", "obfuscator") else "info"
        out.append(sig(f"framework_{fw['kind']}", sev, f"{fw['name']} ({fw['kind']}, {fw['evidence']})",
                       KIND_FP[fw["kind"]]))
    return out
