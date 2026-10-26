"""MITRE ATT&CK mapping for Scanything signals (static evidence -> likely techniques).

A mapping means "this static evidence is typical of the technique", not proof the file performs it.
"""
from __future__ import annotations

# technique id -> (name, tactic)
TECHNIQUES = {
    "T1005": ("Data from Local System", "Collection"),
    "T1027": ("Obfuscated Files or Information", "Defense Evasion"),
    "T1027.001": ("Binary Padding", "Defense Evasion"),
    "T1027.002": ("Software Packing", "Defense Evasion"),
    "T1027.009": ("Embedded Payloads", "Defense Evasion"),
    "T1027.010": ("Command Obfuscation", "Defense Evasion"),
    "T1027.013": ("Encrypted/Encoded File", "Defense Evasion"),
    "T1036": ("Masquerading", "Defense Evasion"),
    "T1036.002": ("Right-to-Left Override", "Defense Evasion"),
    "T1036.007": ("Double File Extension", "Defense Evasion"),
    "T1053.005": ("Scheduled Task", "Persistence"),
    "T1055": ("Process Injection", "Defense Evasion / Privilege Escalation"),
    "T1056.001": ("Keylogging", "Collection"),
    "T1059": ("Command and Scripting Interpreter", "Execution"),
    "T1059.001": ("PowerShell", "Execution"),
    "T1059.006": ("Python", "Execution"),
    "T1059.007": ("JavaScript", "Execution"),
    "T1071.001": ("Web Protocols", "Command and Control"),
    "T1102": ("Web Service", "Command and Control"),
    "T1105": ("Ingress Tool Transfer", "Command and Control"),
    "T1127.001": ("MSBuild", "Defense Evasion"),
    "T1195.001": ("Compromise Software Dependencies and Development Tools", "Initial Access"),
    "T1204.002": ("User Execution: Malicious File", "Execution"),
    "T1218": ("System Binary Proxy Execution", "Defense Evasion"),
    "T1486": ("Data Encrypted for Impact", "Impact"),
    "T1490": ("Inhibit System Recovery", "Impact"),
    "T1496": ("Resource Hijacking", "Impact"),
    "T1497.001": ("Virtualization/Sandbox Evasion: System Checks", "Defense Evasion / Discovery"),
    "T1547.001": ("Registry Run Keys / Startup Folder", "Persistence"),
    "T1548.002": ("Bypass User Account Control", "Privilege Escalation"),
    "T1555.003": ("Credentials from Web Browsers", "Credential Access"),
    "T1562.001": ("Impair Defenses: Disable or Modify Tools", "Defense Evasion"),
    "T1567": ("Exfiltration Over Web Service", "Exfiltration"),
    "T1622": ("Debugger Evasion", "Defense Evasion / Discovery"),
}

# signal id -> technique ids
SIGNAL_MAP = {
    "powershell_obfuscated": ["T1059.001", "T1027.010", "T1105"],
    "lolbin_download": ["T1105", "T1218"],
    "shadow_copy_delete": ["T1490"],
    "defender_tamper": ["T1562.001"],
    "ransom_note": ["T1486"],
    "stealer_targets": ["T1555.003", "T1005"],
    "exfil_channel": ["T1567", "T1102"],
    "miner": ["T1496"],
    "persistence": ["T1547.001", "T1053.005"],
    "uac_bypass": ["T1548.002"],
    "anti_vm": ["T1497.001"],
    "anti_debug_imports": ["T1622"],
    "injection_imports": ["T1055"],
    "keylog_imports": ["T1056.001"],
    "download_imports": ["T1105"],
    "shady_url": ["T1102"],
    "raw_ip_url": ["T1071.001"],
    "high_entropy_section": ["T1027.002"],
    "framework_packer": ["T1027.002"],
    "framework_protector": ["T1027.002"],
    "framework_obfuscator": ["T1027"],
    "padded_overlay": ["T1027.001"],
    "embedded_pe": ["T1027.009"],
    "rlo_filename": ["T1036.002"],
    "double_extension": ["T1036.007"],
    "padded_extension": ["T1036.007"],
    "original_name_mismatch": ["T1036"],
    "encrypted_executable": ["T1027.013"],
    "script_or_lure_in_archive": ["T1204.002"],
    "lnk_file": ["T1204.002"],
    "script_file": ["T1059"],
    "stack_strings": ["T1027"],
    "xor_encoded_strings": ["T1027"],
    "base64_payload": ["T1027", "T1027.009"],
    "encoded_powershell": ["T1059.001", "T1027.010"],
    # source code / repository rules (repo.py)
    "npm_install_hook": ["T1195.001", "T1059"],
    "python_setup_exec": ["T1195.001", "T1059.006", "T1027"],
    "python_obfuscated_exec": ["T1059.006", "T1027"],
    "js_obfuscated_eval": ["T1059.007", "T1027"],
    "vscode_autorun": ["T1195.001", "T1204.002"],
    "msbuild_event": ["T1127.001"],
    "gha_secret_exfil": ["T1567"],
    "gha_pwn_request": ["T1195.001"],
    "curl_pipe_shell": ["T1105"],
    "hidden_far_right_code": ["T1027"],
    "trojan_source_bidi": ["T1027"],
    "build_rs_command": ["T1195.001"],
    "star_farming_suspect": ["T1036"],
}


def annotate(signals: list[dict]) -> None:
    """Add an `attack` list to each signal that maps to ATT&CK techniques (in place)."""
    for s in signals:
        if ids := SIGNAL_MAP.get(s["id"]):
            s["attack"] = ids


def summarize(files: list[dict]) -> list[dict]:
    """Techniques seen across all files, with the signals that point to them."""
    seen: dict[str, list[str]] = {}
    for f in files:
        for s in f.get("signals", []):
            for tid in s.get("attack", []):
                seen.setdefault(tid, []).append(f"#{f['index']} {s['id']}")
    return [{"id": tid, "name": TECHNIQUES[tid][0], "tactic": TECHNIQUES[tid][1], "evidence": sorted(set(ev))}
            for tid, ev in sorted(seen.items())]
