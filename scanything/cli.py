"""Command-line entry point.

  scanything FILE [options]      scan + AI verdict + chat (orchestrator mode)
  scanything mcp                 run the MCP server (agent mode: Claude Code, Codex, ...)
  scanything setup [claude|codex] [--dry-run]   register the MCP server + skill
  scanything models [--provider P]              list models of a provider
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from . import recommend
from .agent import LLMClient, LLMError, Orchestrator, ToolBox, chat_loop, first_prompt, render_transcript
from .api import ScanError, scan_target
from .ids import make_verdict
from .providers import PRESETS, ProviderError, resolve_provider
from .report import print_summary
from .static import pefile
from .util import load_dotenv

SUBCOMMANDS = {"mcp", "setup", "models"}
LLM_HINTS = {
    401: "The {p} API key was rejected - check it or set another one in ~/.config/scanything/.env",
    402: "Your {p} account is out of credit - top it up{topup} or pick another --provider",
    404: "Model not found on {p} - run `scanything models` and pass --model",
    429: "Rate limited by {p} - wait a moment and retry",
}
TOPUP = {"netra": " at https://app.netra.sh", "openrouter": " at https://openrouter.ai/settings/credits",
         "openai": " at https://platform.openai.com/settings/organization/billing"}


def _load_env() -> None:
    load_dotenv(Path.cwd() / ".env")
    load_dotenv(Path.home() / ".config" / "scanything" / ".env")


def _log(msg: str) -> None:
    print(msg, file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    # Windows consoles default to cp1252, which cannot print the tree/separator glyphs.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    _load_env()
    if argv and argv[0] in SUBCOMMANDS:
        return {"mcp": cmd_mcp, "setup": cmd_setup, "models": cmd_models}[argv[0]](argv[1:])
    return cmd_scan(argv)


def cmd_mcp(argv: list[str]) -> int:
    from .mcp_server import serve
    return serve()


def cmd_setup(argv: list[str]) -> int:
    from .setup_agents import setup
    ap = argparse.ArgumentParser(prog="scanything setup",
                                 description="Register the Scanything MCP server and skill with coding agents.")
    # No `choices=` here: with nargs="*" some Python versions validate the empty default against it.
    ap.add_argument("targets", nargs="*", metavar="{claude,codex}", help="which agents (default: both)")
    ap.add_argument("--dry-run", action="store_true", help="print what would happen, change nothing")
    args = ap.parse_args(argv)
    if bad := [t for t in args.targets if t not in ("claude", "codex")]:
        ap.error(f"unknown agent(s): {', '.join(bad)} (choose from claude, codex)")
    return setup(args.targets or ["claude", "codex"], args.dry_run)


def cmd_models(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="scanything models", description="List models a provider serves.")
    ap.add_argument("--provider", choices=list(PRESETS))
    args = ap.parse_args(argv)
    try:
        p = resolve_provider(args.provider)
    except ProviderError as e:
        _log(f"error: {e}")
        return 2
    req = urllib.request.Request(p.base_url.rstrip("/") + "/models",
                                 headers={"Authorization": f"Bearer {p.api_key}", **p.headers})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.load(resp)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
        _log(f"error: {e}")
        return 1
    for m in sorted(m.get("id", "?") for m in data.get("data", [])):
        print(("* " if m == p.model else "  ") + m)
    _log(f"\nprovider: {p.name}  default model: {p.model}")
    return 0


def cmd_scan(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        prog="scanything",
        description="Static malware triage for .zip/.exe + AI verdict & chat. The file is never executed. "
                    "Other commands: `scanything mcp`, `scanything setup`, `scanything models`.")
    ap.add_argument("file", help="file to analyze (.zip, .exe, .dll, anything) or a GitHub repository URL "
                                 "(https://github.com/OWNER/REPO, github:OWNER/REPO@REF)")
    ap.add_argument("--password", help="password for encrypted zips (also tries: infected, malware, virus)")
    ap.add_argument("--vt", action="store_true", help="VirusTotal hash lookup (needs VT_API_KEY; never uploads)")
    ap.add_argument("--vt-max", type=int, default=4, help="max VirusTotal lookups (free tier: 4/min)")
    ap.add_argument("--clamav", action="store_true", help="also run clamscan if installed")
    ap.add_argument("--yara", help="YARA rule file or folder (needs yara-python)")
    ap.add_argument("--json-out", help="write the full JSON report here")
    ap.add_argument("--md-out", help="write the AI verdict + chat transcript here")
    ap.add_argument("--no-llm", action="store_true", help="static report only")
    ap.add_argument("--no-chat", action="store_true", help="verdict only, no interactive chat")
    ap.add_argument("--no-tools", action="store_true", help="disable function calling (for models without it)")
    ap.add_argument("--provider", choices=list(PRESETS), help="netra | openrouter | openai | custom "
                    "(default: LLM_PROVIDER, else the first API key found)")
    ap.add_argument("--model", help="override the provider's default model")
    ap.add_argument("--base-url", help="override the provider's base URL")
    ap.add_argument("--lang", default=None, help="reply language: id | en | ... (default SCANYTHING_LANG or id)")
    ap.add_argument("--temperature", type=float, default=0.2)
    ap.add_argument("-q", "--quiet", action="store_true", help="hide tool-call trace")
    args = ap.parse_args(argv)

    if pefile is None:
        _log("[!] pefile not installed: PE imports/version info unavailable (pip install pefile)")
    try:
        report, scan = scan_target(args.file, password=args.password, vt=args.vt, vt_max=args.vt_max,
                                   clamav=args.clamav, yara=args.yara, log=_log)
    except ScanError as e:
        _log(f"error: {e}")
        return 2
    print_summary(report)
    save_json(report, args.json_out)
    if args.no_llm:
        return 0

    try:
        provider = resolve_provider(args.provider, args.model, args.base_url)
    except ProviderError as e:
        _log(f"\n[!] {e} - static report only.")
        if hint := recommend.no_key_hint():
            _log(hint)
        return 0 if args.provider is None else 2
    lang = args.lang or os.environ.get("SCANYTHING_LANG", "id")
    llm = LLMClient(provider.base_url, provider.api_key, provider.model, args.temperature, provider.headers)
    orch = Orchestrator(llm, ToolBox(report, scan.strings, os.environ.get("VT_API_KEY")), not args.no_tools,
                        lang, not args.quiet)
    _log(f"\n[*] Asking {provider.model} via {provider.name} for a verdict...")
    try:
        verdict = orch.ask(first_prompt(report, orch.use_tools))
    except LLMError as e:
        _log(f"[LLM error] {e}")
        if hint := LLM_HINTS.get(e.status):
            _log(f"    {hint.format(p=provider.name, topup=TOPUP.get(provider.name, ''))}")
        return 1
    record = make_verdict(report["ids"]["scan_id"], provider.name, provider.model, verdict,
                          datetime.now(timezone.utc).isoformat(timespec="seconds"))
    report["verdict"] = record
    print(f"\n{verdict}\n")
    _log(f"verdict_id {record['verdict_id']}  ·  scan_id {record['scan_id']}  ·  file_id {report['ids']['file_id']}")
    if footer := recommend.powered_by(provider.name):
        _log(footer)
    save_json(report, args.json_out, quiet=True)
    ids_md = (f"- verdict_id: `{record['verdict_id']}` ({record['label'] or '?'}, "
              f"confidence {record['confidence'] if record['confidence'] is not None else '?'}%)\n"
              f"- scan_id: `{record['scan_id']}`\n- file_id (sha256): `{report['ids']['file_id']}`\n"
              f"- ruleset: `{report['ids']['ruleset']}` · engine {report['ids']['engine']} · "
              f"model {provider.model} via {provider.name}")
    transcript = [("ids", ids_md), ("scanything verdict", verdict)]
    if not args.no_chat and sys.stdin.isatty():
        chat_loop(orch, transcript)
    if args.md_out:
        Path(args.md_out).write_text(render_transcript(transcript), encoding="utf-8")
        _log(f"[saved] {args.md_out}")
    return 0


def save_json(report: dict, path: str | None, quiet: bool = False) -> None:
    if not path:
        return
    Path(path).write_text(json.dumps(report, indent=1, ensure_ascii=False), encoding="utf-8")
    if not quiet:
        _log(f"\n[saved] full report -> {path}")


if __name__ == "__main__":
    sys.exit(main())
