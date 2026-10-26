"""`scanything setup`: register the MCP server and the skill with Claude Code and Codex."""
from __future__ import annotations

import json
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

SKILL_SRC = Path(__file__).resolve().parent / "skills" / "SKILL.md"


def server_command() -> list[str]:
    # Absolute interpreter path: works no matter which venv/PATH the agent starts with.
    return [sys.executable, "-m", "scanything", "mcp"]


def codex_toml() -> str:
    cmd = server_command()
    return (f"[mcp_servers.scanything]\ncommand = {json.dumps(cmd[0])}\n"
            f"args = [{', '.join(json.dumps(a) for a in cmd[1:])}]\n")


def _run(cmd: list[str], dry: bool) -> bool:
    print(f"  $ {shlex.join(cmd)}")
    if dry:
        return True
    p = subprocess.run(cmd, capture_output=True, text=True)
    out = (p.stdout + p.stderr).strip()
    if out:
        print("    " + out.replace("\n", "\n    "))
    return p.returncode == 0


def _install_skill(dest_root: Path, dry: bool) -> None:
    dest = dest_root / "scanything" / "SKILL.md"
    print(f"  skill -> {dest}")
    if not dry:
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(SKILL_SRC, dest)


def setup(targets: list[str], dry: bool) -> int:
    home = Path.home()
    ok = True
    if "claude" in targets:
        print("Claude Code")
        if shutil.which("claude"):
            ok &= _run(["claude", "mcp", "add", "--scope", "user", "scanything", "--", *server_command()], dry)
        else:
            print("  `claude` not on PATH; run this once it is:")
            print(f"  $ claude mcp add --scope user scanything -- {shlex.join(server_command())}")
        _install_skill(home / ".claude" / "skills", dry)
    if "codex" in targets:
        print("Codex")
        if shutil.which("codex"):
            ok &= _run(["codex", "mcp", "add", "scanything", "--", *server_command()], dry)
        else:
            print("  `codex` not on PATH; add this to ~/.codex/config.toml:")
            print("    " + codex_toml().replace("\n", "\n    ").rstrip())
        _install_skill(home / ".codex" / "skills", dry)
    print("\nDone. Restart the agent, then ask: \"scan ~/Downloads/file.zip with scanything\"" if ok and not dry
          else "\n(dry run - nothing changed)" if dry else "\nSome steps failed; see output above.")
    return 0 if ok else 1
