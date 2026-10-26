# AGENTS.md

Guidance for AI coding agents (Codex, Claude Code, ...) working on this repository.

## Project

Scanything: static malware scanner with two front ends sharing one engine.
- Agent mode: `scanything/mcp_server.py` (MCP over stdio) + `scanything/skills/SKILL.md`.
- Orchestrator mode: `scanything/agent.py` + `scanything/providers.py`.
- Engine: `scanything/static.py`, `scanything/scanner.py`, `scanything/engines.py`, `scanything/api.py`.

## Hard rules

- Never add code that executes, opens, imports or loads the scanned file. Reading bytes is the only allowed access.
- MCP server: stdout is protocol only. Log to stderr.
- Keep the core on the Python standard library; new dependencies go behind an optional extra.
- No real malware in the repo. Tests build harmless fixtures in `tests/conftest.py` (`make_pe`, `make_zip`).
- Every new signal gets an `fp_note` when a benign explanation is realistic.

## Verify before you finish

```bash
pip install -e ".[dev]"
pyflakes scanything tests
pytest -q
```

## Using Scanything as a tool (not developing it)

Follow `scanything/skills/SKILL.md`.
