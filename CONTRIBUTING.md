# Contributing

```bash
pip install -e ".[dev]"
pyflakes scanything tests
pytest
```

## Adding a detection

1. String/IOC rule → add a tuple to `SUS_PATTERNS` in `scanything/static.py` (id, severity, label, regex, false-positive note).
2. Import behaviour → extend `SUS_IMPORTS` and emit a signal in `pe_signals`.
3. Packer/installer/runtime/compiler/obfuscator → an entry in `SIGNATURES` in `scanything/signatures.py` (byte regex, section names or imported DLLs, with a `# source:` comment).
4. Source-code or repository rule → a tuple in `CODE_RULES` in `scanything/repo.py`.
5. Map the new signal id to ATT&CK techniques in `SIGNAL_MAP` in `scanything/attack.py` when it fits one.
6. Add a test in `tests/` with a generated, harmless fixture.

Changing any rule table changes the `ruleset` id and therefore every `scan_id`; that is intended. Keep analysis output deterministic (no sets, timestamps or random values in the report), and run `pytest tests/test_ids.py`.

Every signal should carry an `fp_note` when there is a realistic benign explanation — false-positive reasoning is the point of this project.

## Rules

- No real malware in the repo, issues, or PRs. Use hashes or generated fixtures.
- Keep the core dependency-free (standard library); heavier tools go behind optional extras.
- Never add code paths that execute or open the analyzed file.
