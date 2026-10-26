# Scanything

**Scan any file for malware, with an AI that explains false positives.**

Scanything dissects a `.zip`, `.exe`, `.dll` or a **GitHub repository** **without ever running it**, tells you whether it looks malicious, explains whether an antivirus alert is probably a **false positive**, and lets you chat about the result. It works inside **Claude Code** and **Codex** as an MCP server, or on its own with your API key.

🇮🇩 Bahasa Indonesia: [docs/README.id.md](docs/README.id.md)

## Quick start

```bash
pip install "scanything[pe] @ git+https://github.com/arielfikru/scanything"
```

Then pick one:

```bash
scanything setup                 # use it from Claude Code / Codex (agent mode)
```

```bash
export NETRA_API_KEY=...         # or OPENROUTER_API_KEY / OPENAI_API_KEY
scanything ~/Downloads/file.zip  # standalone AI analyst (orchestrator mode)
```

No key and no agent? `scanything file.zip --no-llm` still gives the full static report.

Checking a repository before you clone it? `scanything https://github.com/OWNER/REPO` downloads the archive pinned to one commit and scans it in memory. Nothing is cloned, built or run.

## Two modes, one engine

| | 🤖 Agent mode (MCP) | 🧠 Orchestrator mode |
|---|---|---|
| The AI is | your coding agent: Claude Code, Codex, any MCP client | Scanything's built-in analyst |
| You need | the agent you already use | an API key: Netra, OpenRouter, OpenAI, or any OpenAI-compatible server |
| Start with | `scanything setup`, then ask your agent | `scanything file.zip` |
| Good for | working in your editor or terminal agent | standalone use, scripts, CI |

Both modes use the same tools: `scan_file`, `scan_github`, `get_report_section`, `search_strings`, `list_files`, `vt_lookup`.

## 🤖 Agent mode: Claude Code & Codex

```bash
scanything setup              # both agents
scanything setup claude       # only Claude Code
scanything setup --dry-run    # show what would happen
```

| Agent | MCP server | Skill |
|---|---|---|
| Claude Code | `claude mcp add --scope user scanything -- <python> -m scanything mcp` | `~/.claude/skills/scanything/SKILL.md` |
| Codex | `codex mcp add scanything -- <python> -m scanything mcp` | `~/.codex/skills/scanything/SKILL.md` |

No `codex` CLI on PATH? Add this to `~/.codex/config.toml`:

```toml
[mcp_servers.scanything]
command = "/path/to/python"
args = ["-m", "scanything", "mcp"]
```

Restart the agent and ask:

```text
> is ~/Downloads/Game_Setup.zip a virus? Defender says Wacatac
```

The agent calls `scan_file`, digs with `search_strings` and `get_report_section`, and answers with a verdict, the false-positive reasoning, the `scan_id`, and a next step.

## 🧠 Orchestrator mode: your own API key

Put one key in `~/.config/scanything/.env` (template: [.env.example](.env.example)) or export it, then:

```text
$ scanything Game_Setup.zip --vt

== scanything: Game_Setup.zip ==
scan_id scn_9f2c41d0b7e3a8c5d1e6f402  ·  file_id (sha256) 5d41…c2a9  ·  ruleset rs_ace23f4945c8
Heuristic verdict: SUSPICIOUS  (score 11, 3 file(s), static only)

  #  type         size  score  name
  0  zip        4.1 MB      4  Game_Setup.zip
  1  pe         9.8 MB      7    └ Setup.exe
  2  text        312 B      0    └ readme.txt

[*] Asking deepseek/deepseek-v4-flash-0731 via netra for a verdict...
   ↳ get_report_section(files[1].pe.suspicious_imports)
   ↳ search_strings({"file_index": 1, "pattern": "webhook|telegram"})

## Verdict: LIKELY FALSE POSITIVE (confidence 75%)
...
verdict_id vrd_3b8e…  ·  scan_id scn_9f2c41d0b7e3a8c5d1e6f402
you> why does Defender call it Wacatac?
```

### Providers

| `--provider` | Key | Default model |
|---|---|---|
| `netra` ⚡ recommended | `NETRA_API_KEY` | `deepseek/deepseek-v4-flash-0731` |
| `openrouter` | `OPENROUTER_API_KEY` | `anthropic/claude-haiku-5.5` |
| `openai` | `OPENAI_API_KEY` | `gpt-6-luna` |
| `custom` | `LLM_API_KEY` + `LLM_BASE_URL` | `LLM_MODEL` |

- Without `--provider`, Scanything uses `LLM_PROVIDER`, else the first key it finds (Netra → OpenRouter → OpenAI).
- `--model` or `LLM_MODEL` picks any other model. `scanything models` lists what your provider serves right now.
- Models without tool calling still work: Scanything falls back to plain chat, or pass `--no-tools`.

### Options

```bash
scanything setup.exe --vt                   # VirusTotal hash lookup (never uploads)
scanything locked.zip --password infected   # encrypted archives
scanything file.exe --no-llm --json-out file.report.json   # offline, no AI
scanything file.exe --no-chat --md-out verdict.md          # CI / batch
scanything file.exe --provider openrouter --model anthropic/claude-sonnet-5.5 --lang en
scanything https://github.com/OWNER/REPO --no-llm             # a repository, pinned to its latest commit
scanything github:OWNER/REPO@v1.2.0                          # a branch, tag or commit
```

| Flag | Meaning |
|---|---|
| `--vt`, `--vt-max N` | VirusTotal lookup of up to N hashes (needs `VT_API_KEY`) |
| `--clamav` | also run `clamscan` |
| `--yara PATH` | YARA rule file or folder |
| `--password` | zip password (`infected`, `malware`, `virus` are always tried) |
| `--no-llm`, `--no-chat`, `--no-tools` | static only, verdict only, model without function calling |
| `--provider`, `--model`, `--base-url`, `--lang` | override `.env` |
| `--json-out`, `--md-out` | save the full report, save the AI transcript |

`GITHUB_TOKEN` (optional) raises GitHub's rate limit and gives access to private repositories you can read.

In chat: `/save [file.md]`, `/exit`. Config is read from `./.env`, then `~/.config/scanything/.env`.

## What it checks

| Layer | What Scanything looks at |
|---|---|
| Archive | nested zips, zip-slip paths, zip bombs, password-protected executables, decoy names (`invoice.pdf.exe`, RLO tricks), scripts, shortcuts and disk images inside |
| PE (`.exe`, `.dll`) | sections and entropy, W+X sections, entry point, imports grouped by behaviour (injection, keylogging, download, anti-debug…), Authenticode presence and certificate names, version info, overlay including anti-scan padding, embedded PEs |
| Toolchain DB | a Detect It Easy style database of about 40 signatures: installers (NSIS, Inno, WiX, 7-Zip SFX…), runtimes (PyInstaller, Nuitka, AutoIt, Go, Rust, .NET, Electron…), compilers (MSVC Rich header, MinGW, Delphi, VB6), packers (UPX, ASPack, MPRESS…), protectors (VMProtect, Themida, Enigma…) and .NET obfuscators, each with its false-positive note |
| Strings & IOCs | URLs, IPs, registry keys, PowerShell cradles, LOLBins, shadow-copy deletion, Defender tampering, stealer paths, Discord/Telegram exfil, miners, ransom notes, EICAR, prompt-injection text |
| Hidden strings | FLOSS-style recovery without emulation: x86 stack strings, single-byte XOR, base64 blobs and embedded PEs, PowerShell `-EncodedCommand`. Decoded text goes through the IOC rules and `search_strings` (prefixed `[decoded]`) |
| Source code | in repositories and any archive: npm install hooks, `setup.py` that execs or downloads, `exec(base64…)`, `eval(atob…)`, VS Code tasks that run on folder open, MSBuild build events, workflows that leak secrets or run fork PRs with secrets, `curl … \| sh`, code hidden far right, Trojan Source bidi characters |
| Repository | stars against owner-account age (star farming), new repository, fork, archived. Metadata never changes `scan_id`; the code is pinned by commit |
| Optional engines | VirusTotal hash lookup, ClamAV, YARA, `osslsigncode` signature verification |

### MITRE ATT&CK

Signals map to the ATT&CK technique they are typical of, like capa does, and the summary lists every technique with its evidence (`T1490 Inhibit System Recovery <- #1 shadow_copy_delete`). A mapping means "this evidence is typical of the technique", not proof that the file performs it.

### How false positives are judged

Every signal carries an `fp_note` saying when it is harmless, and the AI weighs those against the evidence.

| Usually a false positive | Usually real |
|---|---|
| 1–3 VirusTotal engines, all generic/ML names (`Wacatac`, `Generic`, `ML.Attribute`, `Artemis`) | named malware families across many engines |
| PyInstaller, Nuitka, AutoIt or Go binaries | injection + network + persistence together |
| UPX packing, NSIS or Inno Setup installers | stealer paths plus an exfil channel |
| signed by a known publisher (verified with `osslsigncode`) | decoy extensions, padded overlays, encrypted archives hiding an exe |

## Scan IDs

Every result gets IDs, like the hash-based IDs of malware scanning platforms.

| ID | Deterministic? | Computed from |
|---|---|---|
| `file_id` | ✅ always | SHA-256 of the file (same as VirusTotal) |
| `scan_id` | ✅ same file + name + Scanything version + ruleset | hash of the static analysis |
| `ruleset` | ✅ | hash of every detection rule table |
| `verdict_id` | ❌ one per AI answer | hash of `scan_id` + provider + model + answer |

`scan_id` ignores volatile data (timestamps, local path, VirusTotal/ClamAV results), so anyone scanning the same file with the same version gets the same id. It also seals the report:

```python
from scanything.ids import scan_id_of
assert scan_id_of(report) == report["ids"]["scan_id"]   # fails if the JSON was edited
```

With `--json-out`, the report also holds `verdict = {verdict_id, scan_id, label, confidence, provider, model, created}`.

## Try it safely

```bash
python scripts/make-test-samples.py   # harmless samples in ./samples (gitignored)
scanything samples/eicar.zip          # EICAR: every AV flags it, it does nothing
scanything samples/stealer_lookalike.exe
```

The samples are one-instruction PE stubs with malware-like strings, plus the standard EICAR test file. None of them does anything when run.

## Highly recommended: Netra Runtime

We highly recommend [Netra Runtime](https://netraruntime.com/) for orchestrator mode: fast inference, an OpenAI-compatible API, and DeepSeek V4 Flash 0731 handles the tool calling the analyst relies on. It is the first provider Scanything looks for, so `NETRA_API_KEY` is all you need. Save a key from your clipboard with `scripts/save-netra-key` (macOS).

The recommendation appears in this README, as a CLI hint when no key is set, as a one-line footer when Netra produced the verdict, and in the agent instructions only if you ask which provider to use. It never appears inside a verdict or affects how files are judged. `SCANYTHING_NO_RECOMMEND=1` hides it.

## How it works

```text
file or GitHub repo ──► scanner (recursive, in memory, never executed)
           ├─ static: type, hashes, entropy, strings/IOCs, PE, toolchain DB, decoded strings, code rules
           ├─ archive: entries, passwords, bombs, nested files
           └─ engines (optional): VirusTotal, ClamAV, YARA, osslsigncode
        ──► report: signals + fp_notes + heuristic score + file_id / scan_id
        ──► tools: scan_file · scan_github · get_report_section · search_strings · list_files · vt_lookup
              ├─ MCP server ──► Claude Code / Codex / any MCP client     (agent mode)
              └─ built-in analyst ──► Netra / OpenRouter / OpenAI       (orchestrator mode)
```

| Module | Role |
|---|---|
| `static.py` | file type, string and IOC rules, PE parser |
| `signatures.py` / `deobf.py` | toolchain signature DB / hidden-string recovery |
| `repo.py` | GitHub download pinned to a commit, source code and metadata rules |
| `attack.py` | signal → MITRE ATT&CK mapping |
| `scanner.py` | recursive scan, zip handling, YARA, signature verification |
| `engines.py` | VirusTotal and ClamAV |
| `api.py` | `scan_path()`, shared by the CLI and the MCP server |
| `report.py` / `ids.py` | report, compact AI view, terminal summary / deterministic ids |
| `agent.py` / `providers.py` | OpenAI-compatible client, tool loop, chat / provider presets |
| `mcp_server.py` / `setup_agents.py` | MCP server (stdio) / `scanything setup` |
| `skills/SKILL.md` | agent skill |

Content from a scanned file is untrusted: both the MCP instructions and the analyst prompt say so, and text that tries to steer an AI is flagged as a `prompt_injection` signal.

## Limits

- Static analysis can never prove a file is safe. When in doubt, use a sandbox (ANY.RUN, Hybrid Analysis, Tria.ge) or the vendor's published hash.
- No machine-learning score: there is no trained, openly licensed model small enough for a stdlib-only core, and an unexplained number would undercut the false-positive reasoning. VirusTotal results already include vendors' ML engines.
- Hidden-string recovery is pattern based, not emulation: multi-byte XOR, RC4 and runtime-built strings are not recovered.
- Repositories: up to 10,000 archive entries and 3,000 analyzed files, 512 MiB archive. Only what is in the repository is scanned, not the dependencies it pulls at install time.
- 7z, RAR and ISO are detected but not unpacked yet: extract them without running anything, then scan the contents.
- Authenticode is only *verified* when `osslsigncode` is installed; otherwise Scanything reports its presence and certificate names.
- The AI can be wrong. Treat its verdict as a second opinion with cited evidence.

## Development

```bash
git clone https://github.com/arielfikru/scanything && cd scanything
python -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/pyflakes scanything tests && .venv/bin/pytest -q
```

See [CONTRIBUTING.md](CONTRIBUTING.md), [AGENTS.md](AGENTS.md) and [SECURITY.md](SECURITY.md). Never commit live malware.

## License

MIT, see [LICENSE](LICENSE).
