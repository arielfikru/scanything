# Security

## Reporting a vulnerability

Please report security issues privately via GitHub Security Advisories ("Report a vulnerability" on the repo's Security tab) instead of a public issue. Include the Scanything version, OS, and a minimal reproducer. Do not attach live malware; share a hash or a link to a known sample repository instead.

## Design guarantees

- Scanything never executes, opens with an associated app, or loads the analyzed file. Archives are read in memory; nothing is extracted to disk (except a temporary copy for `osslsigncode` when verifying a signature inside an archive).
- Reads are capped (512 MB top-level, 128 MB per archive entry, 300 files, depth 3) to resist zip bombs.
- VirusTotal is queried by hash only; files are never uploaded.
- File-derived text sent to the LLM is marked as untrusted, and prompt-injection text inside a sample is flagged.

## Safe handling of samples

- Scan suspicious files on a machine you can afford to lose, or inside a VM.
- Store samples in password-protected zips (password `infected` is the convention) and never commit them to this repository.
- Test fixtures in `tests/` are generated at test time and are harmless.
