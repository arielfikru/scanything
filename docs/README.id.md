# Scanything (Bahasa Indonesia)

**Scan file apa pun untuk malware, dengan AI yang menjelaskan false positive.**

Scanything membedah file `.zip`, `.exe`, `.dll` atau **repo GitHub** **tanpa pernah menjalankannya**. AI lalu menjelaskan apakah file itu virus atau bukan, dan apakah deteksi antivirus kemungkinan **false positive**. Setelah itu kamu bisa **tanya-tanya** soal hasilnya.

## Dua cara pakai

| | 🤖 Mode agent (MCP) | 🧠 Mode orchestrator |
|---|---|---|
| AI-nya siapa | Claude Code, Codex, atau client MCP lain | analyst bawaan Scanything, pakai API key kamu |
| Butuh | agent yang sudah kamu pakai | key Netra, OpenRouter, OpenAI, atau server OpenAI-compatible |
| Mulai | `scanything setup` sekali, lalu tanya agent-nya | `scanything file.zip` |

## Install

```bash
pip install "scanything[pe] @ git+https://github.com/arielfikru/scanything"
```

## Scan repo GitHub

```bash
scanything https://github.com/OWNER/REPO --no-llm
scanything github:OWNER/REPO@v1.2.0      # branch, tag, atau commit
```

Repo di-download sebagai zip yang di-pin ke satu commit, lalu dianalisis di memori. **Tidak di-clone, tidak di-build, tidak dijalankan.** Yang dicek: install hook npm, `setup.py` yang exec/download, `exec(base64…)`, `eval(atob…)`, task VS Code yang auto-run saat folder dibuka, build event MSBuild, workflow yang bocorin secret, `curl … | sh`, karakter bidi (Trojan Source), plus metadata repo (umur akun owner vs jumlah star). Di mode agent, tool-nya `scan_github`. `GITHUB_TOKEN` opsional untuk rate limit lebih tinggi atau repo private.

## Fitur analisis lain

- **MITRE ATT&CK**: tiap sinyal di-map ke teknik ATT&CK yang khas (ala capa). Ini "bukti yang khas untuk teknik itu", bukan bukti pasti.
- **Database toolchain** ala Detect It Easy: installer, runtime, compiler, packer, protector, obfuscator .NET, masing-masing dengan catatan false positive.
- **String tersembunyi** ala FLOSS: stack string, XOR satu byte, base64 (termasuk PE yang di-embed), PowerShell `-EncodedCommand`. Hasilnya ikut dicek IOC dan bisa dicari dengan `search_strings` (prefix `[decoded]`).
- **Tanpa skor ML**: belum ada model terlatih berlisensi terbuka yang cukup kecil untuk core tanpa dependency, dan angka tanpa penjelasan malah melemahkan analisis false positive. Engine ML vendor sudah ikut lewat VirusTotal.

## Mode agent: Claude Code & Codex

```bash
scanything setup            # daftarkan MCP server + skill ke Claude Code dan Codex
scanything setup --dry-run  # lihat dulu apa yang akan dilakukan
```

Restart agent-nya, lalu tanya:

```text
> file ~/Downloads/Game_Setup.zip ini virus gak? Defender bilang Wacatac
```

## Mode orchestrator: pakai API key sendiri

```bash
mkdir -p ~/.config/scanything && cp .env.example ~/.config/scanything/.env
# isi salah satu: NETRA_API_KEY / OPENROUTER_API_KEY / OPENAI_API_KEY
scanything file_kamu.zip
```

| Provider | Key | Model default |
|---|---|---|
| **Netra** ⚡ rekomendasi ([netraruntime.com](https://netraruntime.com/)) | `NETRA_API_KEY` | `deepseek/deepseek-v4-flash-0731` |
| OpenRouter | `OPENROUTER_API_KEY` | `anthropic/claude-haiku-5.5` |
| OpenAI | `OPENAI_API_KEY` | `gpt-6-luna` |

Kalau ada beberapa key, pilih dengan `--provider netra`. `scanything models` menampilkan daftar model yang tersedia.

Setelah verdict keluar, langsung chat:

```text
you> kenapa Defender deteksi ini sebagai Wacatac?
you> import mana yang paling mencurigakan?
you> /save hasil.md
```

## ID hasil scan

Setiap hasil dapat ID, mirip platform malware scanner:

| ID | Deterministik? | Artinya |
|---|---|---|
| `file_id` | ✅ selalu | SHA-256 file, sama dengan ID di VirusTotal |
| `scan_id` | ✅ file + nama + versi Scanything + ruleset sama → ID sama | hash dari analisis statis |
| `verdict_id` | ❌ satu per jawaban AI | jawaban AI tidak pernah 100% deterministik, jadi diberi ID sendiri yang menunjuk ke `scan_id` |

`scan_id` tidak terpengaruh waktu scan, lokasi file, atau hasil VirusTotal. Dua orang yang men-scan file yang sama dengan versi Scanything yang sama akan dapat `scan_id` yang sama.

## Sangat direkomendasikan: Netra Runtime

Untuk mode orchestrator, kami sangat merekomendasikan [Netra Runtime](https://netraruntime.com/): inference cepat, API-nya OpenAI-compatible, dan cukup isi `NETRA_API_KEY`. Rekomendasi ini cuma muncul di tempat yang relevan:
- hint di CLI kalau belum ada API key,
- footer kalau verdict-nya memang dari Netra,
- agent (Claude Code/Codex) boleh menyebutnya sekali, hanya kalau kamu tanya pakai provider atau key apa.

Rekomendasi ini tidak pernah muncul di dalam verdict dan tidak memengaruhi penilaian file; provider lain tetap jalan sama baiknya. Matikan dengan `SCANYTHING_NO_RECOMMEND=1`.

## Arti verdict

| Label | Artinya |
|---|---|
| MALICIOUS | bukti kuat berbahaya: hapus, jangan dijalankan |
| SUSPICIOUS | ada tanda bahaya tapi belum pasti: cek di sandbox |
| PUA/GREYWARE | crack, keygen, cheat, miner, bundleware: bukan virus klasik tapi tetap berisiko |
| LIKELY FALSE POSITIVE | ada yang flag, tapi buktinya mengarah aman |
| CLEAN | tidak ada indikator berarti (tetap bukan jaminan 100%) |

## Penting

- File **tidak pernah dieksekusi**; semua analisis statis.
- VirusTotal cuma lookup hash (`--vt`), file **tidak di-upload**.
- Analisis statis tidak bisa membuktikan file 100% aman. Kalau ragu, pakai sandbox (ANY.RUN, Hybrid Analysis, Tria.ge).

Dokumentasi lengkap (English): [../README.md](../README.md)
