# Changelog

## 1.0.4 — 2026-03-08

Initial public release.

### Core Analysis
- Streaming SHA-256, SHA-1, and MD5 hash computation in a single pass.
- Malware signature matching via `signatures.json` (21 known-bad hashes).
- Composite risk scoring engine (0–100) with clean / suspicious / malicious verdicts.
- Automated IOC and string extraction (URLs, IPs, domains, emails, PowerShell commands, crypto wallets, registry keys).

### PE Executable Analysis
- Section-level entropy, packer detection, suspicious API import flagging.
- W+X section warnings, compile-time metadata, entry-point display.

### YARA
- 28+ YARA rules across 5 category files: general, ransomware, trojans, packers, and scripts.
- Auto-loads all `.yar` / `.yara` files from the `yara_rules/` directory.

### Threat Intelligence
- MalwareBazaar hash reputation (abuse.ch) — free, runs automatically.
- URLhaus payload database (abuse.ch) — free, runs automatically.
- AlienVault OTX hash reputation (v2 API) — free, runs automatically.
- AbuseIPDB IP reputation — free tier, requires `ABUSEIPDB_API_KEY`.
- VirusTotal API v3 integration — requires `VT_API_KEY`, activated with `--vt`.

### Security
- SSRF redirect validation: each hop checked against private/reserved IPs.
- API keys read from environment variables only — never persisted to disk.
- Config field whitelisting during deserialization.
- Explicit `verify=True` on all HTTP requests (TLS enforcement).
- Symlink-safe batch directory scanning.

### GUI
- Modern dark-themed Tkinter interface with drag-and-drop file support.
- Visual risk score bar with color-coded verdict display.
- Windows taskbar icon via `AppUserModelID` and BMP-encoded ICO.
- Threat indicator checklist with point breakdown.
- Extracted IOC display categorized by type.
- Real-time progress indicators and URL analysis support.
- Persistent settings via GUI Settings tab (`%APPDATA%/HashGuard/config.json`).

### CLI
- Single-file, URL, and batch analysis modes.
- Risk score and IOC summary in console output.
- JSON, CSV, and HTML report export.
- `--gui` flag to launch the graphical interface.

### Distribution
- PyInstaller spec files for standalone Windows executables (CLI + GUI).
- NSIS Windows installer with Start Menu, Desktop shortcut, and optional PATH registration.
- Portable ZIP package.
- GitHub Actions CI (Python 3.9–3.12 matrix) and automated release workflow.
