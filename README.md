<p align="center">
  <img src="https://raw.githubusercontent.com/albertotijunelis/hashguard/main/assets/branding/icon%2Btexto.png" alt="HashGuard" height="160">
</p>

<p align="center">
  <strong>File Verification & Threat Intelligence Platform</strong>
</p>

<p align="center">
  <a href="https://github.com/albertotijunelis/hashguard/releases/latest"><img src="https://img.shields.io/badge/%E2%AC%87%EF%B8%8F_Download-v1.0.4-FF6600?style=for-the-badge" alt="Download"></a>
  <a href="https://pypi.org/project/hashguard/"><img src="https://img.shields.io/badge/%F0%9F%93%A6_PyPI-hashguard-FF6600?style=for-the-badge" alt="PyPI"></a>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-003366.svg" alt="MIT License"></a>
  <a href="https://pypi.org/project/hashguard/"><img src="https://img.shields.io/pypi/v/hashguard?color=FF6600&label=pypi" alt="PyPI version"></a>
  <img src="https://img.shields.io/badge/python-3.9%2B-FF6600.svg" alt="Python 3.9+">
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-informational" alt="Platform">
</p>

---

HashGuard is a professional-grade file analysis platform that combines cryptographic hashing, malware signature matching, PE executable inspection, YARA rules scanning, multi-source threat intelligence, automated risk scoring, and IOC extraction — all through a modern GUI, CLI, or Python API.

## Features

| Category | Feature | Details |
|----------|---------|---------|
| **Hashing** | Streaming hashes | SHA-256, SHA-1, MD5 computed in a single pass |
| **Signatures** | Signature matching | Flag known-bad files via `signatures.json` |
| **Risk Score** | Composite scoring | 0-100 risk score with clean / suspicious / malicious verdicts |
| **PE Analysis** | Executable inspection | Sections, imports, entropy, packer detection via `pefile` |
| **YARA** | Rule-based scanning | 28+ rules across 5 categories in `yara_rules/` |
| **IOC Extraction** | String analysis | URLs, IPs, domains, PowerShell, crypto wallets, registry keys |
| **Threat Intel** | MalwareBazaar | Free hash reputation lookup (abuse.ch) — runs automatically |
| **Threat Intel** | URLhaus | Free payload database lookup (abuse.ch) — runs automatically |
| **Threat Intel** | AlienVault OTX | Free hash reputation (OTX v2) — runs automatically |
| **Threat Intel** | AbuseIPDB | IP reputation (free tier, needs `ABUSEIPDB_API_KEY`) |
| **Threat Intel** | VirusTotal | File hash + URL scanning with `--vt` flag + API key |
| **URL Analysis** | Download & scan | Fetch files from URLs, hash, and check all sources |
| **GUI** | Drag & drop | Drop files onto the dark-themed interface with risk visualization |
| **CLI** | Batch mode | Scan directories, export JSON / CSV / HTML reports |
| **Distribution** | Installer + portable | NSIS installer, portable ZIP, standalone `.exe` |

## Architecture

```
┌──────────────────────────────────────────────────┐
│                  HashGuard                       │
├──────────┬──────────┬────────────────────────────┤
│   CLI    │   GUI    │       Python API            │
│ cli.py   │ gui.py   │   from hashguard import    │
├──────────┴──────────┴────────────────────────────┤
│                  scanner.py                       │
│   compute_hashes() → analyze() → analyze_url()   │
├──────────┬──────────┬──────────┬─────────────────┤
│ PE       │ YARA     │ Threat   │ Risk Scorer     │
│ Analyzer │ Scanner  │ Intel    │ + IOC Extractor │
│ pefile   │ yara‑py  │ VT / MB  │ risk_scorer.py  │
│          │ 28+rules │ URLhaus  │ string_extractor│
│          │          │ OTX      │ .py             │
├──────────┴──────────┴──────────┴─────────────────┤
│               reports.py                          │
│   JSON / CSV / HTML batch reports                 │
└──────────────────────────────────────────────────┘
```

## Quick start

### Install from PyPI

```bash
pip install hashguard
```

### Install from source

```bash
git clone https://github.com/albertotijunelis/hashguard.git
cd hashguard
pip install -e .
```

### CLI

```bash
hashguard file.exe                           # hashes + signatures + PE + YARA + threat intel + risk score
hashguard file.exe --vt --json               # also query VirusTotal (requires VT_API_KEY)
hashguard --url https://example.com/file.exe  # download & analyze file from URL
hashguard --batch ./samples -o report.html   # batch scan to HTML
hashguard --gui                              # launch GUI
```

### GUI

```bash
hashguard-gui
```

The GUI features a dark interface with drag-and-drop, URL analysis, real-time progress, visual risk score bar, color-coded threat indicators, IOC extraction display, PE section details, YARA match display, and multi-source threat intelligence.

### Python API

```python
from hashguard import analyze, analyze_pe, yara_scan, compute_risk, extract_strings

# Full analysis (hashes + signatures + PE + YARA + threat intel + risk score + IOCs)
result = analyze("file.exe")
print(result.hashes["sha256"])
print(result.malicious)
print(result.risk_score)     # {"score": 72, "verdict": "malicious", "factors": [...]}
print(result.strings_info)   # extracted URLs, IPs, domains, PowerShell, crypto wallets
print(result.pe_info)        # PE sections, imports, entropy
print(result.yara_matches)   # YARA rule matches
print(result.threat_intel)   # MalwareBazaar + URLhaus + AlienVault OTX results
print(result.to_json())

# Also query VirusTotal (requires VT_API_KEY env var)
result = analyze("file.exe", vt=True)

# Standalone PE analysis
pe = analyze_pe("file.exe")
print(pe.packed, pe.packer_hint, pe.suspicious_imports)
```

## YARA Rules

Place `.yar` / `.yara` files in the `yara_rules/` directory. HashGuard ships with **28+ rules** across 5 categories:

| File | Rules | Detects |
|------|-------|---------|
| `default.yar` | 11 | PowerShell, injection, anti-debug, ransomware, keylogger, Mimikatz, shellcode, droppers, obfuscation, network, persistence |
| `ransomware.yar` | 3 | Ransom notes, file extension changes, shadow copy deletion |
| `trojans.yar` | 4 | Reverse shells, clipboard hijacking, screen capture, data exfiltration |
| `packers.yar` | 6 | UPX, MPRESS, ASPack, Themida/VMProtect, Enigma, PECompact |
| `scripts.yar` | 4 | VBA macro droppers, batch payloads, JS droppers, HTA payloads |

Custom rules are loaded automatically on each scan.

## Configuration

| Variable | Description |
|---|---|
| `VT_API_KEY` | VirusTotal API key (adds VT lookups; other sources run without it) |
| `ABUSEIPDB_API_KEY` | AbuseIPDB API key (adds IP reputation; free at abuseipdb.com) |
| `HASHGUARD_SIGNATURES` | Path to custom signatures database |

Settings can also be configured via the **GUI Settings tab**, which persists them to `%APPDATA%/HashGuard/config.json`.

## Comparison

| Feature | HashGuard | VirusTotal (web) | ClamAV |
|---------|:----------:|:----------------:|:------:|
| Offline hashing | **Yes** | No | Yes |
| Risk scoring | **Yes** | Partial | No |
| IOC extraction | **Yes** | No | No |
| PE analysis | **Yes** | Partial | No |
| YARA rules | **Yes** | No | Yes |
| MalwareBazaar | **Yes** | No | No |
| URLhaus | **Yes** | No | No |
| AlienVault OTX | **Yes** | No | No |
| VirusTotal | **Yes** | **Yes** | No |
| GUI + CLI | **Yes** | Web only | CLI only |
| Windows installer | **Yes** | N/A | Yes |
| Open source | **MIT** | No | **GPL** |

## Building

```bash
cd scripts
py -3.12 -m PyInstaller hashguard-cli.spec    # CLI executable
py -3.12 -m PyInstaller hashguard-gui.spec    # GUI executable
```

Releases are automated via GitHub Actions — push a `v*` tag and the workflow publishes executables, a portable ZIP, and a Windows installer.

## Project structure

```
src/hashguard/
  scanner.py           core analysis engine
  risk_scorer.py       composite 0-100 risk scoring
  string_extractor.py  automated IOC/string extraction
  pe_analyzer.py       PE executable inspection
  yara_scanner.py      YARA rules scanning
  threat_intel.py      MalwareBazaar + URLhaus + AlienVault OTX + AbuseIPDB
  cli.py               command-line interface
  gui.py               Tkinter dark-themed GUI with risk visualization
  config.py            configuration management
  reports.py           JSON / CSV / HTML reports
  logger.py            logging utilities
yara_rules/            YARA rule files (.yar) — 5 category files, 28+ rules
signatures.json        malware hash signatures
tests/                 101 pytest tests
assets/branding/       logo and icon files
scripts/               PyInstaller specs and build tooling
```

## License

[MIT](LICENSE)

