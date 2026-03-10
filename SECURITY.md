# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|| 1.1.x   | :white_check_mark: || 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in HashGuard, please report it responsibly.

**Do not open a public issue.** Instead, email **albertotijunelis@gmail.com** with:

1. A description of the vulnerability
2. Steps to reproduce the issue
3. Any files or evidence supporting the report

We aim to acknowledge reports within **48 hours** and provide an initial assessment within **5 business days**.

## Scope

The following areas are in scope for security reports:

- Injection vulnerabilities (command injection, XSS in HTML reports, path traversal)
- SSRF in URL analysis or threat intelligence queries
- Sensitive data exposure (API keys, credentials leaking in logs or reports)
- Authentication / authorization failures in API integrations
- Denial-of-service through crafted inputs (e.g., zip bombs, malformed PE files)
- Supply chain risks in dependencies

## Security Practices

HashGuard follows these security practices:

- **HTML reports** use `html.escape()` to prevent XSS
- **CSV reports** use Python's `csv` module with `QUOTE_ALL` to prevent injection
- **URL analysis** validates schemes and blocks private/local addresses (SSRF protection)
- **API keys** are never logged or included in exported configurations
- **File downloads** enforce a 200 MB size limit
- **Threat intelligence queries** are read-only — no files are uploaded to external services (except optional VirusTotal)
- **Dependencies** are pinned to minimum versions and reviewed regularly
