"""Command-line interface for HashGuard.

Professional file verification and threat intelligence platform with:
- Fast cryptographic hash computation
- Malware signature detection
- VirusTotal threat intelligence integration
- Batch processing and reporting
- Configuration management
"""

import warnings

try:
    from requests import RequestsDependencyWarning

    warnings.filterwarnings("ignore", category=RequestsDependencyWarning)
except ImportError:
    pass

import argparse
import sys
from pathlib import Path

from hashguard.scanner import analyze, analyze_url
from hashguard.reports import BatchAnalyzer, ReportGenerator
from hashguard.config import HashGuardConfig, get_default_config
from hashguard.logger import get_logger
from hashguard import __version__

logger = get_logger(__name__)


def run_gui() -> None:
    """Launch the graphical interface."""
    from hashguard import gui as _gui

    _gui.main()


def _print_result(result, title: str = "FILE ANALYSIS REPORT") -> None:
    """Pretty-print a FileAnalysisResult to stdout."""
    print("=" * 70)
    print(f"HASHGUARD - {title}")
    print("=" * 70)
    print(f"\nFile: {result.path}")
    print(f"Size: {result.file_size:,} bytes")
    print(f"\nCryptographic Hashes:")
    for algo, hash_val in result.hashes.items():
        print(f"  {algo.upper():6s}: {hash_val}")

    print(f"\nThreat Status: {'MALICIOUS' if result.malicious else 'CLEAN'}")
    if result.malicious:
        print(f"Description: {result.description}")

    # Risk Score
    risk = result.risk_score or {}
    if risk:
        score = risk.get("score", 0)
        verdict = risk.get("verdict", "unknown")
        filled = max(0, min(20, score // 5))
        bar = "\u2588" * filled + "\u2591" * (20 - filled)
        print(f"\nRisk Score: {bar} {score}/100 — {verdict.upper()}")
        factors = risk.get("factors", [])
        if factors:
            print("  Indicators:")
            for f in factors:
                print(
                    f"    \u2714 {f['name']} (+{f.get('points', 0)}pts)"
                    + (f"  {f['detail']}" if f.get("detail") else "")
                )

    if result.vt_result:
        print(f"\nVirusTotal Report:")
        data = result.vt_result.get("data", {})
        if data:
            attrs = data.get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            positives = stats.get("malicious", 0)
            total = sum(stats.values())
            print(f"  Detections: {positives}/{total}")
        else:
            print("  No report available")

    if result.threat_intel:
        print(f"\nThreat Intelligence:")
        for hit in result.threat_intel.get("hits", []):
            src = hit.get("source", "")
            if hit.get("found"):
                family = hit.get("malware_family", "Detected")
                print(f"  {src}: FOUND — {family}")
            else:
                print(f"  {src}: Not found")

    if result.pe_info and result.pe_info.get("is_pe"):
        pe = result.pe_info
        print(f"\nPE Analysis:")
        print(f"  Machine:     {pe.get('machine', '')}")
        print(f"  Compiled:    {pe.get('compile_time', '')}")
        print(f"  Entry Point: {pe.get('entry_point', '')}")
        print(f"  Entropy:     {pe.get('overall_entropy', 0):.4f} / 8.0")
        if pe.get("packed"):
            print(f"  Packer:      {pe.get('packer_hint', 'Unknown')}")
        for sec in pe.get("sections", []):
            print(
                f"  Section: {sec['name']:10s}  entropy={sec['entropy']:.2f}  size={sec['raw_size']:>8,}"
            )
        for w in pe.get("warnings", []):
            print(f"  WARNING: {w}")
        suspicious = pe.get("suspicious_imports", [])
        if suspicious:
            print(f"  Suspicious imports: {', '.join(suspicious[:10])}")

    if result.yara_matches:
        matches = result.yara_matches.get("matches", [])
        if matches:
            print(f"\nYARA Matches:")
            for m in matches:
                meta = m.get("meta", {})
                desc = meta.get("description", "")
                sev = meta.get("severity", "")
                print(
                    f"  Rule: {m['rule']}{f' [{sev}]' if sev else ''}{f' — {desc}' if desc else ''}"
                )

    # Extracted IOCs / Strings
    si = result.strings_info
    if si and si.get("has_iocs"):
        print(f"\nExtracted IOCs:")
        _cat_labels = [
            ("urls", "URLs"),
            ("ips", "IPs"),
            ("domains", "Domains"),
            ("emails", "Emails"),
            ("powershell_commands", "PowerShell"),
            ("suspicious_paths", "Suspicious Paths"),
            ("crypto_wallets", "Crypto Wallets"),
            ("user_agents", "User-Agents"),
            ("registry_keys", "Registry Keys"),
        ]
        for key, label in _cat_labels:
            items = si.get(key, [])
            if items:
                print(f"  {label} ({len(items)}):")
                for item in items[:5]:
                    print(f"    {item}")
                if len(items) > 5:
                    print(f"    ... and {len(items) - 5} more")

    print(f"\nAnalysis Time: {result.analysis_time * 1000:.1f}ms")
    print("=" * 70)


def analyze_single(args: argparse.Namespace) -> int:
    """Analyze a single file."""
    try:
        result = analyze(args.path, vt=args.vt)

        if args.json:
            print(result.to_json())
        else:
            _print_result(result, "FILE ANALYSIS REPORT")

        return 0

    except FileNotFoundError as e:
        logger.error(str(e))
        return 1
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        return 1


def analyze_url_single(args: argparse.Namespace) -> int:
    """Analyze a URL (download and scan)."""
    try:
        result = analyze_url(args.url, vt=args.vt)

        if args.json:
            print(result.to_json())
        else:
            _print_result(result, "URL ANALYSIS REPORT")

        return 0

    except Exception as e:
        logger.error(f"URL analysis failed: {e}")
        return 1


def analyze_batch(args: argparse.Namespace) -> int:
    """Analyze multiple files in batch mode."""
    try:
        analyzer = BatchAnalyzer()

        if args.directory:
            results = analyzer.analyze_directory(
                args.directory,
                recursive=not args.no_recursive,
                pattern=args.pattern,
                vt=args.vt,
            )
        else:
            # Analyze files from stdin
            files = []
            if not sys.stdin.isatty():
                files = [line.strip() for line in sys.stdin if line.strip()]

            if not files:
                logger.error("No files specified")
                return 1

            results = analyzer.analyze_files(files, vt=args.vt)

        # Output results based on requested format
        if args.output:
            output_path = Path(args.output)
            output_path.parent.mkdir(parents=True, exist_ok=True)

            if args.output.endswith(".json"):
                content = ReportGenerator.to_json(results)
            elif args.output.endswith(".csv"):
                content = ReportGenerator.to_csv(results)
            elif args.output.endswith(".html"):
                content = ReportGenerator.to_html(results)
            else:
                content = ReportGenerator.to_json(results)

            with open(args.output, "w", encoding="utf-8") as f:
                f.write(content)

            logger.info(f"Report saved to: {args.output}")
        else:
            # Print summary to console
            summary = analyzer.get_summary()
            print("\n" + "=" * 70)
            print("HASHGUARD - BATCH ANALYSIS SUMMARY")
            print("=" * 70)
            print(f"Total Files Analyzed: {summary['total_files']}")
            print(f"Malicious Files:      {summary['malicious_count']}")
            print(f"Clean Files:          {summary['clean_count']}")
            print(f"Detection Rate:       {summary['malicious_percentage']}%")
            print(f"Total Size:           {summary['total_size_bytes']:,} bytes")
            print(f"Total Time:           {summary['total_analysis_time_seconds']:.2f}s")
            print("=" * 70 + "\n")

        return 0

    except Exception as e:
        logger.error(f"Batch analysis failed: {e}")
        return 1


def main() -> None:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="hashguard",
        description="HashGuard - Professional File Verification & Threat Intelligence",
        epilog="Examples:\n"
        "  hashguard file.exe --vt\n"
        "  hashguard --url https://example.com/file.exe --vt\n"
        "  hashguard --batch /folder --output report.html\n"
        "  hashguard --gui",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Global options
    parser.add_argument(
        "--version",
        action="version",
        version=f"HashGuard {__version__}",
    )
    parser.add_argument(
        "--config",
        type=str,
        help="Path to configuration file",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Logging level",
    )

    # Mode selection
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "path",
        nargs="?",
        help="Path to file to analyze",
    )
    mode_group.add_argument(
        "--gui",
        action="store_true",
        help="Launch graphical interface",
    )
    mode_group.add_argument(
        "--url",
        type=str,
        metavar="URL",
        help="Download and analyze a file from URL",
    )
    mode_group.add_argument(
        "--batch",
        "-b",
        type=str,
        metavar="DIRECTORY",
        help="Analyze all files in directory (batch mode)",
        dest="directory",
    )

    # Analysis options
    parser.add_argument(
        "--vt",
        action="store_true",
        help="Also query VirusTotal API (requires VT_API_KEY)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON (single file only)",
    )

    # Batch mode options
    parser.add_argument(
        "--pattern",
        type=str,
        default="*",
        help="File pattern to match (default: *)",
    )
    parser.add_argument(
        "--no-recursive",
        action="store_true",
        help="Don't scan subdirectories in batch mode",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        metavar="FILE",
        help="Save report to file (.json, .csv, or .html)",
    )

    args = parser.parse_args()

    # Load configuration if provided
    if args.config:
        config = HashGuardConfig.from_file(args.config)
    else:
        config = get_default_config()

    # Handle GUI mode
    if args.gui or (not args.path and not args.url and not args.directory and sys.stdin.isatty()):
        run_gui()
        return

    # Handle URL mode
    if args.url:
        sys.exit(analyze_url_single(args))

    # Handle batch mode
    if args.directory:
        sys.exit(analyze_batch(args))

    # Handle single file mode
    if args.path:
        sys.exit(analyze_single(args))

    parser.print_help()
    sys.exit(0)


if __name__ == "__main__":
    main()
