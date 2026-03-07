"""Batch file analysis and reporting for HashGuard."""

import csv
import html
import io
import json
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime

from hashguard.scanner import FileAnalysisResult, analyze
from hashguard.config import HashGuardConfig, get_default_config
from hashguard.logger import get_logger

logger = get_logger(__name__)


class BatchAnalyzer:
    """Analyze multiple files in batch mode."""

    def __init__(self, config: Optional[HashGuardConfig] = None):
        """Initialize batch analyzer."""
        self.config = config or get_default_config()
        self.results: List[FileAnalysisResult] = []

    def analyze_directory(
        self,
        directory: str,
        recursive: bool = True,
        pattern: str = "*",
        vt: bool = False,
    ) -> List[FileAnalysisResult]:
        """
        Analyze all files in a directory.

        Args:
            directory: Directory to scan
            recursive: Whether to scan subdirectories
            pattern: File pattern to match (e.g., "*.exe")
            vt: Whether to query VirusTotal

        Returns:
            List of analysis results
        """
        self.results = []
        dir_path = Path(directory)

        if not dir_path.is_dir():
            logger.error(f"Not a directory: {directory}")
            return self.results

        # Find files matching pattern (skip symlinks for security)
        if recursive:
            files = [f for f in dir_path.rglob(pattern) if not f.is_symlink()]
        else:
            files = [f for f in dir_path.glob(pattern) if not f.is_symlink()]

        logger.info(f"Found {len(files)} files to analyze")

        for i, file_path in enumerate(files, 1):
            if file_path.is_file():
                try:
                    logger.info(f"[{i}/{len(files)}] Analyzing {file_path}")
                    result = analyze(str(file_path), vt=vt, config=self.config)
                    self.results.append(result)
                except Exception as e:
                    logger.error(f"Failed to analyze {file_path}: {e}")

        logger.info(f"Batch analysis complete: {len(self.results)} files analyzed")
        return self.results

    def analyze_files(
        self,
        file_paths: List[str],
        vt: bool = False,
    ) -> List[FileAnalysisResult]:
        """
        Analyze a list of specific files.

        Args:
            file_paths: List of file paths
            vt: Whether to query VirusTotal

        Returns:
            List of analysis results
        """
        self.results = []

        for i, path in enumerate(file_paths, 1):
            try:
                logger.info(f"[{i}/{len(file_paths)}] Analyzing {path}")
                result = analyze(path, vt=vt, config=self.config)
                self.results.append(result)
            except Exception as e:
                logger.error(f"Failed to analyze {path}: {e}")

        logger.info(f"Batch analysis complete: {len(self.results)} files analyzed")
        return self.results

    def get_summary(self) -> Dict:
        """Get summary statistics of batch analysis."""
        total = len(self.results)
        malicious = sum(1 for r in self.results if r.malicious)
        clean = total - malicious
        total_size = sum(r.file_size for r in self.results)
        total_time = sum(r.analysis_time for r in self.results)

        return {
            "total_files": total,
            "malicious_count": malicious,
            "clean_count": clean,
            "malicious_percentage": round(100 * malicious / total, 2) if total > 0 else 0,
            "total_size_bytes": total_size,
            "total_analysis_time_seconds": round(total_time, 2),
            "average_time_per_file": round(total_time / total, 2) if total > 0 else 0,
            "timestamp": datetime.now().isoformat(),
        }


class ReportGenerator:
    """Generate analysis reports in various formats."""

    @staticmethod
    def to_json(results: List[FileAnalysisResult], pretty: bool = True) -> str:
        """Generate JSON report."""
        data = [r.to_dict() for r in results]
        return json.dumps(data, indent=2 if pretty else None, default=str)

    @staticmethod
    def to_csv(results: List[FileAnalysisResult]) -> str:
        """Generate CSV report using the csv module for proper escaping."""
        if not results:
            return ""

        buf = io.StringIO()
        writer = csv.writer(buf, quoting=csv.QUOTE_ALL)
        writer.writerow(
            [
                "File Path",
                "Size (bytes)",
                "MD5",
                "SHA1",
                "SHA256",
                "Malicious",
                "Description",
                "Analysis Time (ms)",
            ]
        )

        for result in results:
            writer.writerow(
                [
                    result.path,
                    result.file_size,
                    result.hashes.get("md5", ""),
                    result.hashes.get("sha1", ""),
                    result.hashes.get("sha256", ""),
                    "YES" if result.malicious else "NO",
                    result.description,
                    f"{result.analysis_time * 1000:.2f}",
                ]
            )

        return buf.getvalue()

    @staticmethod
    def to_html(
        results: List[FileAnalysisResult],
        title: str = "HashGuard Analysis Report",
    ) -> str:
        """Generate HTML report."""
        from hashguard import __version__

        _esc = html.escape
        analyzer = BatchAnalyzer()
        analyzer.results = results
        summary = analyzer.get_summary()

        parts: List[str] = []
        parts.append(f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{_esc(title)}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1e3a8a 0%, #3b82f6 100%);
            color: #333;
            padding: 20px;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; border-radius: 10px; box-shadow: 0 10px 40px rgba(0,0,0,0.2); }}
        header {{
            background: linear-gradient(135deg, #1e3a8a 0%, #3b82f6 100%);
            color: white;
            padding: 30px;
            border-radius: 10px 10px 0 0;
        }}
        h1 {{ font-size: 28px; margin-bottom: 10px; }}
        .timestamp {{ font-size: 12px; opacity: 0.9; }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            padding: 30px;
            border-bottom: 1px solid #eee;
        }}
        .stat {{
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            border-left: 4px solid #3b82f6;
        }}
        .stat-label {{ font-size: 12px; color: #666; text-transform: uppercase; }}
        .stat-value {{
            font-size: 24px;
            font-weight: bold;
            color: #1e3a8a;
            margin-top: 5px;
        }}
        .stat.malicious {{ border-left-color: #ef4444; }}
        .stat.malicious .stat-value {{ color: #ef4444; }}
        .stat.clean {{ border-left-color: #10b981; }}
        .stat.clean .stat-value {{ color: #10b981; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th {{
            background: #f3f4f6;
            padding: 15px;
            text-align: left;
            font-weight: 600;
            border-bottom: 2px solid #e5e7eb;
        }}
        td {{
            padding: 12px 15px;
            border-bottom: 1px solid #e5e7eb;
        }}
        .results-container {{ padding: 30px; }}
        .file-row {{ display: table-row; }}
        .file-row.malicious {{ background: #fef2f2; }}
        .file-row.clean {{ background: #f0fdf4; }}
        .badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
        }}
        .badge.malicious {{
            background: #fee2e2;
            color: #991b1b;
        }}
        .badge.clean {{
            background: #dcfce7;
            color: #166534;
        }}
        .hash {{ font-family: monospace; font-size: 11px; color: #666; }}
        footer {{
            background: #f3f4f6;
            padding: 20px 30px;
            border-top: 1px solid #e5e7eb;
            font-size: 12px;
            color: #666;
            border-radius: 0 0 10px 10px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>{_esc(title)}</h1>
            <div class="timestamp">Generated: {_esc(summary['timestamp'])}</div>
        </header>

        <div class="summary">
            <div class="stat">
                <div class="stat-label">Total Files</div>
                <div class="stat-value">{summary['total_files']}</div>
            </div>
            <div class="stat malicious">
                <div class="stat-label">Malicious</div>
                <div class="stat-value">{summary['malicious_count']}</div>
            </div>
            <div class="stat clean">
                <div class="stat-label">Clean</div>
                <div class="stat-value">{summary['clean_count']}</div>
            </div>
            <div class="stat">
                <div class="stat-label">Detection Rate</div>
                <div class="stat-value">{summary['malicious_percentage']}%</div>
            </div>
        </div>

        <div class="results-container">
            <h2>Detailed Results</h2>
            <table>
                <thead>
                    <tr>
                        <th>File Path</th>
                        <th>Size</th>
                        <th>SHA256</th>
                        <th>Status</th>
                        <th>Description</th>
                    </tr>
                </thead>
                <tbody>
""")

        for result in results:
            status = "MALICIOUS" if result.malicious else "CLEAN"
            status_class = "malicious" if result.malicious else "clean"
            sha256 = _esc(result.hashes.get("sha256", "")[:16] + "...")
            size_kb = result.file_size / 1024
            esc_path = _esc(result.path)
            esc_desc = _esc(result.description)

            parts.append(f"""
                    <tr class="file-row {status_class}">
                        <td><strong>{esc_path}</strong></td>
                        <td>{size_kb:.1f} KB</td>
                        <td><span class="hash">{sha256}</span></td>
                        <td><span class="badge {status_class}">{status}</span></td>
                        <td>{esc_desc}</td>
                    </tr>
""")

        parts.append(f"""
                </tbody>
            </table>
        </div>

        <footer>
            <strong>HashGuard</strong> &mdash; Professional File Verification &amp; Threat Intelligence Platform<br>
            Report generated with HashGuard v{_esc(__version__)}
        </footer>
    </div>
</body>
</html>
""")
        return "".join(parts)
