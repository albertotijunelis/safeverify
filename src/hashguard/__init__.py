"""
HashGuard - Professional File Verification & Threat Intelligence Platform

A powerful, production-grade file analysis tool with cryptographic hash verification,
malware signature detection, and integrated VirusTotal threat intelligence.

Version: 1.0.4
License: MIT
Author: Alberto Tijunelis
"""

__version__ = "1.0.4"
__author__ = "Alberto Tijunelis"
__license__ = "MIT"

from hashguard.scanner import analyze, analyze_url, compute_hashes, is_malware
from hashguard.pe_analyzer import analyze_pe
from hashguard.yara_scanner import scan_file as yara_scan
from hashguard.threat_intel import query_all as query_threat_intel
from hashguard.risk_scorer import compute_risk
from hashguard.string_extractor import extract_strings

__all__ = [
    "analyze",
    "analyze_url",
    "compute_hashes",
    "is_malware",
    "analyze_pe",
    "yara_scan",
    "query_threat_intel",
    "compute_risk",
    "extract_strings",
    "__version__",
]
