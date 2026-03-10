"""YARA rules scanning for HashGuard.

Loads .yar/.yara rule files from a configurable directory and matches
them against analysed files. Falls back gracefully when yara-python
is not installed.
"""

import os
from dataclasses import dataclass, field
from typing import List, Optional

from hashguard.logger import get_logger

logger = get_logger(__name__)

_YARA_AVAILABLE = False
try:
    import yara  # type: ignore[import-untyped]

    _YARA_AVAILABLE = True
except ImportError:
    pass


@dataclass
class YaraMatch:
    rule: str
    namespace: str
    tags: List[str] = field(default_factory=list)
    meta: dict = field(default_factory=dict)
    strings: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "namespace": self.namespace,
            "tags": self.tags,
            "meta": self.meta,
            "strings": self.strings,
        }


@dataclass
class YaraScanResult:
    available: bool = False
    rules_loaded: int = 0
    matches: List[YaraMatch] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "available": self.available,
            "rules_loaded": self.rules_loaded,
            "matches": [m.to_dict() for m in self.matches],
        }


def is_available() -> bool:
    """Check whether the yara-python library is installed."""
    return _YARA_AVAILABLE


def _find_rule_files(rules_dir: str) -> List[str]:
    """Discover .yar and .yara files in *rules_dir*."""
    if not os.path.isdir(rules_dir):
        return []
    found = []
    for root, _dirs, files in os.walk(rules_dir):
        for f in files:
            if f.endswith((".yar", ".yara")):
                found.append(os.path.join(root, f))
    return sorted(found)


def scan_file(path: str, rules_dir: Optional[str] = None) -> YaraScanResult:
    """Scan a file against all YARA rules in *rules_dir*.

    Parameters
    ----------
    path : str
        File to scan.
    rules_dir : str | None
        Directory containing ``.yar`` / ``.yara`` files.  When *None*
        the function looks for a ``yara_rules/`` directory next to the
        project root (or inside ``_MEIPASS`` for frozen builds).

    Returns
    -------
    YaraScanResult
    """
    result = YaraScanResult(available=_YARA_AVAILABLE)

    if not _YARA_AVAILABLE:
        return result

    if not os.path.isfile(path):
        return result

    # Resolve rules directory
    if rules_dir is None:
        import sys

        base = getattr(sys, "_MEIPASS", None)
        if base:
            rules_dir = os.path.join(base, "yara_rules")
        else:
            # Package data (pip install)
            pkg_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "yara_rules")
            if os.path.isdir(pkg_dir):
                rules_dir = pkg_dir
            else:
                # Development fallback (project root)
                rules_dir = os.path.join(
                    os.path.dirname(os.path.abspath(__file__)), "..", "..", "yara_rules"
                )

    rule_files = _find_rule_files(rules_dir)
    if not rule_files:
        return result

    # Compile rules
    sources = {}
    for i, rf in enumerate(rule_files):
        ns = os.path.splitext(os.path.basename(rf))[0]
        sources[f"{ns}_{i}"] = rf

    try:
        rules = yara.compile(filepaths=sources)
    except yara.SyntaxError as e:
        logger.warning(f"YARA batch compile failed: {e} — trying file-by-file")
        good_sources = {}
        for ns, rf in sources.items():
            try:
                yara.compile(filepaths={ns: rf})
                good_sources[ns] = rf
            except Exception:
                logger.warning(f"Skipping bad YARA rule: {rf}")
        if not good_sources:
            return result
        try:
            rules = yara.compile(filepaths=good_sources)
        except Exception:
            return result
    except Exception as e:
        logger.error(f"YARA compile error: {e}")
        return result

    result.rules_loaded = len(rule_files)

    try:
        matches = rules.match(path, timeout=30)
    except Exception as e:
        logger.error(f"YARA scan error: {e}")
        return result

    for m in matches:
        string_hits = []
        for s in m.strings:
            for instance in s.instances:
                string_hits.append(f"0x{instance.offset:X}: {s.identifier}")
        ym = YaraMatch(
            rule=m.rule,
            namespace=m.namespace,
            tags=list(m.tags),
            meta=dict(m.meta) if m.meta else {},
            strings=string_hits[:20],  # cap at 20 per match
        )
        result.matches.append(ym)

    return result
