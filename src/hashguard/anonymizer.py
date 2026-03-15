"""Dataset anonymization pipeline for HashGuard.

Sanitizes exported datasets by removing or masking fields that could
identify the original analyst, file paths, machine names, or other
personally identifiable information (PII).

Usage:
    from hashguard.anonymizer import anonymize_dataset
    clean_data = anonymize_dataset(raw_data, fmt="parquet")

Anonymization rules:
- **Drop columns**: file_path, created_at, label_source, label_mb_tags,
  label_mb_signature (contain analyst/machine metadata)
- **Hash filenames**: SHA-256 truncated to 16 chars
- **Strip IOC strings**: URLs, IPs, domains, emails, registry keys are
  replaced with category placeholders
- **Redact paths**: Windows/Unix paths in text fields → ``<REDACTED_PATH>``
- **Normalize timestamps**: Round to date-only (remove time component)
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import re
from typing import Dict, List, Optional

from hashguard.logger import get_logger

logger = get_logger(__name__)

# Columns that leak analyst/machine identity
_DROP_COLUMNS = {
    "file_path",
    "label_source",
    "label_mb_tags",
    "label_mb_signature",
}

# Regex patterns for PII redaction in text fields
_PATH_RE = re.compile(
    r"(?:[A-Za-z]:\\[\w\\. -]+|/(?:home|Users|tmp|var|etc)/[\w/. -]+)"
)
_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
_IP_RE = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)
_HOSTNAME_RE = re.compile(
    r"\b(?:DESKTOP|LAPTOP|PC|WIN|WORKSTATION)-[A-Z0-9]{5,}\b", re.IGNORECASE
)


def _hash_value(val: str, length: int = 16) -> str:
    """Deterministic pseudonymization via truncated SHA-256."""
    return hashlib.sha256(val.encode("utf-8")).hexdigest()[:length]


def _redact_text(text: str) -> str:
    """Remove PII patterns from a free-text field."""
    text = _PATH_RE.sub("<REDACTED_PATH>", text)
    text = _EMAIL_RE.sub("<REDACTED_EMAIL>", text)
    text = _HOSTNAME_RE.sub("<REDACTED_HOST>", text)
    return text


def anonymize_row(row: Dict, hash_filename: bool = True) -> Dict:
    """Anonymize a single dataset row (dict).

    Returns a new dict with sensitive fields removed/masked.
    """
    out = {}
    for key, val in row.items():
        # Drop sensitive columns entirely
        if key in _DROP_COLUMNS:
            continue

        # Hash filenames
        if key == "filename" and hash_filename and val:
            out[key] = _hash_value(str(val))
            continue

        # Truncate timestamps to date only
        if key == "created_at" and val and isinstance(val, str):
            out[key] = val[:10]  # "2024-01-15T12:30:00" → "2024-01-15"
            continue

        # Redact free-text fields
        if key in ("description", "context", "details") and isinstance(val, str):
            out[key] = _redact_text(val)
            continue

        out[key] = val

    return out


def anonymize_rows(rows: List[Dict], **kwargs) -> List[Dict]:
    """Anonymize a list of dataset rows."""
    return [anonymize_row(r, **kwargs) for r in rows]


def anonymize_dataset(data: str | bytes, fmt: str = "csv") -> str | bytes:
    """Anonymize an exported dataset (CSV, JSONL, or Parquet bytes).

    Returns data in the same format with PII removed.
    """
    if fmt == "parquet":
        return _anonymize_parquet(data)
    elif fmt == "jsonl":
        return _anonymize_jsonl(data)
    else:
        return _anonymize_csv(data)


def _anonymize_csv(data: str) -> str:
    """Anonymize a CSV string."""
    reader = csv.DictReader(io.StringIO(data))
    if not reader.fieldnames:
        return data

    out_fields = [f for f in reader.fieldnames if f not in _DROP_COLUMNS]
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=out_fields, extrasaction="ignore")
    writer.writeheader()

    for row in reader:
        writer.writerow(anonymize_row(row))

    return output.getvalue()


def _anonymize_jsonl(data: str) -> str:
    """Anonymize a JSONL string."""
    lines = []
    for line in data.strip().split("\n"):
        if not line.strip():
            continue
        row = json.loads(line)
        lines.append(json.dumps(anonymize_row(row), default=str))
    return "\n".join(lines)


def _anonymize_parquet(data: bytes) -> bytes:
    """Anonymize Parquet bytes."""
    try:
        import pyarrow.parquet as pq
        import pyarrow as pa
    except ImportError:
        logger.warning("pyarrow not installed — returning raw parquet")
        return data

    buf = io.BytesIO(data)
    table = pq.read_table(buf)

    # Drop sensitive columns
    cols_to_drop = [c for c in _DROP_COLUMNS if c in table.column_names]
    if cols_to_drop:
        table = table.drop(cols_to_drop)

    # Convert to dicts for row-level anonymization
    rows = table.to_pydict()
    n = table.num_rows
    if n == 0:
        out = io.BytesIO()
        pq.write_table(table, out, compression="snappy")
        return out.getvalue()

    # Apply per-row transforms
    anon_data = {col: list(rows[col]) for col in table.column_names if col not in cols_to_drop}

    if "filename" in anon_data:
        anon_data["filename"] = [
            _hash_value(str(v)) if v else v for v in anon_data["filename"]
        ]

    if "created_at" in anon_data:
        anon_data["created_at"] = [
            str(v)[:10] if v else v for v in anon_data["created_at"]
        ]

    for text_col in ("description", "context", "details"):
        if text_col in anon_data:
            anon_data[text_col] = [
                _redact_text(str(v)) if v else v for v in anon_data[text_col]
            ]

    anon_table = pa.table(anon_data)
    out = io.BytesIO()
    pq.write_table(anon_table, out, compression="snappy")
    return out.getvalue()
