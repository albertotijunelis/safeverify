"""Batch sample ingest pipeline for the HashGuard ML dataset.

Downloads samples from public threat-intel feeds, runs the full analysis
pipeline on each, and stores extracted features in the dataset table.

Supported sources:
- **MalwareBazaar** (abuse.ch) — requires ``Auth-Key`` header
    - ``get_recent``: latest samples (up to 1000 per request)
    - ``get_taginfo``: samples by tag (e.g. "Emotet", "AgentTesla")
    - ``get_file_type``: samples by type (e.g. "exe", "dll")
- **Local directory** — scan files already on disk (no API key needed)

Design principles:
- SHA-256 dedup: already-analysed samples are skipped automatically.
- Rate limiting: configurable delay between API calls (default 1 req/s).
- Quarantine: downloads are unpacked to a temp dir and deleted after analysis.
- Resilient: individual failures are logged and skipped, never abort the run.
- Thread-safe state: a single ``IngestJob`` tracks progress for the API/UI.
"""

from __future__ import annotations

import hashlib
import io
import os
import shutil
import tempfile
import threading
import time
import zipfile
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from hashguard.logger import get_logger

logger = get_logger(__name__)

# MalwareBazaar ZIP password (public knowledge, documented in their API)
_MB_ZIP_PASSWORD = b"infected"


# ── Ingest job state ───────────────────────────────────────────────────────


@dataclass
class IngestJob:
    """Tracks the progress of a batch ingest run (thread-safe reads)."""

    source: str = ""
    status: str = "idle"  # idle | running | stopping | done | error
    total_candidates: int = 0
    skipped_existing: int = 0
    downloaded: int = 0
    analysed: int = 0
    failed: int = 0
    current_sha256: str = ""
    started_at: float = 0.0
    finished_at: float = 0.0
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        elapsed = 0.0
        if self.started_at:
            end = self.finished_at or time.time()
            elapsed = round(end - self.started_at, 1)
        return {
            "source": self.source,
            "status": self.status,
            "total_candidates": self.total_candidates,
            "skipped_existing": self.skipped_existing,
            "downloaded": self.downloaded,
            "analysed": self.analysed,
            "failed": self.failed,
            "current_sha256": self.current_sha256,
            "elapsed_seconds": elapsed,
            "errors": self.errors[-20:],  # last 20 errors
        }


# Global singleton — only one ingest job at a time
_current_job = IngestJob()
_job_lock = threading.Lock()
_stop_event = threading.Event()


def get_ingest_status() -> dict:
    """Return the current ingest job state (safe to call from any thread)."""
    return _current_job.to_dict()


def request_stop() -> None:
    """Signal the running ingest job to stop gracefully."""
    _stop_event.set()


# ── MalwareBazaar helpers ──────────────────────────────────────────────────


def _get_abuse_ch_key() -> Optional[str]:
    """Return the configured abuse.ch API key, or None."""
    key = os.getenv("ABUSE_CH_API_KEY")
    if key:
        return key
    try:
        from hashguard.config import get_default_config
        return get_default_config().abuse_ch_api_key
    except Exception:
        return None


def _mb_post(data: dict, timeout: int = 30) -> Optional[dict]:
    """POST to MalwareBazaar API and return parsed JSON, or None."""
    try:
        import requests
        headers: Dict[str, str] = {}
        api_key = _get_abuse_ch_key()
        if api_key:
            headers["Auth-Key"] = api_key
        resp = requests.post(
            "https://mb-api.abuse.ch/api/v1/",
            data=data,
            headers=headers,
            timeout=timeout,
            verify=True,
        )
        if resp.status_code == 200:
            return resp.json()
        logger.debug(f"MalwareBazaar API HTTP {resp.status_code}")
    except Exception as e:
        logger.debug(f"MalwareBazaar API error: {e}")
    return None


def _mb_get_recent(limit: int = 100) -> List[dict]:
    """Fetch the most recent samples from MalwareBazaar.

    Returns a list of sample metadata dicts (sha256_hash, file_type, etc.).
    The API accepts selector in multiples of 100 (min 100, max 1000).
    We always fetch at least 100 and truncate to *limit* afterwards.
    """
    # Round up to nearest 100 (API rejects values < 100)
    fetch = min(max(100, ((limit + 99) // 100) * 100), 1000)
    data = _mb_post({"query": "get_recent", "selector": str(fetch)})
    if data and data.get("query_status") == "ok":
        return data.get("data", [])[:limit]
    return []


def _mb_get_by_tag(tag: str, limit: int = 100) -> List[dict]:
    """Fetch samples by MalwareBazaar tag (e.g. ``Emotet``)."""
    fetch = min(max(100, limit), 1000)
    data = _mb_post({"query": "get_taginfo", "tag": tag, "limit": str(fetch)})
    if data and data.get("query_status") == "ok":
        return data.get("data", [])[:limit]
    return []


def _mb_get_by_filetype(file_type: str, limit: int = 100) -> List[dict]:
    """Fetch samples by file type (e.g. ``exe``, ``dll``, ``docx``)."""
    fetch = min(max(100, limit), 1000)
    data = _mb_post({"query": "get_file_type", "file_type": file_type, "limit": str(fetch)})
    if data and data.get("query_status") == "ok":
        return data.get("data", [])[:limit]
    return []


def _mb_download_sample(sha256: str, dest_dir: str) -> Optional[str]:
    """Download a sample ZIP from MalwareBazaar, extract, return file path.

    The ZIP is password-protected with ``infected``.  The extracted file is
    placed into *dest_dir* named ``<sha256>``.
    """
    try:
        import requests
        headers: Dict[str, str] = {}
        api_key = _get_abuse_ch_key()
        if api_key:
            headers["Auth-Key"] = api_key
        resp = requests.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_file", "sha256_hash": sha256},
            headers=headers,
            timeout=60,
            verify=True,
        )
        if resp.status_code != 200 or len(resp.content) < 100:
            return None

        # MalwareBazaar returns an AES-encrypted ZIP with password "infected"
        buf = io.BytesIO(resp.content)
        try:
            import pyzipper

            with pyzipper.AESZipFile(buf, "r") as zf:
                names = zf.namelist()
                if not names:
                    return None
                dest_path = os.path.join(dest_dir, sha256)
                with zf.open(names[0], pwd=_MB_ZIP_PASSWORD) as src, open(dest_path, "wb") as dst:
                    shutil.copyfileobj(src, dst)
                return dest_path
        except ImportError:
            # Fallback to stdlib zipfile (works for non-AES zips)
            try:
                with zipfile.ZipFile(buf) as zf:
                    names = zf.namelist()
                    if not names:
                        return None
                    dest_path = os.path.join(dest_dir, sha256)
                    with zf.open(names[0], pwd=_MB_ZIP_PASSWORD) as src, open(dest_path, "wb") as dst:
                        shutil.copyfileobj(src, dst)
                    return dest_path
            except (zipfile.BadZipFile, RuntimeError) as e:
                logger.debug(f"Failed to extract ZIP for {sha256}: {e}")
                return None
        except (zipfile.BadZipFile, RuntimeError, Exception) as e:
            logger.debug(f"Failed to extract ZIP for {sha256}: {e}")
            return None
    except Exception as e:
        logger.debug(f"Download failed for {sha256}: {e}")
        return None


# ── Core ingest engine ─────────────────────────────────────────────────────


def _analyse_file(file_path: str, use_vt: bool = False) -> Optional[dict]:
    """Run the full analysis pipeline on a single file.

    Uses the same pipeline as the web dashboard's ``_run_full_analysis``.
    Returns the sanitised result dict, or None on failure.
    """
    try:
        from hashguard.web.api import _run_full_analysis
        return _run_full_analysis(file_path, use_vt=use_vt)
    except Exception as e:
        logger.warning(f"Analysis failed for {file_path}: {e}")
        return None


def _already_in_dataset(sha256: str) -> bool:
    """Check if a SHA-256 is already stored in the samples table."""
    try:
        from hashguard.database import get_sample
        return get_sample(sha256) is not None
    except Exception:
        return False


def _run_ingest(
    candidates: List[dict],
    delay: float = 1.0,
    use_vt: bool = False,
) -> None:
    """Process a list of MalwareBazaar candidate dicts.

    This is the inner loop that runs in a background thread.
    """
    global _current_job
    _current_job.total_candidates = len(candidates)

    quarantine_dir = tempfile.mkdtemp(prefix="hashguard_ingest_")
    try:
        for entry in candidates:
            if _stop_event.is_set():
                _current_job.status = "stopping"
                break

            sha256 = entry.get("sha256_hash", "")
            if not sha256:
                continue

            _current_job.current_sha256 = sha256

            # Dedup
            if _already_in_dataset(sha256):
                _current_job.skipped_existing += 1
                continue

            # Download
            file_path = _mb_download_sample(sha256, quarantine_dir)
            if not file_path:
                _current_job.failed += 1
                _current_job.errors.append(f"download_failed:{sha256[:16]}")
                time.sleep(delay)
                continue

            _current_job.downloaded += 1

            # Analyse (features are extracted & stored automatically by the hook)
            result = _analyse_file(file_path, use_vt=use_vt)
            if result:
                _current_job.analysed += 1
            else:
                _current_job.failed += 1
                _current_job.errors.append(f"analysis_failed:{sha256[:16]}")

            # Cleanup individual file
            try:
                os.remove(file_path)
            except OSError:
                pass

            # Respect rate limit
            time.sleep(delay)

    finally:
        # Cleanup quarantine directory
        shutil.rmtree(quarantine_dir, ignore_errors=True)
        _current_job.current_sha256 = ""
        _current_job.finished_at = time.time()
        if _current_job.status == "running":
            _current_job.status = "done"
        elif _current_job.status == "stopping":
            _current_job.status = "done"


# ── Public API ─────────────────────────────────────────────────────────────


def _run_local_ingest(
    directory: str,
    limit: int = 100,
    delay: float = 0.1,
    use_vt: bool = False,
) -> None:
    """Ingest files from a local directory (no download step).

    Each file is hashed with SHA-256 for dedup, then analysed in place.
    """
    global _current_job

    files = []
    for name in os.listdir(directory):
        path = os.path.join(directory, name)
        if os.path.isfile(path):
            files.append(path)
        if len(files) >= limit:
            break

    _current_job.total_candidates = len(files)

    for file_path in files:
        if _stop_event.is_set():
            _current_job.status = "stopping"
            break

        # Compute SHA-256 for dedup / progress
        try:
            h = hashlib.sha256()
            with open(file_path, "rb") as fh:
                for chunk in iter(lambda: fh.read(65536), b""):
                    h.update(chunk)
            sha256 = h.hexdigest()
        except OSError:
            _current_job.failed += 1
            _current_job.errors.append(f"read_failed:{os.path.basename(file_path)[:16]}")
            continue

        _current_job.current_sha256 = sha256

        if _already_in_dataset(sha256):
            _current_job.skipped_existing += 1
            continue

        _current_job.downloaded += 1  # counts as "loaded" for local

        result = _analyse_file(file_path, use_vt=use_vt)
        if result:
            _current_job.analysed += 1
        else:
            _current_job.failed += 1
            _current_job.errors.append(f"analysis_failed:{sha256[:16]}")

        time.sleep(delay)

    _current_job.current_sha256 = ""
    _current_job.finished_at = time.time()
    if _current_job.status in ("running", "stopping"):
        _current_job.status = "done"


def start_ingest(
    source: str = "recent",
    limit: int = 100,
    tag: str = "",
    file_type: str = "exe",
    delay: float = 1.0,
    use_vt: bool = False,
    directory: str = "",
) -> dict:
    """Start a batch ingest job in the background.

    Parameters
    ----------
    source : str
        ``"recent"`` — most recent samples from MalwareBazaar.
        ``"tag"`` — samples matching *tag*.
        ``"filetype"`` — samples matching *file_type*.
        ``"local"`` — scan files from a local *directory*.
    limit : int
        Maximum number of candidates to fetch (capped at 1000).
    tag : str
        MalwareBazaar tag (only used when source="tag").
    file_type : str
        File type filter (only used when source="filetype"), e.g. "exe", "dll".
    delay : float
        Seconds between API calls (rate limiting).
    use_vt : bool
        Whether to query VirusTotal during analysis.
    directory : str
        Path to directory containing samples (only used when source="local").

    Returns
    -------
    dict with ``{"started": True, ...}`` or ``{"started": False, "reason": ...}``.
    """
    global _current_job

    with _job_lock:
        if _current_job.status == "running":
            return {"started": False, "reason": "A job is already running"}

        # Reset state
        _stop_event.clear()
        _current_job = IngestJob(
            source=source,
            status="running",
            started_at=time.time(),
        )

    # ── Local directory mode ──────────────────────────────────────────
    if source == "local":
        if not directory or not os.path.isdir(directory):
            _current_job.status = "error"
            _current_job.errors.append("Invalid or missing directory path")
            _current_job.finished_at = time.time()
            return {"started": False, "reason": "Invalid or missing directory path"}

        t = threading.Thread(
            target=_run_local_ingest,
            args=(directory, limit, delay, use_vt),
            daemon=True,
            name="hashguard-ingest",
        )
        t.start()
        return {"started": True, "source": "local", "candidates": min(limit, len(os.listdir(directory)))}

    # ── MalwareBazaar mode ────────────────────────────────────────────
    logger.info(f"Fetching candidates: source={source} limit={limit} tag={tag} file_type={file_type}")

    if source == "tag" and tag:
        candidates = _mb_get_by_tag(tag, limit)
    elif source == "filetype":
        candidates = _mb_get_by_filetype(file_type, limit)
    else:
        candidates = _mb_get_recent(limit)

    if not candidates:
        api_key = _get_abuse_ch_key()
        reason = "No candidates returned from feed"
        if not api_key:
            reason += " (no ABUSE_CH_API_KEY configured — the abuse.ch API requires authentication)"
        _current_job.status = "error"
        _current_job.errors.append(reason)
        _current_job.finished_at = time.time()
        return {"started": False, "reason": reason}

    _current_job.total_candidates = len(candidates)

    # Run the heavy lifting in a background thread
    t = threading.Thread(
        target=_run_ingest,
        args=(candidates, delay, use_vt),
        daemon=True,
        name="hashguard-ingest",
    )
    t.start()

    return {
        "started": True,
        "source": source,
        "candidates": len(candidates),
    }
