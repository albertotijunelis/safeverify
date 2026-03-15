"""HashGuard Python SDK — typed client for the HashGuard REST API.

Usage
-----
::

    from hashguard.sdk import HashGuardClient

    hg = HashGuardClient("http://localhost:8000", api_key="hg_abc123")

    # Analyse a file
    result = hg.analyze("malware.exe", use_vt=True)
    print(result["risk_score"])

    # Search samples
    for s in hg.search("emotet"):
        print(s["sha256"])

    # Get threat feeds
    hashes = hg.feed_hashes(verdict="malicious", fmt="txt")
    stix_bundle = hg.feed_stix(limit=50)

    # Async analysis
    task = hg.analyze_async("large_sample.bin")
    result = hg.poll_task(task["task_id"])
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, BinaryIO, Dict, List, Optional, Union

try:
    import httpx
    _HAS_HTTPX = True
except ImportError:
    _HAS_HTTPX = False


class HashGuardError(Exception):
    """Raised when the API returns an error response."""

    def __init__(self, status_code: int, detail: str):
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"HTTP {status_code}: {detail}")


class HashGuardClient:
    """Typed Python client for the HashGuard REST API.

    Parameters
    ----------
    base_url:
        HashGuard server URL (e.g. ``http://localhost:8000``).
    api_key:
        API key for authenticated requests (``X-API-Key`` header).
    token:
        JWT bearer token (alternative to api_key).
    timeout:
        Request timeout in seconds.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        api_key: Optional[str] = None,
        token: Optional[str] = None,
        timeout: float = 120.0,
    ):
        if not _HAS_HTTPX:
            raise ImportError(
                "httpx is required for the HashGuard SDK. Install with: pip install httpx"
            )
        self.base_url = base_url.rstrip("/")
        self._timeout = timeout
        headers: Dict[str, str] = {}
        if api_key:
            headers["X-API-Key"] = api_key
        elif token:
            headers["Authorization"] = f"Bearer {token}"
        self._client = httpx.Client(base_url=self.base_url, headers=headers, timeout=timeout)

    def close(self):
        """Close the underlying HTTP client."""
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    # -- internal helpers --------------------------------------------------

    def _request(self, method: str, path: str, **kwargs) -> Any:
        resp = self._client.request(method, path, **kwargs)
        if resp.status_code >= 400:
            detail = resp.text[:500]
            try:
                detail = resp.json().get("detail", detail)
            except Exception:
                pass
            raise HashGuardError(resp.status_code, detail)
        return resp

    def _get_json(self, path: str, **params) -> Any:
        return self._request("GET", path, params=params).json()

    # ── Analysis ─────────────────────────────────────────────────────────

    def analyze(
        self,
        file: Union[str, Path, BinaryIO],
        use_vt: bool = False,
    ) -> dict:
        """Upload and analyse a file synchronously.

        Returns the full analysis result dict.
        """
        if isinstance(file, (str, Path)):
            path = Path(file)
            with open(path, "rb") as f:
                files = {"file": (path.name, f, "application/octet-stream")}
                return self._request(
                    "POST", "/api/analyze", files=files, data={"use_vt": str(use_vt).lower()}
                ).json()
        else:
            name = getattr(file, "name", "upload")
            files = {"file": (name, file, "application/octet-stream")}
            return self._request(
                "POST", "/api/analyze", files=files, data={"use_vt": str(use_vt).lower()}
            ).json()

    def analyze_async(self, file: Union[str, Path, BinaryIO], use_vt: bool = False) -> dict:
        """Submit a file for asynchronous analysis. Returns ``{task_id: ...}``."""
        if isinstance(file, (str, Path)):
            path = Path(file)
            with open(path, "rb") as f:
                files = {"file": (path.name, f, "application/octet-stream")}
                return self._request(
                    "POST", "/api/analyze/async", files=files, data={"use_vt": str(use_vt).lower()}
                ).json()
        else:
            name = getattr(file, "name", "upload")
            files = {"file": (name, file, "application/octet-stream")}
            return self._request(
                "POST", "/api/analyze/async", files=files, data={"use_vt": str(use_vt).lower()}
            ).json()

    def poll_task(self, task_id: str, poll_interval: float = 2.0, max_wait: float = 300.0) -> dict:
        """Poll an async task until completion."""
        deadline = time.monotonic() + max_wait
        while time.monotonic() < deadline:
            resp = self._get_json(f"/api/tasks/{task_id}")
            if resp.get("status") in ("completed", "failed"):
                return resp
            time.sleep(poll_interval)
        raise TimeoutError(f"Task {task_id} did not complete within {max_wait}s")

    def analyze_url(self, url: str) -> dict:
        """Analyse a URL (downloads and scans the target)."""
        return self._request("POST", "/api/analyze-url", json={"url": url}).json()

    # ── Samples & Search ─────────────────────────────────────────────────

    def get_stats(self) -> dict:
        """Get dashboard statistics."""
        return self._get_json("/api/stats")

    def get_sample(self, sample_id: int) -> dict:
        """Get a single sample by ID."""
        return self._get_json(f"/api/samples/{sample_id}")

    def list_samples(self, limit: int = 50, offset: int = 0) -> dict:
        """List samples with pagination."""
        return self._get_json("/api/samples", limit=limit, offset=offset)

    def search(self, query: str) -> List[dict]:
        """Search samples by filename, hash, or family."""
        return self._get_json("/api/search", q=query)

    # ── Intelligence ─────────────────────────────────────────────────────

    def get_graph(self, sample_id: int) -> dict:
        """Get IOC relationship graph for a sample."""
        return self._get_json(f"/api/graph/{sample_id}")

    def get_timeline(self, sample_id: int) -> List[dict]:
        """Get timeline events for a sample."""
        return self._get_json(f"/api/timeline/{sample_id}")

    def get_clusters(self) -> List[dict]:
        """Get sample clusters."""
        return self._get_json("/api/clusters")

    def get_enrichment(self, sample_id: int) -> dict:
        """Get IOC enrichment data for a sample."""
        return self._get_json(f"/api/enrichment/{sample_id}")

    def export_stix(self, sample_id: int) -> dict:
        """Export a single sample as STIX 2.1 bundle."""
        return self._get_json(f"/api/export/stix/{sample_id}")

    # ── Threat Feeds ─────────────────────────────────────────────────────

    def feed_recent(
        self,
        since: Optional[str] = None,
        verdict: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> dict:
        """Get recent samples feed."""
        params: Dict[str, Any] = {"limit": limit, "offset": offset}
        if since:
            params["since"] = since
        if verdict:
            params["verdict"] = verdict
        return self._get_json("/api/feeds/recent", **params)

    def feed_iocs(
        self,
        since: Optional[str] = None,
        ioc_type: Optional[str] = None,
        limit: int = 500,
        fmt: str = "json",
    ) -> Any:
        """Get aggregated IOC feed. Returns dict for json, str for csv/txt."""
        params: Dict[str, Any] = {"limit": limit, "fmt": fmt}
        if since:
            params["since"] = since
        if ioc_type:
            params["ioc_type"] = ioc_type
        resp = self._request("GET", "/api/feeds/iocs", params=params)
        if fmt in ("csv", "txt"):
            return resp.text
        return resp.json()

    def feed_families(self, since: Optional[str] = None, limit: int = 50) -> dict:
        """Get malware family summary feed."""
        params: Dict[str, Any] = {"limit": limit}
        if since:
            params["since"] = since
        return self._get_json("/api/feeds/families", **params)

    def feed_hashes(
        self,
        hash_type: str = "sha256",
        verdict: str = "malicious",
        fmt: str = "txt",
        limit: int = 10000,
        since: Optional[str] = None,
    ) -> Any:
        """Get hash blocklist. Returns str for txt/csv, dict for json."""
        params: Dict[str, Any] = {
            "hash_type": hash_type, "verdict": verdict, "fmt": fmt, "limit": limit
        }
        if since:
            params["since"] = since
        resp = self._request("GET", "/api/feeds/hashes", params=params)
        if fmt in ("txt", "csv"):
            return resp.text
        return resp.json()

    def feed_stix(self, since: Optional[str] = None, limit: int = 100) -> dict:
        """Get STIX 2.1 bundle feed."""
        params: Dict[str, Any] = {"limit": limit}
        if since:
            params["since"] = since
        return self._get_json("/api/feeds/stix", **params)

    def feed_misp(self, since: Optional[str] = None, limit: int = 100) -> dict:
        """Get MISP-format event feed."""
        params: Dict[str, Any] = {"limit": limit}
        if since:
            params["since"] = since
        return self._get_json("/api/feeds/misp", **params)

    # ── ML ───────────────────────────────────────────────────────────────

    def ml_predict(self, file: Union[str, Path, BinaryIO]) -> dict:
        """Run ML classification on a file."""
        if isinstance(file, (str, Path)):
            path = Path(file)
            with open(path, "rb") as f:
                files = {"file": (path.name, f, "application/octet-stream")}
                return self._request("POST", "/api/ml/predict", files=files).json()
        else:
            name = getattr(file, "name", "upload")
            files = {"file": (name, file, "application/octet-stream")}
            return self._request("POST", "/api/ml/predict", files=files).json()

    def ml_models(self) -> List[dict]:
        """List available ML models."""
        return self._get_json("/api/ml/models")

    # ── Webhooks ─────────────────────────────────────────────────────────

    def create_webhook(self, url: str, events: List[str], secret: Optional[str] = None) -> dict:
        """Register a webhook."""
        payload: Dict[str, Any] = {"url": url, "events": events}
        if secret:
            payload["secret"] = secret
        return self._request("POST", "/api/webhooks", json=payload).json()

    def list_webhooks(self) -> List[dict]:
        """List registered webhooks."""
        return self._get_json("/api/webhooks")

    def delete_webhook(self, hook_id: str) -> dict:
        """Delete a webhook."""
        return self._request("DELETE", f"/api/webhooks/{hook_id}").json()

    # ── Batch Ingest ─────────────────────────────────────────────────────

    def start_ingest(self, source: str = "recent", limit: int = 100, **kwargs) -> dict:
        """Start a batch ingest job."""
        payload = {"source": source, "limit": limit, **kwargs}
        return self._request("POST", "/api/ingest/start", json=payload).json()

    def ingest_status(self) -> dict:
        """Get current ingest job status."""
        return self._get_json("/api/ingest/status")

    def stop_ingest(self) -> dict:
        """Stop the current ingest job."""
        return self._request("POST", "/api/ingest/stop").json()

    # ── Auth ─────────────────────────────────────────────────────────────

    def login(self, username: str, password: str) -> dict:
        """Login and get a JWT token."""
        resp = self._request("POST", "/api/auth/login", json={"username": username, "password": password})
        data = resp.json()
        if "token" in data:
            self._client.headers["Authorization"] = f"Bearer {data['token']}"
        return data

    def register(self, username: str, email: str, password: str) -> dict:
        """Register a new user account."""
        return self._request(
            "POST", "/api/auth/register",
            json={"username": username, "email": email, "password": password},
        ).json()

    def me(self) -> dict:
        """Get current user profile."""
        return self._get_json("/api/auth/me")
