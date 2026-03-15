# HashGuard API Reference

> **Version:** 1.1.4  
> **Framework:** FastAPI  
> **Base URL:** `http://localhost:8000`  
> **Interactive Docs:** `GET /api/docs` (Swagger UI)

---

## Table of Contents

- [Authentication](#authentication)
- [Rate Limiting](#rate-limiting)
- [Analysis](#analysis)
- [Samples](#samples)
- [Intelligence & Enrichment](#intelligence--enrichment)
- [Sandbox](#sandbox)
- [Memory Analysis](#memory-analysis)
- [Dataset](#dataset)
- [ML Training](#ml-training)
- [Anomaly Detection](#anomaly-detection)
- [Batch Ingest](#batch-ingest)
- [Webhooks](#webhooks)
- [Threat Feeds](#threat-feeds)
- [SOC Integrations](#soc-integrations)
- [Teams](#teams)
- [Billing](#billing)
- [Admin](#admin)
- [Dataset Hub](#dataset-hub)
- [Settings](#settings)
- [Error Handling](#error-handling)

---

## Authentication

Authentication is **optional** by default. Enable it by setting `HASHGUARD_AUTH=1`.

Two methods are supported:

| Method | Header | Format |
|--------|--------|--------|
| API Key | `X-API-Key` | Raw key string |
| JWT Bearer | `Authorization` | `Bearer <token>` |

### Roles & Permissions

| Role | Permissions |
|------|-------------|
| `admin` | Full access — manage keys, settings, training, export, ingest |
| `analyst` | Analyze, search, export, ingest |
| `viewer` | Read-only — view samples, stats, feeds |

### `POST /api/auth/token`

Exchange an API key for a JWT token.

**Request (Form):**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `api_key` | string | required | Valid API key |
| `expiry` | int | `86400` | Token TTL in seconds |

**Response:**
```json
{
  "access_token": "eyJ...",
  "token_type": "bearer",
  "expires_in": 86400,
  "role": "analyst"
}
```

### `POST /api/auth/keys`

Create a new API key. **Requires:** `admin` role.

**Request (Form):**

| Field | Type | Default |
|-------|------|---------|
| `name` | string | required |
| `role` | string | `"analyst"` |

### `GET /api/auth/keys`

List all API keys. **Requires:** `admin` role.

### `DELETE /api/auth/keys/{key_id}`

Revoke an API key. **Requires:** `admin` role.

---

## Rate Limiting

Requests are rate-limited per plan using [slowapi](https://github.com/laurentS/slowapi):

| Plan | Analyze | Search | Ingest | ML Train |
|------|---------|--------|--------|----------|
| Free | 10/min | 15/min | 0/min | 1/min |
| Pro | 60/min | 60/min | 0/min | 5/min |
| Team | 120/min | 120/min | 10/min | 10/min |
| Enterprise | 600/min | 600/min | 60/min | 60/min |

Rate-limited responses return `429 Too Many Requests`.

---

## Analysis

### `POST /api/analyze`

Upload and analyze a file. Returns the complete analysis including hashes, PE info, YARA matches, ML classification, risk score, capabilities, IOCs, and more.

**Rate Limit:** 30/minute (plan-dependent)  
**Permission:** `analyze`

**Request:** `multipart/form-data`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `file` | File | required | File to analyze |
| `use_vt` | bool | `false` | Query VirusTotal |

**Response:** Full `FileAnalysisResult` JSON — includes `sha256`, `verdict`, `risk_score`, `pe_info`, `yara_matches`, `ml_classification`, `capabilities`, `iocs`, `family`, `timeline`, etc.

### `POST /api/analyze-url`

Analyze a URL (downloads and scans the target).

**Rate Limit:** 10/minute (plan-dependent)  
**Permission:** `analyze`

**Request (Form):**

| Field | Type | Default |
|-------|------|---------|
| `url` | string | required |
| `use_vt` | bool | `false` |

### `POST /api/analyze/async`

Submit a file for asynchronous analysis via Celery. Returns a task ID to poll.

**Rate Limit:** 30/minute  
**Permission:** `analyze`

**Request:** Same as `/api/analyze`.

**Response:**
```json
{
  "task_id": "abc123...",
  "status": "queued",
  "detail": "Analysis queued"
}
```

### `GET /api/tasks/{task_id}`

Poll the status of an async analysis task.

**Response:**
```json
{
  "task_id": "abc123...",
  "status": "completed",
  "result": { ... }
}
```

Status values: `queued`, `running`, `completed`, `failed`.

---

## Samples

### `GET /api/stats`

Dashboard statistics: totals, detection rate, top families, verdict distribution.

**Response:**
```json
{
  "total_samples": 1234,
  "malicious": 567,
  "clean": 667,
  "detection_rate": 0.459,
  "top_families": [["Emotet", 42], ["AgentTesla", 31]],
  "recent_samples": [...],
  "verdict_distribution": {"malicious": 567, "clean": 667, "suspicious": 0}
}
```

### `GET /api/samples`

List analyzed samples with pagination.

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `limit` | int (1–1000) | 100 | Page size |
| `offset` | int (≥ 0) | 0 | Offset |

### `GET /api/samples/{sample_id}`

Full sample detail including IOCs, behaviors, timeline, and IOC graph.

### `GET /api/search`

Search samples and IOCs by query string.

**Rate Limit:** 30/minute  

| Param | Type | Description |
|-------|------|-------------|
| `q` | string (min 1 char) | Search term (hash, filename, family, IP, domain) |

**Response:**
```json
{
  "samples": [...],
  "iocs": [...]
}
```

---

## Intelligence & Enrichment

### `GET /api/graph/{sample_id}`

IOC relationship graph in vis.js-compatible format (nodes + edges).

### `GET /api/timeline/{sample_id}`

Kill-chain timeline for a sample (phases, events, severity).

### `GET /api/clusters`

Malware clusters based on behavioral similarity.

### `GET /api/enrichment/{sample_id}`

Enrich sample IOCs with WHOIS, GeoIP, AbuseIPDB, URLhaus data.

### `GET /api/export/stix/{sample_id}`

Export sample as a STIX 2.1 Bundle (Indicator, Malware, Relationship objects).

**Permission:** `export`

---

## Sandbox

### `GET /api/sandbox/status`

Check sandbox availability.

**Response:**
```json
{
  "any_available": true
}
```

### `POST /api/sandbox/enhanced-monitor`

Run enhanced monitoring (filesystem diffs, ETW tracing, registry monitoring).

**Rate Limit:** 5/minute

| Field | Type | Default | Range |
|-------|------|---------|-------|
| `duration` | int | 30 | 5–120 seconds |

---

## Memory Analysis

### `POST /api/memory/analyze`

Run memory/injection analysis on a stored sample.

| Field | Type | Description |
|-------|------|-------------|
| `sample_id` | int | Sample ID from database |

---

## Dataset

### `GET /api/dataset/stats`

Dataset summary (sample counts, feature statistics).

### `GET /api/dataset/export`

Export the full ML dataset.

| Param | Type | Options |
|-------|------|---------|
| `fmt` | string | `csv`, `jsonl`, `parquet` |

### `GET /api/dataset/export/anonymized`

Export dataset with PII removed (hashes, filenames anonymized).

| Param | Type | Options |
|-------|------|---------|
| `fmt` | string | `csv`, `jsonl`, `parquet` |

### `GET /api/dataset/features/{sample_id}`

Get extracted ML feature vector for a specific sample.

### `GET /api/dataset/versions`

List all versioned dataset snapshots.

### `POST /api/dataset/versions`

Create a versioned snapshot of the current dataset.

| Param | Type | Description |
|-------|------|-------------|
| `version` | string | Semver format (`1.0.0`) |
| `fmt` | string | `parquet`, `csv`, `jsonl` |
| `notes` | string | Optional description |

### `GET /api/dataset/versions/{version}/download`

Download a specific dataset version.

---

## ML Training

### `POST /api/ml/train`

Start an ML training job.

**Rate Limit:** 2/minute  
**Permission:** `train`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `mode` | string | `"binary"` | Training mode |
| `algorithm` | string | `"random_forest"` | Algorithm |
| `test_size` | float | `0.2` | Test split ratio |

### `GET /api/ml/status`

Current training job status.

### `GET /api/ml/models`

List all trained models.

### `GET /api/ml/models/{model_id}`

Metrics and details for a specific model.

### `DELETE /api/ml/models/{model_id}`

Delete a trained model.

### `POST /api/ml/predict`

Run prediction on a dataset sample using the trained model.

| Field | Type | Description |
|-------|------|-------------|
| `sample_id` | int | Sample ID |

---

## Anomaly Detection

### `POST /api/anomaly/train`

Train the anomaly detection model (Isolation Forest + Mahalanobis distance).

**Rate Limit:** 2/minute  
**Permission:** `train`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `contamination` | float | `0.05` | Expected anomaly ratio |
| `min_samples` | int | `200` | Minimum samples required |

### `POST /api/anomaly/detect`

Detect anomalies for a dataset sample.

| Field | Type | Description |
|-------|------|-------------|
| `sample_id` | int | Sample ID |

---

## Batch Ingest

### `POST /api/ingest/start`

Start a batch ingest job from threat feeds or a local directory.

**Rate Limit:** 5/minute  
**Permission:** `ingest`

| Field | Type | Description |
|-------|------|-------------|
| `source` | string | `recent`, `tag`, `filetype`, `mixed`, `local`, `continuous`, `benign` |
| `limit` | int | Max samples to ingest |
| `tag` | string | MalwareBazaar tag (if `source=tag`) |
| `file_type` | string | File type filter (if `source=filetype`) |
| `directory` | string | Local path (if `source=local`) |

### `GET /api/ingest/status`

Current ingest job progress.

### `POST /api/ingest/stop`

Stop the running ingest job.

---

## Webhooks

### `POST /api/webhooks`

Create a webhook that fires on analysis events.

**Permission:** `webhooks` feature

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | string | required | Webhook name |
| `url` | string | required | Target URL |
| `events` | string | required | Comma-separated: `analysis.complete`, `analysis.malicious`, `ingest.complete` |
| `min_risk_score` | int | `0` | Minimum risk score to trigger (0–100) |

### `GET /api/webhooks`

List all configured webhooks.

### `PUT /api/webhooks/{hook_id}`

Update webhook configuration.

### `DELETE /api/webhooks/{hook_id}`

Delete a webhook.

### `POST /api/webhooks/{hook_id}/test`

Send a test payload to verify webhook connectivity.

---

## Threat Feeds

Public feeds for integration with SIEMs, threat intel platforms, and blocklists.

### `GET /api/feeds/recent`

Recent malicious/suspicious samples (paginated).

### `GET /api/feeds/iocs`

Aggregated IOC feed — IPs, domains, URLs, hashes.

### `GET /api/feeds/families`

Malware family summary with sample counts.

### `GET /api/feeds/hashes`

Hash blocklist (SHA256 / MD5 / SHA1).

### `GET /api/feeds/stix`

STIX 2.1 bundle feed.

### `GET /api/feeds/taxii`

TAXII 2.1 discovery endpoint (stub).

### `GET /api/feeds/misp`

MISP-format event feed.

---

## SOC Integrations

### `GET /api/soc/integrations`

List configured SOC integrations.

### `POST /api/soc/integrations`

Create a new SOC integration.

Supported types: `syslog`, `splunk`, `elastic`, `sentinel`.

### `PUT /api/soc/integrations/{integration_id}`

Update integration configuration.

### `DELETE /api/soc/integrations/{integration_id}`

Delete an integration.

---

## Teams

### `POST /api/teams`

Create a new team.

### `GET /api/teams/current`

Get current user's team info and members.

### `POST /api/teams/invite`

Invite a member by email.

### `POST /api/teams/invite/accept`

Accept a team invitation (provide invite token).

### `PUT /api/teams/members/{member_user_id}`

Update a team member's role.

### `DELETE /api/teams/members/{member_user_id}`

Remove a member from the team.

---

## Billing

### `GET /api/billing/plans`

List available plans and pricing.

### `GET /api/billing/current`

Current plan and usage for the authenticated user.

### `POST /api/billing/checkout`

Create a Stripe checkout session for plan upgrade.

### `POST /api/billing/portal`

Create a Stripe customer portal session.

### `POST /api/billing/webhook`

Stripe webhook handler (called by Stripe).

### `GET /api/billing/usage`

Usage statistics for the current billing period.

---

## Admin

All admin endpoints require `admin` role.

### `GET /api/admin/tenants`

List all tenants.

### `GET /api/admin/tenants/{tenant_id}`

Get tenant details.

### `PUT /api/admin/tenants/{tenant_id}/role`

Update a tenant's role.

### `PUT /api/admin/tenants/{tenant_id}/plan`

Update a tenant's plan.

### `GET /api/admin/stats`

Platform-wide admin statistics.

### `GET /api/admin/activity`

Platform activity log.

### `GET /api/admin/audit-logs`

Paginated audit logs.

### `GET /api/admin/audit-logs/actions`

List available audit log action types.

---

## Dataset Hub

### `GET /api/dataset/hub/status`

Check which hub platforms (HuggingFace, Kaggle) are configured.

### `POST /api/dataset/hub/huggingface/publish`

Publish the current dataset to HuggingFace.

### `POST /api/dataset/hub/kaggle/publish`

Publish the current dataset to Kaggle.

---

## Settings

### `GET /api/settings`

Get current API key configuration (keys are masked).

### `POST /api/settings`

Save API keys for external services.

**Permission:** `settings`

| Field | Type | Description |
|-------|------|-------------|
| `vt_api_key` | string | VirusTotal API key |
| `abuse_ch_api_key` | string | Abuse.ch API key |
| `malshare_api_key` | string | MalShare API key |
| `hybrid_analysis_api_key` | string | Hybrid Analysis API key |
| `triage_api_key` | string | Triage API key |

---

## Error Handling

All errors return JSON:

```json
{
  "detail": "Error description"
}
```

| Status | Meaning |
|--------|---------|
| `400` | Bad request / validation error |
| `401` | Unauthorized — missing or invalid credentials |
| `403` | Forbidden — insufficient permissions |
| `404` | Resource not found |
| `429` | Rate limit exceeded |
| `500` | Internal server error |

---

## Middleware

| Middleware | Description |
|-----------|-------------|
| CORS | Configurable origins via `DOMAIN` env var |
| CSRF | Enabled in production (`HASHGUARD_ENV=production`) |
| Prometheus | Request duration and status metrics at `/metrics` |
| Rate Limiter | Plan-based dynamic limits via slowapi |
