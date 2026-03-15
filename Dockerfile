# HashGuard SaaS — Production Docker Image
FROM python:3.12-slim AS base

# System deps for yara, pefile, crypto
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ make libffi-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies (core + SaaS)
COPY pyproject.toml README.md ./
COPY src/ src/
RUN pip install --no-cache-dir -e "." \
    sqlalchemy[asyncio] alembic psycopg2-binary celery[redis] \
    python-dotenv itsdangerous bcrypt boto3 stripe \
    && pip install --no-cache-dir lief networkx stix2 || true

# Non-root user
RUN useradd -m -r hashguard && chown -R hashguard:hashguard /app
USER hashguard

EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/health')" || exit 1

CMD ["uvicorn", "hashguard.web.api:app", "--host", "0.0.0.0", "--port", "8000"]
