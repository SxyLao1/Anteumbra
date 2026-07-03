# Anteumbra v1.0.5 — Web Perimeter Threat Intelligence
# Multi-stage build: compile native deps → slim runtime
# Linux 三轨哈希全激活: ssdeep + py-tlsh + yara-python

# ── Stage 1: Builder ──────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

# Build dependencies for native extensions
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    make \
    libfuzzy-dev \
    libssl-dev \
    libffi-dev \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python packages with native compilation
# Note: ssdeep / py-tlsh use legacy pkg_resources (removed in setuptools >=68),
# so they are installed with fallback — the app works without them.
COPY pyproject.toml .
RUN pip install --no-cache-dir --upgrade pip setuptools wheel \
    && pip install --no-cache-dir --user yara-python>=4.3.0 \
    && pip install --no-cache-dir --user ssdeep 2>/dev/null || echo "[Docker] ssdeep skipped (build incompatible)" \
    && pip install --no-cache-dir --user py-tlsh 2>/dev/null || echo "[Docker] py-tlsh skipped (build incompatible)" \
    && pip install --no-cache-dir --user \
    'flask>=2.3.3,<3.0.0' \
    flask-wtf>=1.2.1 \
    flask-session>=0.5.0 \
    flask-babel>=3.1.0 \
    wtforms>=3.1.2 \
    watchdog>=3.0.0 \
    click>=8.1.0 \
    requests>=2.32.3 \
    psutil>=5.9.8 \
    tomli>=2.0.1 \
    tomli-w>=1.0.0 \
    colorama>=0.4.6 \
    urllib3>=2.2.2 \
    python-dotenv>=1.0.0 \
    gunicorn>=22.0.0

# ── Stage 2: Runtime ──────────────────────────────────────
FROM python:3.12-slim

LABEL maintainer="SxyLao1"
LABEL org.opencontainers.image.title="Anteumbra"
LABEL org.opencontainers.image.version="1.0.5"
LABEL org.opencontainers.image.description="Web Perimeter Threat Intelligence — passive detection, attacker profiling, IP block"
LABEL org.opencontainers.image.url="https://github.com/SxyLao1/Anteumbra"

WORKDIR /app

# Runtime deps: libfuzzy (for ssdeep) + ca-certificates
RUN apt-get update && apt-get install -y --no-install-recommends \
    libfuzzy2 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy compiled Python packages from builder
COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local/bin:$PATH

# Copy application source
COPY src/ ./src/
COPY pyproject.toml .
COPY translations/ ./translations/

# Install the package itself (editable not needed in container)
RUN pip install --no-cache-dir --no-deps -e . \
    || pip install --no-cache-dir --no-deps .

# Create data directories with proper permissions
RUN mkdir -p data/registry data/quarantine data/wal data/sessions data/archives logs \
    && chmod -R 755 data logs

# Run as non-root
RUN useradd --create-home --shell /bin/bash anteumbra \
    && chown -R anteumbra:anteumbra /app
USER anteumbra

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/api/v1/health', timeout=5)" || exit 1

EXPOSE 8080

# Gunicorn with Flask app factory, 4 workers, access log to stdout
CMD ["gunicorn", "anteumbra.interfaces.web.factory:create_app()", \
     "--bind", "0.0.0.0:8080", \
     "--workers", "4", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "--access-logformat", "%(h)s %(l)s %(u)s %(t)s \"%(r)s\" %(s)s %(b)s \"%(f)s\" \"%(a)s\""]
