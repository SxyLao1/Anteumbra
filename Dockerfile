# Anteumbra v1.0.30 - Web Perimeter Threat Intelligence
# Multi-stage build with a dedicated runtime virtualenv.

FROM python:3.12-slim AS builder

ENV DEBIAN_FRONTEND=noninteractive
ENV VIRTUAL_ENV=/opt/venv
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    make \
    libfuzzy-dev \
    libssl-dev \
    libffi-dev \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv "$VIRTUAL_ENV" \
    && pip install --no-cache-dir --upgrade pip setuptools wheel \
    && pip install --no-cache-dir 'yara-python>=4.5.0' \
    && (pip install --no-cache-dir ssdeep || echo "[Docker] ssdeep skipped; fuzzy hashing will degrade gracefully") \
    && (pip install --no-cache-dir py-tlsh || echo "[Docker] py-tlsh skipped; TLSH hashing will degrade gracefully") \
    && pip install --no-cache-dir \
    'flask>=2.3.3,<3.0.0' \
    'flask-wtf>=1.2.1' \
    'flask-session>=0.8.0,<1.0.0' \
    'cachelib>=0.13.0' \
    'flask-babel>=3.1.0' \
    'wtforms>=3.1.2' \
    'watchdog>=3.0.0' \
    'click>=8.1.0' \
    'requests>=2.32.3' \
    'psutil>=5.9.8' \
    'tomli>=2.0.1' \
    'tomli-w>=1.0.0' \
    'colorama>=0.4.6' \
    'urllib3>=2.2.2' \
    'python-dotenv>=1.0.0' \
    'waitress>=3.0.0,<4.0.0'

FROM python:3.12-slim

LABEL maintainer="SxyLao1"
LABEL org.opencontainers.image.title="Anteumbra"
LABEL org.opencontainers.image.version="1.0.30"
LABEL org.opencontainers.image.description="Web Perimeter Threat Intelligence - passive detection, attacker profiling, IP block"
LABEL org.opencontainers.image.url="https://github.com/SxyLao1/Anteumbra"

ENV DEBIAN_FRONTEND=noninteractive
ENV VIRTUAL_ENV=/opt/venv
ENV PATH="$VIRTUAL_ENV/bin:$PATH"
ENV ANTEUMBRA_HOME=/app
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libfuzzy2 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /opt/venv /opt/venv

COPY README.md .
COPY pyproject.toml .
COPY src/anteumbra/config.toml ./config.toml
COPY src/ ./src/
COPY scripts/docker-entrypoint.sh /usr/local/bin/anteumbra-docker-entrypoint

RUN pip install --no-cache-dir --no-deps . \
    && mkdir -p data/registry data/quarantine data/wal data/sessions data/archives data/threat_intel data/siem logs sites/default rules \
    && cp -r src/anteumbra/rules/webshell rules/webshell \
    && sed -i 's/\r$//' /usr/local/bin/anteumbra-docker-entrypoint \
    && chmod +x /usr/local/bin/anteumbra-docker-entrypoint \
    && useradd --create-home --shell /bin/bash anteumbra \
    && chown -R anteumbra:anteumbra /app /opt/venv

USER anteumbra

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/api/v1/health', timeout=5)" || exit 1

EXPOSE 8080

ENTRYPOINT ["anteumbra-docker-entrypoint"]
CMD ["anteumbra", "run", "--host", "0.0.0.0", "--port", "8080"]
