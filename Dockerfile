# syntax=docker/dockerfile:1

FROM python:3.12-slim AS builder

WORKDIR /app

# Install build dependencies (for any compilation requirements)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency files first for layer caching
COPY requirements.txt .
COPY pii_guardrail.py .

# Install Python dependencies
RUN pip install --user --no-cache-dir -r requirements.txt


FROM python:3.12-slim AS runtime

WORKDIR /app

# Create non-root user for security (best practice)
RUN groupadd -g 1000 appgroup && \
    useradd -u 1000 -g appgroup -m -s /bin/bash appuser

COPY --from=builder --chown=appuser:appgroup /root/.local /home/appuser/.local
COPY --chown=appuser:appgroup pii_guardrail.py requirements.txt .

# Set environment variables (can also be passed via docker-compose or -e)
ENV PYTHONPATH=/home/appuser/.local/bin \
    LOG_LEVEL=INFO \
    METRICS_RETENTION_DAYS=30 \
    REDACTION_LOG_DIR=/var/log/pii-guardrail/redaction_logs

# Create log directory owned by appuser
RUN mkdir -p /var/log/pii-guardrail/redaction_logs && \
    chown -R appuser:appgroup /var/log/pii-guardrail

USER appuser

EXPOSE 9090

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:9090/health || exit 1

CMD ["python", "pii_guardrail.py"]
