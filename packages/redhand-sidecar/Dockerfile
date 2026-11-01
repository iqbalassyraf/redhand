# syntax=docker/dockerfile:1.4
# RedHand In-VPC Sidecar - Production Multi-Stage Distroless Container
FROM python:3.11-slim AS builder

WORKDIR /app

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:0.5.20 /uv /bin/uv

# Copy root workspace and install dependencies
COPY pyproject.toml uv.lock ./
COPY packages/redhand-sdk ./packages/redhand-sdk
COPY packages/redhand-sidecar ./packages/redhand-sidecar

RUN uv sync --frozen --no-dev --package redhand-sidecar

# Runtime stage: slim non-root container
FROM python:3.11-slim AS runner

WORKDIR /app

RUN groupadd -g 10001 redhand && \
    useradd -u 10001 -g redhand -s /bin/false -m redhand

COPY --from=builder --chown=redhand:redhand /app/.venv /app/.venv
COPY --from=builder --chown=redhand:redhand /app/packages /app/packages

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PORT=8080

USER 10001:10001

EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
  CMD curl -f http://localhost:8080/healthz || exit 1

ENTRYPOINT ["uvicorn", "redhand_sidecar.proxy:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "2"]

