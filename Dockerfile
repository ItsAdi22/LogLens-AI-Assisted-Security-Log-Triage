# Multi-stage Dockerfile for LogLens (AI-Assisted Security Log Triage)

FROM python:3.12-slim as builder

WORKDIR /build

# Install build tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Install loglens package and dependencies into a dedicated prefix
COPY pyproject.toml README.md ./
COPY src/ src/
RUN pip install --no-cache-dir --prefix=/install .[drain]

# Final runtime stage
FROM python:3.12-slim as runtime

# Security: create non-root user and group
RUN groupadd -g 1000 loglens && \
    useradd -u 1000 -g loglens -s /bin/bash -m loglens

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application source & built-in rules
COPY src/ /app/src/
COPY rules/ /app/rules/
COPY examples/ /app/examples/

# Create configuration and logs mount points
RUN mkdir -p /config /logs && \
    chown -R loglens:loglens /app /config /logs

USER loglens

ENV PYTHONUNBUFFERED=1 \
    LOGLENS_CONFIG_DIR=/config

VOLUME ["/logs", "/config"]

ENTRYPOINT ["loglens"]
CMD ["--help"]

