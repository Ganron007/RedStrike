# ============================================================================
# RedStrike — Standalone Agentic Active Directory & ADCS Assessment Engine
# ============================================================================

FROM python:3.12-slim-bookworm

LABEL maintainer="CADRE Platform <https://github.com/Ganron007/RedStrike>"
LABEL description="Policy-gated agentic Active Directory assessment & campaign engine"

ENV PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive \
    REDSTRIKE_HOST=0.0.0.0 \
    REDSTRIKE_PORT=8890

# Install runtime dependencies & toolchain
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        git \
        gcc \
        g++ \
        make \
        libkrb5-dev \
        libssl-dev \
        procps \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy dependency specifications first for layer caching
COPY pyproject.toml requirements.txt ./

# Install python dependencies including AD tools & MCP
RUN pip install --no-cache-dir -U pip setuptools wheel && \
    pip install --no-cache-dir -e ".[dev,mcp]" && \
    pip install --no-cache-dir certipy-ad bloodyAD netexec impacket

# Copy full application source
COPY . .

# Re-install local package in editable mode
RUN pip install --no-cache-dir -e .

WORKDIR /workspace

EXPOSE 8890

ENTRYPOINT ["redstrike"]
CMD ["check"]
