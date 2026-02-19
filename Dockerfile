# =============================================================================
# Dockerfile for LENOOS NET AUDIT v1.0.1
# Multi-stage: lean runtime image with all audit dependencies
# =============================================================================

FROM ubuntu:22.04 AS base

LABEL maintainer="Lenoos"
LABEL description="Lenoos Net Audit v1.0.1 — Swiss Army Knife for Network Security & Diagnostics"
LABEL version="1.0.1"

# Prevent interactive prompts during install
ENV DEBIAN_FRONTEND=noninteractive
ENV TERM=xterm-256color

# ── Ollama defaults (CPU-only) ──
ENV CUDA_VISIBLE_DEVICES=""
ENV OLLAMA_NUM_GPU=0
ENV OLLAMA_HOST=0.0.0.0:11434

# ── Core system packages ──
RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends \
    # Networking & DNS
    curl \
    wget \
    dnsutils \
    knot-dnsutils \
    mtr-tiny \
    whois \
    nmap \
    openssl \
    ca-certificates \
    # JSON / text processing
    jq \
    bc \
    gawk \
    sed \
    grep \
    coreutils \
    # System utilities
    procps \
    iproute2 \
    iputils-ping \
    net-tools \
    # Required for script internals / Ollama installer
    bash \
    zstd \
    # Prometheus exporter HTTP server
    socat \
    && rm -rf /var/lib/apt/lists/*

# ── PDF backend: chromium headless (widely available, no wkhtmltopdf needed) ──
RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends chromium-browser 2>/dev/null || \
    apt-get install -y --no-install-recommends chromium 2>/dev/null || true && \
    rm -rf /var/lib/apt/lists/*

# ── Ollama (CPU-based AI LLM engine for -M flag) ──
# Install Ollama for AI-powered pentest analysis (optional at runtime)
RUN curl -fsSL https://ollama.com/install.sh | sh 2>/dev/null || true

# ── Create default model directory ──
RUN mkdir -p /opt/lenoos-net-audit/models
ENV OLLAMA_MODELS=/opt/lenoos-net-audit/models

# ── Working directory ──
WORKDIR /opt/lenoos-net-audit

# ── Copy the audit script + config ──
COPY lenoos-net-audit.sh /opt/lenoos-net-audit/lenoos-net-audit.sh
COPY pdf.conf /opt/lenoos-net-audit/pdf.conf
RUN chmod +x /opt/lenoos-net-audit/lenoos-net-audit.sh

# ── Create default exports directory ──
RUN mkdir -p /opt/lenoos-net-audit/exports

# ── Health check ──
HEALTHCHECK --interval=60s --timeout=5s --retries=3 \
    CMD bash -n /opt/lenoos-net-audit/lenoos-net-audit.sh || exit 1

# ── Default entrypoint ──
ENTRYPOINT ["bash", "/opt/lenoos-net-audit/lenoos-net-audit.sh"]

# Default: show usage
CMD ["--help"]
