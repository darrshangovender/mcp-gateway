# --- build stage: resolve and install into an isolated venv --------------
FROM python:3.12-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY pyproject.toml README.md LICENSE ./
COPY mcp_gateway ./mcp_gateway
COPY examples ./examples
RUN pip install ".[server,redis]"

# --- runtime stage: slim image, non-root, only the venv ------------------
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    MCP_GATEWAY_AUDIT_PATH=/var/lib/mcp-gateway/audit.jsonl

RUN groupadd --system gateway && useradd --system --gid gateway --home /app gateway \
    && mkdir -p /app /var/lib/mcp-gateway \
    && chown -R gateway:gateway /app /var/lib/mcp-gateway

COPY --from=builder /opt/venv /opt/venv
COPY --chown=gateway:gateway examples /app/examples

WORKDIR /app
USER gateway
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz').status == 200 else 1)"

CMD ["uvicorn", "examples.crm_server:app", "--host", "0.0.0.0", "--port", "8000"]
