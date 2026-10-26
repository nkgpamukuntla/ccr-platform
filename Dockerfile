# syntax=docker/dockerfile:1
# linux/arm64 only (R8): built natively on an ARM CodeBuild host. Official images via the
# ECR Public mirror (no Docker Hub rate limits). TODO: pin each FROM by digest.
FROM public.ecr.aws/docker/library/node:22-bookworm-slim AS frontend
WORKDIR /src
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM ghcr.io/astral-sh/uv:0.8.22 AS uv

FROM public.ecr.aws/docker/library/python:3.12-slim-bookworm AS backend
COPY --from=uv /uv /bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
WORKDIR /app
COPY backend/pyproject.toml backend/uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY backend/app ./app
COPY backend/migrations ./migrations

FROM public.ecr.aws/docker/library/python:3.12-slim-bookworm
# Open Policy Agent, the engine ScubaGear 1.8.0 uses (default 1.15.2), to run the vendored SCuBA
# rules inside the fenced evaluator. Pinned and checked against the release's published SHA-256.
ARG OPA_VERSION=1.15.2
ARG OPA_SHA256=6651bf5a80cfec6ba6a2d3b6a550b8f748d9cade1c74d54b5f854782f9bea67a
ADD --checksum=sha256:${OPA_SHA256} https://github.com/open-policy-agent/opa/releases/download/v${OPA_VERSION}/opa_linux_arm64_static /usr/local/bin/opa
RUN chmod 0755 /usr/local/bin/opa && /usr/local/bin/opa version
RUN useradd --uid 10001 --no-create-home app
WORKDIR /app
COPY --from=backend --chown=app:app /app /app
COPY --from=frontend --chown=app:app /src/dist /app/static
# RDS CA bundle for PGSSLMODE=verify-full (PGSSLROOTCERT is set by the task definition).
ADD --chown=app:app https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem /app/certs/rds-global-bundle.pem
# Offline collector, Authenticode-signed by scripts/sign-collector.sh just before this build.
# Last, so the pre-sign build in that script shares every layer above.
COPY --chown=app:app collector /app/collector
ENV PATH="/app/.venv/bin:$PATH" PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
USER 10001
EXPOSE 8000
# Portal by default; ECS overrides the command for db-bootstrap (python -m app.migrate).
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
