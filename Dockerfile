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
RUN useradd --uid 10001 --no-create-home app
WORKDIR /app
COPY --from=backend --chown=app:app /app /app
COPY --from=frontend --chown=app:app /src/dist /app/static
# RDS CA bundle for PGSSLMODE=verify-full (PGSSLROOTCERT is set by the task definition).
ADD --chown=app:app https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem /app/certs/rds-global-bundle.pem
ENV PATH="/app/.venv/bin:$PATH" PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
USER 10001
EXPOSE 8000
# Portal by default; ECS overrides the command for db-bootstrap (python -m app.migrate).
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
