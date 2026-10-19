# Court Connection Readiness platform

Discover, assess, recommend and track remediation of court endpoints before they connect
to GAVEL. Built from the solution walkthrough (draft v0.3) and the Evidence Collector design
(rules R1–R11). Infrastructure lives in
[nkgpamukuntla/evidence-collector](https://github.com/nkgpamukuntla/evidence-collector) (`infra/`).

**What is deployed today:** [DEPLOYMENT.md](https://github.com/nkgpamukuntla/evidence-collector/blob/main/docs/DEPLOYMENT.md)
(portal: https://d2589qqp8c0e2b.cloudfront.net).

## Stack (open source)

| Layer | Choice |
|---|---|
| API | Python 3.12, FastAPI, psycopg 3, plain SQL migrations |
| Portal | React 18, Vite, TypeScript (served by the API from one image) |
| Data | PostgreSQL 16 (RDS), raw evidence in S3, credentials in Secrets Manager |
| Sign-in | Amazon Cognito (OIDC code + PKCE, MFA required) |
| Hosting | ECS Fargate ARM64 behind an internal ALB, published through CloudFront |
| Tooling | uv, ruff, mypy (strict), pytest; image built in AWS CodeBuild |

## Build phases (walkthrough slide 12)

| Phase | Delivers | Status |
|---|---|---|
| 1 Foundation | Tenancy, consent records, vault, portal shell, audit, 6-step onboarding wizard | **this release** |
| 2 Microsoft path | Graph / Intune connector via KMS-signed app, ScubaGear, MFA and CA rules, posture view | next |
| 3 Collector + import | Signed collector, bundle intake, CSV templates, validation | |
| 4 EDR connectors | CrowdStrike first, then Defender, SentinelOne, Cortex | |
| 5 Findings to remediation | Reconciliation, findings, tracker, evidence pack | |
| 6 POC and pilot | Readiness gate, three pilot counties | |

## Run locally (no Docker, no admin rights)

```powershell
# backend: tests spin up an embedded PostgreSQL 16 (pgserver)
cd backend
uv sync
uv run pytest
uv run ruff check . ; uv run mypy app

# frontend
cd ..\frontend
npm ci
npm run build          # or `npm run dev` with uvicorn on :8000 (AUTH_MODE=dev, ENVIRONMENT=local)
```

`AUTH_MODE=dev` picks the user from an `X-Dev-User` header and is refused unless `ENVIRONMENT=local`.

## Build and deploy

```powershell
.\scripts\build-image.ps1 -Environment dev      # CodeBuild (ARM) builds HEAD, prints the tag
# then in the infra repo: write the tag into infra/envs/dev.image, terraform plan, apply
# migrations: run the ec-dev-db-bootstrap task once (see infra README)
```
