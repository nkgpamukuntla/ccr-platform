# HANDOFF-TIM.md: Evidence Collector / CCR, state of the build

For Tim Hill and the AI assistant he uses. Written 19 October 2026 by D-Biz (Naresh Pamukuntla).
Read this first, then the two repositories. It maps what was built back to Tim's
"Evidence Collector Hosting Package" (29 Sep 2026, rules R1–R11, sections 1–10) and the
"Court Connection Readiness Platform" walkthrough (draft v0.3).

## 1. One-paragraph summary

Tim's handover described a design and a hosting pack; no application code existed. D-Biz
wrote the application and the missing core Terraform, deployed a **dev** environment in a new
AWS account (555509860132, us-east-1, separate from PRISM), and proved the Microsoft path
end to end against a Microsoft CDX E5 test tenant: KMS-signed certificate → token → 7 Graph
reads (all 200) → evidence sealed per office → evaluator with no internet → control states on
a Posture page. The CCR portal (onboarding wizard, consent, members, AOC view) is the front
end; the Evidence Collector design is the engine. Everything is in Terraform (174 resources,
no drift) and two Git repositories.

## 2. Repositories

| Repo | Contents | Start with |
|---|---|---|
| github.com/nkgpamukuntla/evidence-collector | `infra/` Terraform (bootstrap + 9 modules), `docs/` | `docs/DEPLOYMENT.md`, `infra/main.tf` |
| github.com/nkgpamukuntla/ccr-platform | `backend/` FastAPI + worker + evaluator, `frontend/` React, `scripts/`, `docs/` | `README.md`, `backend/app/controls.py` |

Branch model: short-lived branches fast-forwarded into `main`; `main` = what is deployed.

## 3. Map from Tim's handover to the code

| Handover item | Where it is now |
|---|---|
| §3 kms.tf: raw[tenant], signing RSA-2048, fingerprint HMAC-256, secrets | `infra/modules/kms/main.tf` (no root delegation, no CreateGrant, admins manage not use) |
| §3 s3.tf: Object Lock governance 90 d, per-tenant key policy, no bucket keys | `infra/modules/raw-bucket/main.tf` |
| §3 iam.tf: worker / evaluator / terminator | `infra/modules/identity/main.tf` (+ `portal` role) |
| §3 network.tf: evaluator fence | `infra/modules/network/` (`vpc.tf`, `endpoints.tf`, `security_groups.tf`) |
| §3 liveness.tf | `infra/modules/liveness/main.tf` (alarm gated off, R10) |
| §5 worker network, compute, database, state backend | `network`, `compute`, `database` modules; `infra/bootstrap/` |
| §8 KMS-signed certificate (tool "not written yet") | `backend/app/microsoft/certificate.py`, `backend/app/tools/make_cert.py` |
| §7 five Graph application permissions | `backend/app/microsoft/graph.py` (`READS`, `PERMISSIONS`) |
| §7 "unobserved answer withholds adverse result" | `backend/app/controls.py` (`not_observed`, never met, never adverse) |
| §6 migrations create runtime roles; CONNECT granted by bootstrap | `backend/migrations/*.sql`, `backend/app/migrate.py` |
| Walkthrough slides 5, 16 (profiles A–E, path) | `backend/app/profiles.py` (+ tests reproducing slide 16) |
| Walkthrough slides 17, 26 (prerequisites) | `backend/app/prerequisites.py` |
| Walkthrough slide 22 (posture, no composite score) | `frontend/src/pages/Posture.tsx`, `backend/app/routers/microsoft.py` |
| Walkthrough slide 28 (lab counties, seeded issues) | `scripts/lab_scenarios.py` (lab county A implemented) |

## 4. Deviations from the handover, with reasons (please review)

1. **No CI/CD pipelines.** The pack's three GitHub Actions workflows and the OIDC
   `AdministratorAccess` apply role were removed; deploys run from a workstation SSO session.
   Reason: requested by D-Biz; removes a standing high-privilege role. Revisit later.
2. **Break-glass key administrator** `ec-<env>-key-admin` added as a second key admin on every
   key. Reason: with no root delegation (R4), an Identity Center re-provision changes the SSO
   role ARN and would orphan the keys.
3. **RDS IAM authentication** for all runtime roles (`ec_portal`, `ec_worker`,
   `ec_evaluator`); no application DB password exists (strengthens R5).
4. **Database key: AWS-managed `aws/rds` (Option B)**, pending Tim's decision.
5. **Worker and evaluator as scheduled ECS tasks** (EventBridge Scheduler, every 6 h, evaluator
   +20 min) instead of always-on services, for cost. The liveness alarm (R10) is still off: its
   period must be aligned to 6 h and a paging target chosen.
6. **Portal exposure:** CloudFront → VPC origin → internal ALB (no internet-facing origin),
   Cognito with MFA, 8-hour sessions. Portal tasks run in the worker subnets (NAT egress,
   DNS Firewall allowlist adds `*.amazoncognito.com`).
7. **Interface endpoints reduced to ecr.api, ecr.dkr, logs, kms** in dev (cost); the worker
   reaches Secrets Manager and CloudWatch through NAT.
8. **Pack defects fixed:** db-bootstrap could not pull its image (443 egress was VPC-only);
   no RDS CA bundle for `verify-full`; NAT count could exceed public subnets; netnums overlapped
   with >2 AZs.
9. **Dev Microsoft app registration lives in the CDX test tenant** (client id
   `acfac7f2-3c1f-4f1d-87d7-18c8ee03dc3e`), created by `scripts/register_microsoft_app.py`
   via device sign-in, no secret. Production waits for D7.
10. **Collector tenant id = the portal office id.** Each office needs its id in `tenant_ids`
    (tfvars) and one apply before collection (creates its raw key and bucket-policy rule).
11. **Control rule refinement:** only unconditional MFA policies count (not risk-based or
    client-app-limited) — found against the CDX tenant's real policies.

## 5. Current evidence (dev, 19 Oct 2026)

- CDX tenant `m365b547779.onmicrosoft.com`, office "Lab County A", consent granted by its GA.
- Before seeding: control 1 Met, 2 Met, 3 Gap. After seeding lab county A (enforced MFA
  policy → report-only; disabled `lab-admin-sms` with Helpdesk Administrator + SMS only):
  1 Weak, 2 Gap, 3 Gap. Controls 4–5 Not observed, 6–8 Pending (attested).
- Snapshot for `restore` kept locally (not committed).

## 6. How to run and verify

```
# app
cd ccr-platform/backend && uv sync && uv run pytest          # 35 tests, embedded PostgreSQL 16
uv run ruff check . && uv run mypy app
# infra (needs AWS SSO profile for 555509860132)
cd evidence-collector/infra && terraform plan -var-file=envs/dev.tfvars   # expect: No changes
```

Versions are pinned exactly (uv.lock, package-lock.json, Terraform lock file). Terraform 1.16.3
is BUSL-licensed; OpenTofu is a drop-in alternative if OSI open source is required.

## 7. Open questions for Tim

1. D7: home tenant and publisher name for the production app registration.
2. Database key: Option B (aws/rds) or Option A (customer key + scoped CreateGrant)?
3. May the D-Biz Microsoft 365 tenant be onboarded as a test office? (Needs D-Biz IT approval,
   a D-Biz Global Admin consent, and agreement on storing D-Biz sign-in data in dev.)
4. Terraform or OpenTofu?
5. Production: separate AWS account (recommended) and region.
6. Lab matrix: we are creating the free-Entra (no P1) and Business Premium tenants; any
   preference on the Security Defaults on/off read order?

## 8. How to send feedback (for Tim's assistant)

Please reply with a list in this shape, one item per point, so we can act on each:

```
- id: F1
  area: infra | app | rules | docs | process
  file: <path or doc section, if any>
  type: defect | rule-violation | question | suggestion
  rule: <R1..R11 if relevant>
  says: <what you found, one or two sentences>
  want: <the change you want, or the decision>
```

Things we would most value a second look at: `infra/modules/kms/main.tf` key policies against
R4; `infra/modules/raw-bucket/main.tf` bucket policy; `backend/app/controls.py` control
rules; deviations 1, 5 and 6 above.
