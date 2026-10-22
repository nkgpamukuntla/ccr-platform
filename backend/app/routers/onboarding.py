"""Steps 2-6: environment, prerequisites, connect (consent + credentials), import/collect, validate."""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import APIRouter, HTTPException, status
from psycopg.types.json import Jsonb
from pydantic import BaseModel, Field

from app import audit, prerequisites, vault
from app.access import can_read, can_write
from app.auth import CurrentUser
from app.config import get_settings
from app.db import tx
from app.microsoft.graph import PERMISSIONS
from app.profiles import EnvironmentAnswers, PathItem, ProfileResult, classify
from app.routers.offices import complete_step

router = APIRouter(prefix="/api/offices/{office_id}", tags=["onboarding"])
preview_router = APIRouter(prefix="/api", tags=["onboarding"])


@preview_router.post("/profile/preview")
def preview(answers: EnvironmentAnswers, user: CurrentUser) -> ProfileResult:
    """The path recalculates live as answers change; nothing is stored."""
    return classify(answers)


# What each source's consent covers, shown before consent (walkthrough slide 18).
CONSENT_SCOPES = {"microsoft365": PERMISSIONS}


# Read through the Microsoft 365 consent; they never take a key of their own.
COVERED_BY_MICROSOFT = {"intune", "defender"}


class ConsentIn(BaseModel):
    tenant_ref: str | None = Field(default=None, max_length=200)


class SecretIn(BaseModel):
    value: str = Field(min_length=8, max_length=8192)


def _profile(conn: Any, office_id: UUID) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM environment_profile WHERE office_id = %s", (office_id,)).fetchone()
    if row is None:
        raise HTTPException(status.HTTP_409_CONFLICT, "complete step 2 (environment) first")
    return dict(row)


# ---------- step 2 ----------
@router.put("/environment")
def save_environment(office_id: UUID, answers: EnvironmentAnswers, user: CurrentUser) -> ProfileResult:
    result = classify(answers)
    with tx() as conn:
        can_write(conn, user, office_id)
        conn.execute(
            "INSERT INTO environment_profile (office_id, answers, profile, path, updated_by) "
            "VALUES (%s, %s, %s, %s, %s) ON CONFLICT (office_id) DO UPDATE SET answers = EXCLUDED.answers, "
            "profile = EXCLUDED.profile, path = EXCLUDED.path, updated_at = now(), updated_by = EXCLUDED.updated_by",
            (office_id, Jsonb(answers.model_dump()), result.profile, Jsonb([p.model_dump() for p in result.path]), user.email),
        )
        for p in result.path:
            conn.execute(
                "INSERT INTO connection (office_id, source, mode) VALUES (%s, %s, %s) "
                "ON CONFLICT (office_id, source) DO UPDATE SET mode = EXCLUDED.mode, updated_at = now()",
                (office_id, p.source, p.mode),
            )
        conn.execute(
            "DELETE FROM connection WHERE office_id = %s AND NOT (source = ANY(%s))",
            (office_id, [p.source for p in result.path]),
        )
        complete_step(conn, office_id, 2)
        audit.record(conn, user, "onboarding.environment", office_id, profile=result.profile)
    return result


@router.get("/environment")
def get_environment(office_id: UUID, user: CurrentUser) -> dict[str, Any]:
    with tx() as conn:
        can_read(conn, user, office_id)
        row = conn.execute("SELECT * FROM environment_profile WHERE office_id = %s", (office_id,)).fetchone()
        if row is None:
            return {}
        return dict(classify(EnvironmentAnswers(**row["answers"])).model_dump(), answers=row["answers"])


# ---------- step 3 ----------
@router.get("/prerequisites")
def get_prerequisites(office_id: UUID, user: CurrentUser) -> list[prerequisites.Prerequisite]:
    with tx() as conn:
        can_read(conn, user, office_id)
        path = [PathItem(**p) for p in _profile(conn, office_id)["path"]]
    return prerequisites.generate(path)


@router.post("/prerequisites/ack")
def ack_prerequisites(office_id: UUID, user: CurrentUser) -> dict[str, str]:
    with tx() as conn:
        can_write(conn, user, office_id)
        _profile(conn, office_id)
        complete_step(conn, office_id, 3)
        audit.record(conn, user, "onboarding.prerequisites_ack", office_id)
    return {"status": "acknowledged"}


# ---------- step 4: consent and credentials ----------
@router.get("/connections")
def connections(office_id: UUID, user: CurrentUser) -> list[dict[str, Any]]:
    with tx() as conn:
        can_read(conn, user, office_id)
        rows = conn.execute(
            "SELECT c.source, c.mode, c.status, c.last_test_at, c.secret_arn IS NOT NULL AS has_credential, "
            "k.status AS consent_status, k.granted_at, k.tenant_ref, k.scopes AS granted_scopes "
            "FROM connection c LEFT JOIN consent k ON k.office_id = c.office_id AND k.source = c.source "
            "AND k.status = 'granted' WHERE c.office_id = %s ORDER BY c.source",
            (office_id,),
        ).fetchall()
        for r in rows:
            r["scopes"] = CONSENT_SCOPES.get(r["source"], [])
            granted = set(r.pop("granted_scopes") or [])
            # Consent given before permissions were added must be granted again to cover them.
            r["consent_outdated"] = r["consent_status"] == "granted" and bool(set(r["scopes"]) - granted)
        return rows


@router.post("/consents/{source}", status_code=status.HTTP_201_CREATED)
def grant_consent(office_id: UUID, source: str, body: ConsentIn, user: CurrentUser) -> dict[str, str]:
    """Records the office's consent for sources without an online consent flow.

    Microsoft 365 uses the admin-consent redirect (routers/microsoft.py) once the app is configured."""
    if source == "microsoft365" and get_settings().ms_client_id:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "Microsoft 365 consent is granted by the tenant's administrator through Microsoft"
        )
    with tx() as conn:
        can_write(conn, user, office_id)
        conn.execute(
            "INSERT INTO consent (office_id, source, status, scopes, tenant_ref, granted_by) "
            "VALUES (%s, %s, 'granted', %s, %s, %s) ON CONFLICT DO NOTHING",
            (office_id, source, Jsonb(CONSENT_SCOPES.get(source, [])), body.tenant_ref, user.email),
        )
        audit.record(conn, user, "consent.grant", office_id, source=source, tenant_ref=body.tenant_ref)
    return {"status": "granted"}


@router.post("/consents/{source}/revoke")
def revoke_consent(office_id: UUID, source: str, user: CurrentUser) -> dict[str, str]:
    with tx() as conn:
        can_write(conn, user, office_id)
        cur = conn.execute(
            "UPDATE consent SET status = 'revoked', revoked_by = %s, revoked_at = now() "
            "WHERE office_id = %s AND source = %s AND status = 'granted'",
            (user.email, office_id, source),
        )
        if cur.rowcount == 0:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "no active consent")
        audit.record(conn, user, "consent.revoke", office_id, source=source)
    return {"status": "revoked"}


@router.put("/connections/{source}/credential")
def store_credential(office_id: UUID, source: str, body: SecretIn, user: CurrentUser) -> dict[str, str]:
    """Write-only: the value goes to Secrets Manager and is never returned or logged."""
    with tx() as conn:
        can_write(conn, user, office_id)
        row = conn.execute("SELECT mode FROM connection WHERE office_id = %s AND source = %s", (office_id, source)).fetchone()
        if source in COVERED_BY_MICROSOFT:
            raise HTTPException(status.HTTP_409_CONFLICT, f"{source} is read through the Microsoft 365 consent; no key is needed")
        if row is None or row["mode"] != "connect":
            raise HTTPException(status.HTTP_409_CONFLICT, f"{source} is not a Connect source for this office")
        arn = vault.put_source_secret(office_id, source, body.value)
        conn.execute(
            "UPDATE connection SET secret_arn = %s, status = 'pending', updated_at = now() WHERE office_id = %s AND source = %s",
            (arn, office_id, source),
        )
        audit.record(conn, user, "connection.credential_set", office_id, source=source)
    return {"status": "stored"}


@router.post("/connect/complete")
def complete_connect(office_id: UUID, user: CurrentUser) -> dict[str, str]:
    with tx() as conn:
        can_write(conn, user, office_id)
        complete_step(conn, office_id, 4)
        audit.record(conn, user, "onboarding.connect_done", office_id)
    return {"status": "ok"}


# ---------- step 6 ----------
@router.get("/validate")
def validate(office_id: UUID, user: CurrentUser) -> dict[str, Any]:
    """Readiness check. Warnings do not block go-live; missing data shows as Not observed, never met."""
    with tx() as conn:
        can_read(conn, user, office_id)
        sites = conn.execute("SELECT count(*) AS n FROM office_site WHERE office_id = %s", (office_id,)).fetchone()
        conns = conn.execute(
            "SELECT c.source, c.mode, c.secret_arn IS NOT NULL AS has_credential, k.id IS NOT NULL AS consented "
            "FROM connection c LEFT JOIN consent k ON k.office_id = c.office_id AND k.source = c.source "
            "AND k.status = 'granted' WHERE c.office_id = %s",
            (office_id,),
        ).fetchall()
    checks: list[dict[str, str]] = [
        {
            "check": "Sites confirmed",
            "result": "pass" if sites and sites["n"] else "warn",
            "action": "" if sites and sites["n"] else "Confirm sites in step 1",
        }
    ]
    ms_consented = any(c["source"] == "microsoft365" and c["consented"] for c in conns)
    for c in conns:
        if c["mode"] == "connect":
            ok = c["consented"] or c["has_credential"] or (c["source"] in COVERED_BY_MICROSOFT and ms_consented)
            checks.append(
                {
                    "check": f"{c['source']} connected",
                    "result": "pass" if ok else "warn",
                    "action": "" if ok else "Grant consent or add the read-only key in step 4",
                }
            )
        else:
            checks.append(
                {
                    "check": f"{c['source']} ({c['mode']})",
                    "result": "warn",
                    "action": "Arrives in a later phase; shows as Not observed",
                }
            )
    blocking = [c for c in checks if c["result"] == "fail"]
    return {"ready": not blocking, "checks": checks}


@router.post("/go-live")
def go_live(office_id: UUID, user: CurrentUser) -> dict[str, str]:
    with tx() as conn:
        can_write(conn, user, office_id)
        complete_step(conn, office_id, 6)
        conn.execute("UPDATE onboarding SET live_at = %s WHERE office_id = %s", (datetime.now(UTC), office_id))
        audit.record(conn, user, "onboarding.go_live", office_id)
    return {"status": "live"}
