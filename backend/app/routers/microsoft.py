"""Microsoft 365 admin consent (step 4) and the posture view.

The tenant's own administrator grants consent at Microsoft; we receive only the tenant id and
the outcome. No partner relationship, GDAP or delegated admin is involved (R7), and the
county can revoke it in its own tenant at any time.
"""

import secrets
from typing import Annotated, Any
from urllib.parse import urlencode
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from psycopg.types.json import Jsonb

from app import audit
from app.access import can_read, can_write
from app.auth import CurrentUser
from app.config import Settings, get_settings
from app.db import tx
from app.imports import edr_coverage
from app.microsoft.graph import PERMISSIONS
from app.routers.imports import office_devices

CONSENT_COOKIE = "ccr_consent"
router = APIRouter(tags=["microsoft"])


def _redirect_uri(s: Settings) -> str:
    return f"{s.public_url}/consent/microsoft/callback"


@router.get("/api/offices/{office_id}/consents/microsoft365/start")
def start(office_id: UUID, user: CurrentUser, s: Annotated[Settings, Depends(get_settings)]) -> RedirectResponse:
    if not s.ms_client_id:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "The Microsoft app is not configured yet")
    with tx() as conn:
        can_write(conn, user, office_id)
        audit.record(conn, user, "consent.microsoft365_start", office_id)
    state = secrets.token_urlsafe(24)
    url = "https://login.microsoftonline.com/organizations/v2.0/adminconsent?" + urlencode(
        {
            "client_id": s.ms_client_id,
            "scope": "https://graph.microsoft.com/.default",
            "redirect_uri": _redirect_uri(s),
            "state": state,
        }
    )
    resp = RedirectResponse(url)
    resp.set_cookie(
        CONSENT_COOKIE,
        f"{state}.{office_id}",
        max_age=900,
        httponly=True,
        secure=s.secure_cookies,
        samesite="lax",
        path="/consent",
    )
    return resp


@router.get("/consent/microsoft/callback")
def callback(
    request: Request,
    user: CurrentUser,
    s: Annotated[Settings, Depends(get_settings)],
    state: str = "",
    tenant: str = "",
    admin_consent: str = "",
    error: str = "",
    error_description: str = "",
) -> RedirectResponse:
    expected, _, office = request.cookies.get(CONSENT_COOKIE, "").partition(".")
    if not office or not secrets.compare_digest(expected, state):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "consent state mismatch; start again from step 4")
    office_id = UUID(office)
    back = f"/offices/{office_id}/onboarding/4"
    with tx() as conn:
        can_write(conn, user, office_id)
        if error or admin_consent.lower() != "true":
            audit.record(conn, user, "consent.microsoft365_refused", office_id, error=error, description=error_description[:300])
            resp = RedirectResponse(f"{back}?consent=refused")
        else:
            UUID(tenant)  # Microsoft returns the consenting tenant's id
            conn.execute(
                "UPDATE consent SET status = 'revoked', revoked_by = %s, revoked_at = now() "
                "WHERE office_id = %s AND source = 'microsoft365' AND status = 'granted'",
                (user.email, office_id),
            )
            conn.execute(
                "INSERT INTO consent (office_id, source, status, scopes, tenant_ref, granted_by) "
                "VALUES (%s, 'microsoft365', 'granted', %s, %s, %s)",
                (office_id, Jsonb(PERMISSIONS), tenant.lower(), user.email),
            )
            conn.execute(
                "UPDATE connection SET status = 'ready', updated_at = now() WHERE office_id = %s AND source = 'microsoft365'",
                (office_id,),
            )
            audit.record(conn, user, "consent.microsoft365_granted", office_id, tenant=tenant.lower())
            resp = RedirectResponse(f"{back}?consent=granted")
    resp.delete_cookie(CONSENT_COOKIE, path="/consent")
    return resp


@router.get("/api/offices/{office_id}/posture")
def posture(office_id: UUID, user: CurrentUser) -> dict[str, Any]:
    """The latest evaluated run: eight controls, each with its method and date. No composite score."""
    with tx() as conn:
        can_read(conn, user, office_id)
        latest = conn.execute(
            "SELECT id, started_at, finished_at, ms_tenant_id, summary FROM collection_run "
            "WHERE office_id = %s AND status = 'evaluated' ORDER BY started_at DESC LIMIT 1",
            (office_id,),
        ).fetchone()
        last_attempt = conn.execute(
            "SELECT started_at, status, error FROM collection_run WHERE office_id = %s ORDER BY started_at DESC LIMIT 1",
            (office_id,),
        ).fetchone()
        if latest is None:
            return {"run": None, "last_attempt": last_attempt, "controls": [], "facts": None}
        controls = conn.execute(
            "SELECT control, name, state, method, detail, as_of FROM control_result WHERE run_id = %s ORDER BY control",
            (latest["id"],),
        ).fetchall()
        f = conn.execute("SELECT facts FROM run_facts WHERE run_id = %s", (latest["id"],)).fetchone()
        devs = office_devices(conn, office_id)
    controls = [_edr_from_devices(c, devs) if c["control"] == 5 else c for c in controls]
    return {"run": latest, "last_attempt": last_attempt, "controls": controls, "facts": f["facts"] if f else None}


def _edr_from_devices(c: dict[str, Any], devs: list[dict[str, Any]]) -> dict[str, Any]:
    """Control 5 from the reconciled device register: coverage is a count, never a yes."""
    if not devs:
        return c
    cov = edr_coverage(devs)
    state = "met" if cov["uncovered"] == 0 else "gap"
    return {
        **c,
        "state": state,
        "method": "Imported · device register",
        "detail": {**cov, "note": f"{cov['covered']} of {cov['devices']} covered"},
    }
