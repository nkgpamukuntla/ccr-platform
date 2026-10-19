"""End to end against a real PostgreSQL 16: migrations, then the six onboarding steps.

The app connects as ec_portal (the runtime role), so the grants in 0001 are exercised too.
Uses pgserver (an embedded PostgreSQL) so it runs without Docker; skipped if unavailable.
"""

import os
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest import mock

import pytest

pgserver = pytest.importorskip("pgserver")

ADMIN = {"x-dev-user": "admin@dbiz-demo.org", "x-dev-groups": "platform_admin"}
CLERK = {"x-dev-user": "clerk@county-demo.org", "x-dev-groups": ""}
OTHER = {"x-dev-user": "someone@else-demo.org", "x-dev-groups": ""}
AOC = {"x-dev-user": "viewer@aoc-demo.org", "x-dev-groups": "aoc_viewer"}


@pytest.fixture(scope="module")
def client() -> Iterator[Any]:
    srv = pgserver.get_server(tempfile.mkdtemp(prefix="ccr-test-"), cleanup_mode="stop")
    srv.psql("CREATE DATABASE evidence;")
    port = srv.get_uri().rsplit(":", 1)[1].split("/")[0]
    env = {
        "PGHOST": "127.0.0.1",
        "PGPORT": port,
        "PGDATABASE": "evidence",
        "PGSSLMODE": "disable",
        "AUTH_MODE": "dev",
        "ENVIRONMENT": "local",
        "STATIC_DIR": "does-not-exist",
    }
    with mock.patch.dict(os.environ, {**env, "PGUSER": "postgres"}):
        from app.config import get_settings

        get_settings.cache_clear()
        from app.migrate import migrate

        assert migrate(Path(__file__).parent.parent / "migrations") == ["0001_foundation.sql", "0002_seed_sites.sql"]
        assert migrate(Path(__file__).parent.parent / "migrations") == []  # idempotent
    with mock.patch.dict(os.environ, {**env, "PGUSER": "ec_portal"}):
        get_settings.cache_clear()
        from fastapi.testclient import TestClient

        from app.main import app

        with TestClient(app) as c:
            yield c
    get_settings.cache_clear()


def test_onboarding_end_to_end(client: Any) -> None:
    r = client.post(
        "/api/offices",
        headers=ADMIN,
        json={"name": "Clerk of Superior Court", "office_type": "Superior Court Clerk", "county": "Bulloch"},
    )
    assert r.status_code == 201, r.text
    oid = r.json()["id"]

    # Nobody else sees it until added.
    assert client.get(f"/api/offices/{oid}", headers=CLERK).status_code == 404
    assert (
        client.post(
            f"/api/offices/{oid}/members", headers=ADMIN, json={"email": "Clerk@County-Demo.org", "role": "office_admin"}
        ).status_code
        == 201
    )
    assert [o["id"] for o in client.get("/api/offices", headers=CLERK).json()] == [oid]
    assert client.get("/api/offices", headers=OTHER).json() == []

    # 1 organisation
    sites = client.get("/api/sites?county=Bulloch", headers=CLERK).json()
    assert len(sites) == 2
    r = client.put(
        f"/api/offices/{oid}/organisation",
        headers=CLERK,
        json={
            "name": "Bulloch County — Clerk of Superior Court",
            "office_type": "Superior Court Clerk",
            "signatory_name": "J. Smith",
            "technical_contact": "it-lead@county.example.gov",
            "site_ids": [s["id"] for s in sites],
        },
    )
    assert r.status_code == 200, r.text

    # 2 environment (slide 16 example -> profile C)
    answers = {"m365": "commercial", "device_mgmt": "rmm", "edr": "crowdstrike", "it_admin": "msp", "api_allowed": "yes"}
    assert client.post("/api/profile/preview", headers=CLERK, json=answers).json()["profile"] == "C"
    r = client.put(f"/api/offices/{oid}/environment", headers=CLERK, json=answers)
    assert r.json()["profile"] == "C"

    # 3 prerequisites
    items = client.get(f"/api/offices/{oid}/prerequisites", headers=CLERK).json()
    assert {"Microsoft 365", "RMM import", "CrowdStrike", "Collector"} <= {i["group"] for i in items}
    assert client.post(f"/api/offices/{oid}/prerequisites/ack", headers=CLERK).status_code == 200

    # 4 connect: consent recorded; credential write goes to the vault (mocked here)
    assert (
        client.post(
            f"/api/offices/{oid}/consents/microsoft365", headers=CLERK, json={"tenant_ref": "county.onmicrosoft.com"}
        ).status_code
        == 201
    )
    with mock.patch("app.vault.put_source_secret", return_value="arn:aws:secretsmanager:us-east-1:1:secret:x") as put:
        r = client.put(
            f"/api/offices/{oid}/connections/crowdstrike/credential", headers=CLERK, json={"value": "read-only-key-123"}
        )
    assert r.status_code == 200 and put.call_count == 1
    conns = {c["source"]: c for c in client.get(f"/api/offices/{oid}/connections", headers=CLERK).json()}
    assert conns["crowdstrike"]["has_credential"] and "value" not in conns["crowdstrike"]
    assert conns["microsoft365"]["consent_status"] == "granted"
    # An Import source cannot take a credential.
    assert (
        client.put(f"/api/offices/{oid}/connections/rmm/credential", headers=CLERK, json={"value": "xxxxxxxxxx"}).status_code
        == 409
    )
    assert client.post(f"/api/offices/{oid}/connect/complete", headers=CLERK).status_code == 200

    # 6 validate and go live
    v = client.get(f"/api/offices/{oid}/validate", headers=CLERK).json()
    assert v["ready"] is True
    assert client.post(f"/api/offices/{oid}/go-live", headers=CLERK).status_code == 200
    office = client.get(f"/api/offices/{oid}", headers=CLERK).json()
    assert office["onboarding"]["live_at"] and office["onboarding"]["completed_steps"] == [1, 2, 3, 4, 6]

    # Revocation is recorded, never deleted.
    assert client.post(f"/api/offices/{oid}/consents/microsoft365/revoke", headers=CLERK).status_code == 200

    # Audit trail has every step, newest first.
    actions = [a["action"] for a in client.get(f"/api/offices/{oid}/audit", headers=CLERK).json()]
    assert actions[0] == "consent.revoke" and "office.create" in actions and "onboarding.go_live" in actions


def test_aoc_is_aggregate_and_read_only(client: Any) -> None:
    s = client.get("/api/aoc/summary", headers=AOC).json()
    assert s["totals"]["offices"] >= 1
    assert client.get("/api/aoc/summary", headers=CLERK).status_code == 403
    oid = client.get("/api/offices", headers=AOC).json()[0]["id"]
    r = client.put(
        f"/api/offices/{oid}/environment",
        headers=AOC,
        json={"m365": "none", "device_mgmt": "none", "edr": "none", "it_admin": "none", "api_allowed": "yes"},
    )
    assert r.status_code == 403


def test_only_admins_create_offices(client: Any) -> None:
    assert (
        client.post(
            "/api/offices", headers=CLERK, json={"name": "X office", "office_type": "Sheriff", "county": "Lab A"}
        ).status_code
        == 403
    )


def test_audit_log_is_append_only(client: Any) -> None:
    import psycopg

    from app.config import get_settings
    from app.db import conninfo

    with psycopg.connect(**conninfo(get_settings())) as conn, pytest.raises(psycopg.errors.InsufficientPrivilege):  # as ec_portal
        conn.execute("DELETE FROM audit_log")


def test_dev_auth_refused_outside_local() -> None:
    from pydantic import ValidationError

    from app.config import Settings

    with pytest.raises(ValidationError):
        Settings(auth_mode="dev", environment="dev")
