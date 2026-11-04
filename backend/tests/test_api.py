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

        assert migrate(Path(__file__).parent.parent / "migrations") == sorted(
            p.name for p in (Path(__file__).parent.parent / "migrations").glob("*.sql")
        )
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


def _as_role(role: str) -> None:
    """Reopen the pool as another runtime role, so its grants are what the code runs under."""
    from app import db
    from app.config import get_settings

    db.close_pool()
    os.environ["PGUSER"] = role
    get_settings.cache_clear()
    db.open_pool()


def test_collection_to_posture_end_to_end(client: Any) -> None:
    """Worker (ec_worker) seals a bundle, evaluator (ec_evaluator) scores it, portal (ec_portal) shows it."""
    from tests.test_microsoft import bundle as make_bundle
    from tests.test_microsoft import policy

    r = client.post(
        "/api/offices", headers=ADMIN, json={"name": "Lab County A office", "office_type": "County IT", "county": "Lab A"}
    )
    oid = r.json()["id"]
    tenant = "0f0e0d0c-0b0a-0908-0706-050403020100"
    assert client.post(f"/api/offices/{oid}/consents/microsoft365", headers=ADMIN, json={"tenant_ref": tenant}).status_code == 201

    regs = [{"userPrincipalName": "admin@lab", "isAdmin": True, "isMfaRegistered": True, "methodsRegistered": ["mobilePhone"]}]
    reads = make_bundle(ca=[policy("Require MFA", state="enabledForReportingButNotEnforced")], regs=regs)["reads"]
    stored: dict[str, bytes] = {}

    class FakeS3:
        def put_object(self, **kw: Any) -> dict[str, str]:
            assert kw["SSEKMSKeyId"] == "arn:aws:kms:us-east-1:1:key/lab-a" and kw["Key"].startswith(f"{oid}/")
            stored[kw["Key"]] = kw["Body"]
            return {"VersionId": "v1"}

        def get_object(self, **kw: Any) -> dict[str, Any]:
            import io

            return {"Body": io.BytesIO(stored[kw["Key"]])}

    from app import worker
    from app.config import get_settings

    try:
        _as_role("ec_worker")
        s = get_settings().model_copy(
            update={"ms_client_id": "app", "ec_raw_bucket": "raw", "ec_raw_keys": {oid: "arn:aws:kms:us-east-1:1:key/lab-a"}}
        )
        offices = {str(o["office_id"]): o["tenant_ref"] for o in worker.consented_offices()}
        assert offices[oid] == tenant
        with (
            mock.patch("app.worker.get_token", return_value="token"),
            mock.patch(
                "app.worker.graph.fetch",
                side_effect=lambda _h, _t, rd: next(x for x in reads if x["name"] == rd.name) | {"name": rd.name}
                if any(x["name"] == rd.name for x in reads)
                else {"name": rd.name, "status": 404, "pages": []},
            ),
            mock.patch("app.worker.boto3.client", return_value=FakeS3()),
            mock.patch("app.worker.scuba_aad.LiveGraph", return_value=mock.Mock(responses={})),
            mock.patch("app.worker.scuba_aad.build_provider"),
        ):
            assert worker.collect_one(s, mock.Mock(), mock.Mock(), oid, tenant, "fp") == "collected"

        _as_role("ec_evaluator")
        from app.evaluator import evaluate_pending

        assert evaluate_pending(FakeS3(), "raw") == {"evaluated": 1, "failed": 0}
    finally:
        _as_role("ec_portal")

    p = client.get(f"/api/offices/{oid}/posture", headers=ADMIN).json()
    by = {c["control"]: c for c in p["controls"]}
    assert by[1]["state"] == "weak" and by[3]["state"] == "weak" and by[5]["state"] == "not_observed"
    assert p["facts"]["licences"][0]["sku"] == "SPE_E5"
    assert p["run"]["ms_tenant_id"] == tenant


def test_page_navigation_without_session_goes_to_sign_in_and_back() -> None:
    from fastapi.testclient import TestClient

    from app.auth import safe_next
    from app.config import get_settings
    from app.main import app

    with mock.patch.dict(os.environ, {"AUTH_MODE": "cognito", "ENVIRONMENT": "dev", "STATIC_DIR": "none"}):
        get_settings.cache_clear()
        try:
            c = TestClient(app)  # no lifespan: no database needed for a 401
            page = c.get("/api/offices/x/consents/microsoft365/start", headers={"accept": "text/html"}, follow_redirects=False)
            assert page.status_code == 307
            assert page.headers["location"] == "/auth/login?next=%2Fapi%2Foffices%2Fx%2Fconsents%2Fmicrosoft365%2Fstart"
            api = c.get("/api/me", headers={"accept": "application/json"})
            assert api.status_code == 401
        finally:
            get_settings.cache_clear()
    assert (
        safe_next("//evil.example") == "/"
        and safe_next("https://evil.example") == "/"
        and safe_next("/offices/1") == "/offices/1"
    )


def test_members_invite_and_remove(client: Any) -> None:
    oid = client.post(
        "/api/offices", headers=ADMIN, json={"name": "Members test office", "office_type": "Sheriff", "county": "Lab E"}
    ).json()["id"]
    other = client.post(
        "/api/offices", headers=ADMIN, json={"name": "Other office", "office_type": "Sheriff", "county": "Lab E"}
    ).json()["id"]
    lead = {"x-dev-user": "lead@county-demo.org", "x-dev-groups": ""}
    with (
        mock.patch("app.directory.ensure_user", return_value="invited") as ensure,
        mock.patch("app.directory.add_to_group") as group,
    ):
        # Platform admin makes the office's administrator.
        assert (
            client.post(
                "/api/members", headers=ADMIN, json={"email": "Lead@County-Demo.org", "role": "office_admin", "office_id": oid}
            ).status_code
            == 201
        )
        ensure.assert_called_with("lead@county-demo.org")
        # The office admin invites a colleague to their own office ...
        assert (
            client.post(
                "/api/members", headers=lead, json={"email": "eng@county-demo.org", "role": "office_member", "office_id": oid}
            ).status_code
            == 201
        )
        # ... but not to another office, and cannot create AOC viewers.
        assert (
            client.post(
                "/api/members", headers=lead, json={"email": "x@county-demo.org", "role": "office_member", "office_id": other}
            ).status_code
            == 403
        )
        assert (
            client.post("/api/members", headers=lead, json={"email": "x@aoc-demo.org", "role": "aoc_viewer"}).status_code == 403
        )
        assert (
            client.post("/api/members", headers=ADMIN, json={"email": "v@aoc-demo.org", "role": "aoc_viewer"}).status_code == 201
        )
        group.assert_called_once_with("v@aoc-demo.org", "aoc_viewer")
    members = {m["email"]: m["role"] for m in client.get(f"/api/offices/{oid}/members", headers=lead).json()}
    assert members == {"lead@county-demo.org": "office_admin", "eng@county-demo.org": "office_member"}
    assert client.delete(f"/api/offices/{oid}/members/eng@county-demo.org", headers=lead).status_code == 200
    assert client.delete(f"/api/offices/{oid}/members/lead@county-demo.org", headers=lead).status_code == 409  # not yourself
    eng = {"x-dev-user": "eng@county-demo.org", "x-dev-groups": ""}
    assert client.get(f"/api/offices/{oid}", headers=eng).status_code == 404  # access gone with the membership
    actions = [a["action"] for a in client.get(f"/api/offices/{oid}/audit", headers=ADMIN).json()]
    assert actions[:3] == ["member.remove", "member.add", "member.add"]

    with mock.patch(
        "app.directory.list_users",
        return_value=[{"email": "lead@county-demo.org", "status": "CONFIRMED", "enabled": True, "groups": []}],
    ):
        people = {p["email"]: p for p in client.get("/api/admin/users", headers=ADMIN).json()}
    assert people["lead@county-demo.org"]["offices"][0]["role"] == "office_admin"
    assert client.get("/api/admin/users", headers=lead).status_code == 403


def test_scuba_import_and_findings(client: Any) -> None:
    import json as _json

    sample = (Path(__file__).parent / "fixtures" / "scuba" / "sample-ScubaResults.json").read_bytes()
    oid = client.post(
        "/api/offices", headers=ADMIN, json={"name": "SCuBA import office", "office_type": "County IT", "county": "Lab A"}
    ).json()["id"]
    r = client.post(f"/api/offices/{oid}/scuba-import", headers=ADMIN, content=sample)
    assert r.status_code == 201, r.text
    assert set(r.json()["products"]) == {"AAD", "Defender", "EXO", "PowerPlatform", "SharePoint", "Teams"}
    f = client.get(f"/api/offices/{oid}/findings", headers=ADMIN).json()
    assert f["summary"]["EXO"] and all(x["source"] == "imported" for x in f["results"])
    exo = [x for x in f["results"] if x["policy_id"].startswith("MS.EXO.")]
    assert exo and exo[0]["baseline"] == "v1.8.0" and "<" not in exo[0]["requirement"]  # HTML stripped

    # A report for another tenant than the one that consented is refused.
    other = client.post(
        "/api/offices", headers=ADMIN, json={"name": "Consented office", "office_type": "County IT", "county": "Lab A"}
    ).json()["id"]
    client.post(
        f"/api/offices/{other}/consents/microsoft365", headers=ADMIN, json={"tenant_ref": "11111111-2222-3333-4444-555555555555"}
    )
    assert client.post(f"/api/offices/{other}/scuba-import", headers=ADMIN, content=sample).status_code == 409
    assert client.post(f"/api/offices/{other}/scuba-import", headers=ADMIN, content=_json.dumps({"hello": 1})).status_code == 422


def test_evaluator_scores_collected_scuba(client: Any) -> None:
    """A bundle with recorded Entra responses gets ScubaGear's results stored and controls 1-3 rolled up."""
    import io
    import json as _json

    from tests.test_scuba import OPA, mfa_policy, tenant

    if not Path(OPA).exists():
        pytest.skip("OPA not installed")
    os.environ["OPA_PATH"] = OPA
    oid = client.post(
        "/api/offices", headers=ADMIN, json={"name": "SCuBA collected office", "office_type": "County IT", "county": "Lab A"}
    ).json()["id"]
    bundle = {
        "run_id": None,
        "office_id": oid,
        "ms_tenant_id": "1ac3b327-2499-4778-8b7d-8d7eab7040b8",
        "reads": [],
        "scuba_aad": {"baseline": "v1.8.0", "responses": tenant([mfa_policy()])},
    }
    try:
        _as_role("ec_worker")
        from app import db

        with db.tx() as conn:
            run = conn.execute(
                "INSERT INTO collection_run (office_id, source, ms_tenant_id, status, s3_key, finished_at) "
                "VALUES (%s, 'microsoft365', %s, 'collected', 'k', now()) RETURNING id",
                (oid, bundle["ms_tenant_id"]),
            ).fetchone()
        bundle["run_id"] = str(run["id"])
        body = _json.dumps(bundle).encode()

        class S3:
            def get_object(self, **_: Any) -> dict[str, Any]:
                return {"Body": io.BytesIO(body)}

        _as_role("ec_evaluator")
        from app.evaluator import evaluate_pending

        assert evaluate_pending(S3(), "raw") == {"evaluated": 1, "failed": 0}
    finally:
        _as_role("ec_portal")
    f = client.get(f"/api/offices/{oid}/findings", headers=ADMIN).json()
    by = {x["policy_id"]: x for x in f["results"]}
    assert len(by) == 30 and by["MS.AAD.3.2v1"]["status"] == "pass" and by["MS.AAD.3.2v1"]["source"] == "collected"
    assert "Legacy authentication" in by["MS.AAD.1.1v1"]["requirement"]
    posture = {c["control"]: c for c in client.get(f"/api/offices/{oid}/posture", headers=ADMIN).json()["controls"]}
    assert posture[1]["method"].startswith("Connected · SCuBA v1.8.0")
    assert posture[1]["detail"]["required"]["MS.AAD.3.2v1"] == "pass"


def test_import_flow_and_device_register(client: Any) -> None:
    from tests.test_imports import FALCON, RMM

    oid = client.post(
        "/api/offices", headers=ADMIN, json={"name": "Import office", "office_type": "County IT", "county": "Lab A"}
    ).json()["id"]
    p = client.post(f"/api/offices/{oid}/imports/preview?template=edr_hosts", headers=ADMIN, content=FALCON).json()
    assert p["accepted"] and p["rows_ok"] == 3 and len(p["sample"]) == 3
    assert client.get(f"/api/offices/{oid}/imports", headers=ADMIN).json() == []  # preview stores nothing

    r = client.post(
        f"/api/offices/{oid}/imports?template=edr_hosts&filename=falcon.csv&export_date=2026-10-21", headers=ADMIN, content=FALCON
    )
    assert r.status_code == 201 and r.json()["rows_loaded"] == 3
    assert (
        client.post(
            f"/api/offices/{oid}/imports?template=edr_hosts&filename=again.csv", headers=ADMIN, content=FALCON
        ).status_code
        == 409
    )
    assert (
        client.post(f"/api/offices/{oid}/imports?template=rmm_inventory&filename=rmm.csv", headers=ADMIN, content=RMM).status_code
        == 201
    )
    bad = client.post(f"/api/offices/{oid}/imports?template=edr_hosts&filename=bad.csv", headers=ADMIN, content="Hostname\nX\n")
    assert bad.status_code == 422

    hist = client.get(f"/api/offices/{oid}/imports", headers=ADMIN).json()
    assert [h["filename"] for h in hist] == ["rmm.csv", "falcon.csv"] and len(hist[1]["sha256"]) == 64
    d = client.get(f"/api/offices/{oid}/devices", headers=ADMIN).json()
    assert d["coverage"] == {"devices": 4, "covered": 2, "uncovered": 2}  # CLERK-FRONT-01 matched across both files
    assert d["matched"] == 1 and d["unmatched"] == 3
    actions = [a["action"] for a in client.get(f"/api/offices/{oid}/audit", headers=ADMIN).json()]
    assert actions.count("import.load") == 2


def test_collector_download_upload_and_revoke(client: Any) -> None:
    import io
    import json
    import zipfile

    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    from app.collector import bundle
    from app.config import get_settings
    from app.routers import collector
    from tests.test_collector import ARN, KEY, facts, unwrap, wrap

    oid = client.post(
        "/api/offices", headers=ADMIN, json={"name": "Collector office", "office_type": "County IT", "county": "Lab E"}
    ).json()["id"]
    assert client.get(f"/api/offices/{oid}/collector/download", headers=ADMIN).status_code == 409  # no key yet

    s = get_settings()
    der = KEY.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    with (
        mock.patch.dict(s.ec_collector_keys, {oid: ARN}),
        mock.patch.object(s, "collector_dir", str(Path(__file__).resolve().parents[2] / "collector")),
        mock.patch.object(collector, "kms_public_key", lambda arn: der),
        mock.patch.object(collector, "kms_unwrap", lambda arn, ek: unwrap(ek)),
    ):
        r = client.get(f"/api/offices/{oid}/collector/download", headers=ADMIN)
        assert r.status_code == 200
        z = zipfile.ZipFile(io.BytesIO(r.content))
        assert {"Collect-CCREvidence.ps1", "office.json", "README.txt"} <= set(z.namelist())
        cfg = json.loads(z.read("office.json"))
        assert cfg["office_id"] == oid and cfg["key_arn"] == ARN and cfg["token"]

        def make(token: str, host: str = "kiosk-9", office: str = oid) -> bytes:
            f = facts()
            f["collector"]["token"] = token
            f["device"]["hostname"] = host
            f["device"]["serial"] = host + "-sn"
            return bundle.seal(f, office, ARN, wrap, os.urandom(64), os.urandom(16))

        good = make(cfg["token"])
        up = client.post(f"/api/offices/{oid}/collector/bundles?filename=KIOSK-9.ccre", headers=ADMIN, content=good)
        assert up.status_code == 201 and up.json()["edr_status"] == "active" and up.json()["hostname"] == "KIOSK-9"
        again = client.post(f"/api/offices/{oid}/collector/bundles?filename=x.ccre", headers=ADMIN, content=good)
        assert again.status_code == 409
        forged = client.post(f"/api/offices/{oid}/collector/bundles?filename=x.ccre", headers=ADMIN, content=make("never-issued"))
        assert forged.status_code == 422 and "never downloaded" in forged.json()["detail"]
        elsewhere = client.post(
            f"/api/offices/{oid}/collector/bundles?filename=x.ccre", headers=ADMIN, content=make(cfg["token"], office="other")
        )
        assert elsewhere.status_code == 422 and "different office" in elsewhere.json()["detail"]
        stranger = client.post(f"/api/offices/{oid}/collector/bundles?filename=x.ccre", headers=OTHER, content=good)
        assert stranger.status_code in (403, 404)

        assert client.post(f"/api/offices/{oid}/collector/downloads/{cfg['token']}/revoke", headers=ADMIN).status_code == 200
        late = client.post(
            f"/api/offices/{oid}/collector/bundles?filename=y.ccre", headers=ADMIN, content=make(cfg["token"], "pc-2")
        )
        assert late.status_code == 422 and "revoked" in late.json()["detail"]

        st = client.get(f"/api/offices/{oid}/collector/status", headers=ADMIN).json()
        assert st["enabled"] and st["downloads"][0]["bundles"] == 1 and st["downloads"][0]["revoked_at"]
        assert [b["hostname"] for b in st["bundles"]] == ["KIOSK-9"]
        dev = client.get(f"/api/offices/{oid}/devices", headers=ADMIN).json()
        assert dev["coverage"] == {"devices": 1, "covered": 1, "uncovered": 0}
        assert dev["devices"][0]["sources"] == ["collector"] and dev["devices"][0]["collected"]["device"]["hostname"] == "kiosk-9"
    actions = [a["action"] for a in client.get(f"/api/offices/{oid}/audit", headers=ADMIN).json()]
    assert {"collector.download", "collector.bundle", "collector.revoke"} <= set(actions)


def test_workspaces_types_schedule_and_viewers(client: Any) -> None:
    # Accountability courts are a court office type.
    assert "Accountability Court" in client.get("/api/office-types", headers=ADMIN).json()
    court = client.post(
        "/api/offices",
        headers=ADMIN,
        json={"name": "Lab A Accountability Court", "office_type": "Accountability Court", "county": "Lab A"},
    )
    assert court.status_code == 201 and court.json()["time_zone"] == "America/New_York"

    # A separate workspace for an organisation, outside the courts.
    ws = client.post(
        "/api/workspaces", headers=ADMIN, json={"name": "D-Biz Solutions", "kind": "organization", "industry": "IT services"}
    )
    assert ws.status_code == 201
    wid = ws.json()["id"]
    assert client.post("/api/workspaces", headers=AOC, json={"name": "X", "kind": "organization"}).status_code == 403
    assert (
        client.post("/api/workspaces", headers=ADMIN, json={"name": "d-biz solutions", "kind": "organization"}).status_code == 409
    )
    assert "Head office" in client.get("/api/office-types?kind=organization", headers=ADMIN).json()
    bad = client.post(
        "/api/offices",
        headers=ADMIN,
        json={"name": "D-Biz HQ", "office_type": "Sheriff", "county": "Singapore", "workspace_id": wid},
    )
    assert bad.status_code == 422  # court types do not belong in an organisation
    hq = client.post(
        "/api/offices",
        headers=ADMIN,
        json={
            "name": "D-Biz HQ",
            "office_type": "Head office",
            "county": "Singapore",
            "workspace_id": wid,
            "time_zone": "Asia/Singapore",
            "collect_at": "19:00",
        },
    )
    assert hq.status_code == 201
    hid = hq.json()["id"]
    assert (
        client.post(
            "/api/offices",
            headers=ADMIN,
            json={"name": "Bad tz", "office_type": "Head office", "county": "X", "workspace_id": wid, "time_zone": "Mars/Base"},
        ).status_code
        == 422
    )

    # The AOC sees the courts, not D-Biz; a D-Biz viewer sees D-Biz only, read-only.
    aoc_names = {o["name"] for o in client.get("/api/offices", headers=AOC).json()}
    assert "Lab A Accountability Court" in aoc_names and "D-Biz HQ" not in aoc_names
    assert client.get(f"/api/offices/{hid}", headers=AOC).status_code == 404
    ciso = {"x-dev-user": "ciso@dbiz-demo.org", "x-dev-groups": ""}
    with mock.patch("app.directory.ensure_user", return_value="invited"):
        assert (
            client.post(f"/api/workspaces/{wid}/viewers", headers=ADMIN, json={"email": "CISO@dbiz-demo.org"}).status_code == 201
        )
    rows = client.get("/api/offices", headers=ciso).json()
    assert [o["name"] for o in rows] == ["D-Biz HQ"] and rows[0]["workspace"] == "D-Biz Solutions" and rows[0]["next_scan"]
    assert (
        client.put(f"/api/offices/{hid}/schedule", headers=ciso, json={"time_zone": "UTC", "collect_at": "17:00"}).status_code
        == 403
    )
    assert client.get(f"/api/workspaces/{wid}/summary", headers=ciso).json()["totals"]["offices"] == 1
    assert client.get(f"/api/workspaces/{wid}/summary", headers=AOC).status_code == 403
    assert [w["name"] for w in client.get("/api/workspaces", headers=ciso).json()] == ["D-Biz Solutions"]

    # The office's own schedule can be changed by its administrators.
    r = client.put(f"/api/offices/{hid}/schedule", headers=ADMIN, json={"time_zone": "Asia/Kolkata", "collect_at": "18:30"})
    assert r.status_code == 200
    o = client.get(f"/api/offices/{hid}", headers=ADMIN).json()
    assert o["time_zone"] == "Asia/Kolkata" and o["collect_at"].startswith("18:30") and o["workspace_kind"] == "organization"
    assert (
        client.put(
            f"/api/offices/{hid}/schedule", headers=ADMIN, json={"time_zone": "Nowhere", "collect_at": "18:00"}
        ).status_code
        == 422
    )
    assert client.delete(f"/api/workspaces/{wid}/viewers/ciso@dbiz-demo.org", headers=ADMIN).status_code == 200
    assert client.get("/api/offices", headers=ciso).json() == []


def _collect_and_score(
    oid: str, tenant: str, extra: list[dict[str, Any]] | None = None, dns: dict[str, Any] | None = None
) -> None:
    """One worker collection (ec_worker) and evaluation (ec_evaluator) for an office, as in production."""
    from tests.test_microsoft import bundle as make_bundle
    from tests.test_microsoft import policy

    regs = [{"userPrincipalName": "admin@lab", "isAdmin": True, "isMfaRegistered": True, "methodsRegistered": ["mobilePhone"]}]
    reads = make_bundle(ca=[policy("Require MFA", state="enabledForReportingButNotEnforced")], regs=regs)["reads"] + (extra or [])
    stored: dict[str, bytes] = {}

    class FakeS3:
        def put_object(self, **kw: Any) -> dict[str, str]:
            stored[kw["Key"]] = kw["Body"]
            return {"VersionId": "v1"}

        def get_object(self, **kw: Any) -> dict[str, Any]:
            import io

            return {"Body": io.BytesIO(stored[kw["Key"]])}

    from app import worker
    from app.config import get_settings
    from app.evaluator import evaluate_pending

    try:
        _as_role("ec_worker")
        s = get_settings().model_copy(update={"ms_client_id": "app", "ec_raw_bucket": "raw", "ec_raw_keys": {oid: "arn:k"}})
        with (
            mock.patch("app.worker.get_token", return_value="token"),
            mock.patch(
                "app.worker.graph.fetch",
                side_effect=lambda _h, _t, rd: next((x | {"name": rd.name} for x in reads if x["name"] == rd.name), None)
                or {"name": rd.name, "status": 404, "pages": []},
            ),
            mock.patch("app.worker.boto3.client", return_value=FakeS3()),
            mock.patch("app.worker.scuba_aad.LiveGraph", return_value=mock.Mock(responses={})),
            mock.patch("app.worker.scuba_aad.build_provider"),
            mock.patch("app.worker.email_dns.lookup", return_value=dns or {}),
        ):
            assert worker.collect_one(s, mock.Mock(), mock.Mock(), oid, tenant, "fp") == "collected"
        _as_role("ec_evaluator")
        assert evaluate_pending(FakeS3(), "raw")["evaluated"] >= 1
    finally:
        _as_role("ec_portal")


def test_findings_remediation_evidence_exports_and_email(client: Any) -> None:
    """Phase 5: findings register, tracker that closes only on fresh evidence, evidence pack,
    exports with audit, and one quiet email per scan sent by the worker."""
    from tests.test_imports import FALCON, RMM

    ws = client.post(
        "/api/workspaces", headers=ADMIN, json={"name": "Phase5 Co", "kind": "organization", "industry": "IT"}
    ).json()
    oid = client.post(
        "/api/offices",
        headers=ADMIN,
        json={
            "workspace_id": ws["id"],
            "name": "HQ",
            "office_type": "Head office",
            "county": "Singapore",
            "time_zone": "Asia/Kolkata",
        },
    ).json()["id"]
    tenant = "1a1a1a1a-0b0a-0908-0706-050403020100"
    assert client.post(f"/api/offices/{oid}/consents/microsoft365", headers=ADMIN, json={"tenant_ref": tenant}).status_code == 201
    _collect_and_score(oid, tenant)
    for name, tpl, body in (("falcon.csv", "edr_hosts", FALCON), ("rmm.csv", "rmm_inventory", RMM)):
        assert (
            client.post(f"/api/offices/{oid}/imports?template={tpl}&filename={name}", headers=ADMIN, content=body).status_code
            == 201
        )

    ent = client.get(f"/api/offices/{oid}/entra-devices", headers=ADMIN).json()
    assert ent["summary"]["total"] == 2 and ent["edr"]["company_computers_active"] == 0 and "records" not in ent
    assert "entra_devices" not in client.get(f"/api/offices/{oid}/posture", headers=ADMIN).json()["facts"]
    assert client.get(f"/api/offices/{oid}/entra-devices", headers=OTHER).status_code in (403, 404)
    assert client.get(f"/api/offices/{oid}/export/entra-devices.xlsx", headers=ADMIN).status_code == 200

    reg = client.get(f"/api/offices/{oid}/register", headers=ADMIN).json()
    keys = {f["key"]: f for f in reg["findings"]}
    assert {"control:1", "control:3", "device:edr_missing", "device:edr_stale"} <= set(keys)
    assert keys["control:3"]["title"] == "1 admin(s) with phone-only MFA" and keys["control:3"]["severity"] == "High"
    assert keys["device:edr_missing"]["evidence"]["sample"] == ["SCANNER-PC"]
    assert reg["findings"][0]["severity"] == "Mandatory"  # most severe first
    plan = reg["themes"]
    assert plan[0]["priority"] == "Mandatory" and sum(t["steps"] for t in plan) == len(reg["findings"])
    assert {"mfa", "admins", "devices"} <= {t["key"] for t in plan}

    # Track and move; never close by hand; outsiders cannot touch it.
    new = {"finding_key": "device:edr_missing", "owner": "IT team", "target_date": "2026-01-01"}
    assert client.post(f"/api/offices/{oid}/remediation", headers=OTHER, json=new).status_code in (403, 404)
    item = client.post(f"/api/offices/{oid}/remediation", headers=ADMIN, json=new).json()["id"]
    assert client.post(f"/api/offices/{oid}/remediation", headers=ADMIN, json=new).status_code == 409
    assert client.post(f"/api/offices/{oid}/remediation", headers=ADMIN, json={**new, "finding_key": "nope"}).status_code == 404
    url = f"/api/offices/{oid}/remediation/{item}"
    assert client.patch(url, headers=ADMIN, json={"status": "closed"}).status_code == 422
    moved = client.patch(url, headers=ADMIN, json={"status": "awaiting_evidence", "note": "agent pushed"})
    assert moved.json()["status"] == "awaiting_evidence"
    items = client.get(f"/api/offices/{oid}/remediation", headers=ADMIN).json()
    assert items[0]["status"] == "awaiting_evidence" and items[0]["overdue"] and len(items[0]["events"]) == 2

    # Evidence pack: coverage is a count, not a yes.
    pack = client.get(f"/api/offices/{oid}/evidence-pack?destination=irma", headers=ADMIN).json()
    c = {x["control"]: x for x in pack["controls"]}
    assert c[5]["answer"] == "Partial" and c[5]["evidence"] == "2 of 4 devices with an active EDR agent"
    assert c[1]["question"].startswith("Is MFA required") and pack["plan"][0]["steps"] >= 1
    assert c[1]["answer"] == "Partial (weak method)" and c[6]["answer"] == "Pending attestation"
    assert "Phase5 Co remains responsible" in pack["statement"]
    assert client.get(f"/api/offices/{oid}/evidence-pack?destination=nope", headers=ADMIN).status_code == 400

    # Exports: Excel and CSV, each audited with its hash.
    x = client.get(f"/api/offices/{oid}/export/evidence-pack.xlsx?destination=irma", headers=ADMIN)
    assert x.status_code == 200 and x.content[:2] == b"PK" and "attachment" in x.headers["content-disposition"]
    csv_ = client.get(f"/api/offices/{oid}/export/devices.csv", headers=ADMIN)
    assert csv_.content.decode("utf-8-sig").startswith("Hostname,Serial,OS,EDR")
    for what in ("findings", "remediation", "posture", "audit"):
        assert client.get(f"/api/offices/{oid}/export/{what}.xlsx", headers=ADMIN).status_code == 200
    assert client.get(f"/api/offices/{oid}/export/secrets.csv", headers=ADMIN).status_code == 404
    audit_rows = client.get(f"/api/offices/{oid}/audit", headers=ADMIN).json()
    assert sum(1 for a in audit_rows if a["action"] == "export.downloaded") == 7
    assert any(len(a["detail"].get("sha256", "")) == 64 for a in audit_rows)

    # Fresh evidence clears the finding: the item closes itself.
    fixed = FALCON + "SCANNER-PC,aid-9,7.18.19105,Online,2026-10-21T08:00:00Z,SN009,Windows\n"
    r = client.post(f"/api/offices/{oid}/imports?template=edr_hosts&filename=falcon2.csv", headers=ADMIN, content=fixed)
    assert r.status_code == 201
    items = client.get(f"/api/offices/{oid}/remediation", headers=ADMIN).json()
    assert items[0]["status"] == "closed" and items[0]["closed_reason"].startswith("Closed by re-read")
    assert items[0]["events"][-1]["actor"] == "evidence"

    # Notifications: one email per scored scan, queued and sent by the worker.
    assert (
        client.post(f"/api/offices/{oid}/notifications", headers=ADMIN, json={"email": "Ops@Phase5.example"}).status_code == 201
    )
    from app import db, notify
    from app.config import get_settings

    sent: list[dict[str, Any]] = []

    def send_email(**kw: Any) -> dict[str, str]:
        sent.append(kw)
        return {"MessageId": "m1"}

    try:
        _as_role("ec_worker")
        with db.tx() as conn:
            assert notify.report_new_runs(conn) >= 1
        with db.tx() as conn:
            assert notify.report_new_runs(conn) == 0  # once per scan
        with (
            mock.patch.object(get_settings(), "ses_from", "CCR <noreply@example.org>"),
            mock.patch("app.notify.boto3.client", return_value=mock.Mock(send_email=send_email)),
            db.tx() as conn,
        ):
            assert notify.send_pending(conn)["sent"] >= 1
    finally:
        _as_role("ec_portal")
    mine = [m for m in sent if m["Destination"]["ToAddresses"] == ["ops@phase5.example"]]
    assert len(mine) == 1
    text = mine[0]["Content"]["Simple"]["Body"]["Text"]["Data"]
    assert "IST" in text and "first reported scan" in text and f"/offices/{oid}/remediation" in text
    n = client.get(f"/api/offices/{oid}/notifications", headers=ADMIN).json()
    assert n["recipients"][0]["email"] == "ops@phase5.example" and n["recent"][0]["sent_at"]


def test_scan_report_lists_changes_since_previous_scan() -> None:
    from datetime import UTC, datetime

    from app import notify

    prev = [{"key": "a", "title": "Old gap", "severity": "High"}, {"key": "b", "title": "3 devices stale", "severity": "High"}]
    cur = [
        {"key": "b", "title": "1 devices stale", "severity": "High"},
        {"key": "c", "title": "New gap", "severity": "Mandatory"},
    ]
    d = notify.diff(prev, cur)
    assert [f["key"] for f in d["new"]] == ["c"] and [f["key"] for f in d["resolved"]] == ["a"] and len(d["changed"]) == 1
    head = {
        "controls": {"1": {"name": "MFA", "state": "met"}},
        "devices": 10,
        "edr_active": 9,
        "findings": 2,
        "by_severity": {"High": 1},
    }
    office = {"id": "o1", "name": "D-Biz", "workspace": "D-Biz", "time_zone": "Asia/Kolkata"}
    was = {
        "taken_at": datetime(2026, 11, 1, 12, 40, tzinfo=UTC),
        "headline": {"controls": {"1": {"state": "gap"}}, "devices": 10, "edr_active": 8},
    }
    rem = {"open": 1, "overdue": 0, "closed_now": 1}
    subject, body = notify.render_report(office, datetime(2026, 11, 2, 12, 40, tzinfo=UTC), head, was, d, rem)
    assert subject == "[D-Biz Assure] D-Biz: scan 02 Nov - 2 findings, 1 new, 1 resolved"
    assert "02 Nov 2026 18:10 IST" in body and "MFA: Met  (was Gap)" in body
    assert "New (1):" in body and "Resolved (1):" in body and "3 devices stale  ->  1 devices stale" in body
    assert "previous scan 10 devices, 8 active" in body


def test_compliance_by_country_with_intune_and_email(client: Any) -> None:
    """New reads land as findings and framework evidence; items stay open when a source goes unread."""
    from tests.test_compliance import MANAGED, dkim, txt
    from tests.test_microsoft import read

    oid = client.post(
        "/api/offices",
        headers=ADMIN,
        json={"name": "Sydney office", "office_type": "County IT", "county": "Lab AU", "time_zone": "Australia/Sydney"},
    ).json()["id"]
    tenant = "2b2b2b2b-0b0a-0908-0706-050403020100"
    assert client.post(f"/api/offices/{oid}/consents/microsoft365", headers=ADMIN, json={"tenant_ref": tenant}).status_code == 201

    # Before any scan: no countries chosen for a new office, every check not yet observed.
    c = client.get(f"/api/offices/{oid}/compliance", headers=ADMIN).json()
    assert c["jurisdictions"] == [] and c["frameworks"] == [] and {x["code"] for x in c["countries"]} == {"US", "AU", "SG"}
    assert client.put(f"/api/offices/{oid}/jurisdictions", headers=ADMIN, json={"jurisdictions": ["XX"]}).status_code == 422
    assert client.put(f"/api/offices/{oid}/jurisdictions", headers=OTHER, json={"jurisdictions": ["AU"]}).status_code == 404
    r = client.put(f"/api/offices/{oid}/jurisdictions", headers=ADMIN, json={"jurisdictions": ["SG", "AU", "AU"]})
    assert r.json() == {"jurisdictions": ["AU", "SG"]}

    extra = [
        read("domains", 200, {"value": [{"id": "lab.org", "isVerified": True, "isDefault": True}]}),
        read("managed_devices", 200, {"value": MANAGED}),
        read("compliance_policies", 200, {"value": [{"id": "p1"}]}),
    ]
    from tests.test_compliance import licence_reads

    extra += [r for r in licence_reads() if r["name"] in ("users", "user_signins")]
    _collect_and_score(oid, tenant, extra, {"lab.org": {"spf": txt(), "dmarc": txt(), "dkim": dkim(False)}})

    lic = client.get(f"/api/offices/{oid}/licences", headers=ADMIN).json()
    assert lic["products"][0]["part"] == "SPE_E5" and lic["read"]["sign_ins"]
    assert client.get(f"/api/offices/{oid}/licences", headers=OTHER).status_code == 404
    assert client.put(f"/api/offices/{oid}/licence-prices", headers=ADMIN, json={"prices": {"SPE_E5": 50}}).json() == {
        "SPE_E5": 50
    }
    assert client.get(f"/api/offices/{oid}/licences", headers=ADMIN).json()["products"][0]["monthly"] == 25 * 50
    assert client.put(f"/api/offices/{oid}/licence-prices", headers=ADMIN, json={"prices": {"SPE_E5": -1}}).status_code == 422
    assert client.get(f"/api/offices/{oid}/export/licences.xlsx", headers=ADMIN).status_code == 200
    assert "licence_data" not in client.get(f"/api/offices/{oid}/posture", headers=ADMIN).json()["facts"]

    c = client.get(f"/api/offices/{oid}/compliance", headers=ADMIN).json()
    assert [f["key"] for f in c["frameworks"]] == ["essential_eight", "privacy_au", "cyber_essentials_sg", "pdpa"]
    assert set(c["deadlines"]) == {"AU", "SG"}
    ce = {r["clause"]: r for r in c["frameworks"][2]["requirements"]}
    assert ce["A.3"]["state"] == "gap" and ce["A.3"]["evidence"][0]["note"] == "1 of 2 computers encrypted"
    assert ce["B.6"]["state"] == "gap"  # spoofable email and a non-compliant device
    assert "intune_devices" not in client.get(f"/api/offices/{oid}/posture", headers=ADMIN).json()["facts"]

    reg = client.get(f"/api/offices/{oid}/register", headers=ADMIN).json()
    keys = {f["key"]: f for f in reg["findings"]}
    assert {"intune:unencrypted", "intune:noncompliant", "intune:stale", "device:windows10", "email:spoofable"} <= set(keys)
    assert keys["intune:unencrypted"]["evidence"]["sample"] == ["LT-2"] and keys["email:spoofable"]["theme"] == "email"
    assert "email" in {t["key"] for t in reg["themes"]}
    assert (
        client.post(
            f"/api/offices/{oid}/remediation",
            headers=ADMIN,
            json={"finding_key": "intune:unencrypted", "owner": "IT", "target_date": None},
        ).status_code
        == 201
    )

    # The next scan cannot read Intune (consent withdrawn): the item stays open, it is not "fixed".
    _collect_and_score(oid, tenant)
    items = client.get(f"/api/offices/{oid}/remediation", headers=ADMIN).json()
    assert [i["status"] for i in items if i["finding_key"] == "intune:unencrypted"] == ["open"]


def test_delete_office_archives_it(client: Any) -> None:
    """Deleting hides the office everywhere and revokes consent; the name can be reused."""
    body = {"name": "Old annex", "office_type": "County IT", "county": "Lab Z"}
    oid = client.post("/api/offices", headers=ADMIN, json=body).json()["id"]
    assert client.post(f"/api/offices/{oid}/consents/microsoft365", headers=ADMIN, json={"tenant_ref": "t"}).status_code == 201
    assert client.request("DELETE", f"/api/offices/{oid}", headers=CLERK, json={"confirm_name": "Old annex"}).status_code == 403
    assert client.request("DELETE", f"/api/offices/{oid}", headers=ADMIN, json={"confirm_name": "old"}).status_code == 422
    assert client.request("DELETE", f"/api/offices/{oid}", headers=ADMIN, json={"confirm_name": "Old annex"}).json() == {
        "status": "deleted"
    }
    assert oid not in {o["id"] for o in client.get("/api/offices", headers=ADMIN).json()}
    assert client.get(f"/api/offices/{oid}", headers=ADMIN).status_code == 404
    assert client.get(f"/api/offices/{oid}/posture", headers=ADMIN).status_code == 404
    from app import worker

    assert oid not in {str(o["office_id"]) for o in worker.consented_offices()}
    assert client.post("/api/offices", headers=ADMIN, json=body).status_code == 201
