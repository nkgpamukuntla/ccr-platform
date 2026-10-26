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
