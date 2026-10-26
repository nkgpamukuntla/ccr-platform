"""Offline collector (step 5, Collect): download for an office, bundle upload, revocation."""

import base64
import hashlib
import io
import json
import zipfile
from pathlib import Path
from typing import Any
from uuid import UUID

import boto3
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_der_public_key
from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import Response
from psycopg.types.json import Jsonb

from app import audit
from app.access import can_read, can_write
from app.auth import CurrentUser
from app.collector import bundle
from app.config import get_settings
from app.db import tx

router = APIRouter(prefix="/api/offices/{office_id}/collector", tags=["collector"])

SCRIPT = "Collect-CCREvidence.ps1"
CERT = "ccr-collector-signing.cer"

README = """Court Connection Readiness - offline evidence collector
Office: {office}
Downloaded by {who} on {when} (download {token})

1. Copy this folder to each PC (USB stick, network share, or push with GPO / RMM).
2. On each PC, right-click Windows PowerShell > Run as administrator, then:
       cd <this folder>
       powershell.exe -ExecutionPolicy RemoteSigned -File .\\Collect-CCREvidence.ps1
   Add -Preview first to see exactly what is read, without writing anything.
3. Each run writes one file named <PC>_<time>.ccre next to the script (or on the Desktop).
   It is encrypted for this office only; nobody else, including D-Biz staff, can read it
   outside the portal.
4. Upload the .ccre files in the CCR portal: Devices > Upload collector bundles.

The script reads security configuration only: never files, email, browser data, passwords or
anything from Gavel. It installs nothing and leaves nothing running.

Signature: {signed}
If PowerShell refuses to run the script ("not digitally signed" or "root certificate which
is not trusted"): Windows treats files from the internet as remote, and where an execution
policy is set by Group Policy (RemoteSigned or AllSigned), -ExecutionPolicy Bypass on the
command line does not override it. The lab certificate above is not from a public CA, so
such PCs will not run the script until your IT team trusts it or we move to a commercial
certificate. Check the signature first:
    Get-AuthenticodeSignature .\\Collect-CCREvidence.ps1
It must show the signer above; HashMismatch means the file was changed, so do not run it.
Ask your CCR contact before changing any execution policy or trusting the certificate.
"""


def kms_public_key(key_arn: str) -> bytes:
    """SubjectPublicKeyInfo DER of the office's collector key (seam for tests)."""
    der: bytes = boto3.client("kms", region_name=get_settings().aws_region).get_public_key(KeyId=key_arn)["PublicKey"]
    return der


def kms_unwrap(key_arn: str, ek: bytes) -> bytes:
    """kms:Decrypt the bundle's content key; the key policy allows RSAES_OAEP_SHA_256 only (seam for tests)."""
    kms = boto3.client("kms", region_name=get_settings().aws_region)
    out: bytes = kms.decrypt(KeyId=key_arn, CiphertextBlob=ek, EncryptionAlgorithm="RSAES_OAEP_SHA_256")["Plaintext"]
    return out


def _key_arn(office_id: UUID) -> str:
    arn = get_settings().ec_collector_keys.get(str(office_id))
    if not arn:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "the collector is not enabled for this office yet: a platform administrator adds the office to the "
            "deployment (tenant_ids) to create its key",
        )
    return arn


def _b64int(n: int) -> str:
    return base64.b64encode(n.to_bytes((n.bit_length() + 7) // 8, "big")).decode()


@router.get("/status")
def collector_status(office_id: UUID, user: CurrentUser) -> dict[str, Any]:
    with tx() as conn:
        can_read(conn, user, office_id)
        downloads = conn.execute(
            "SELECT d.id, d.created_by, d.created_at, d.revoked_by, d.revoked_at, "
            "(SELECT count(*) FROM device_observation o JOIN import_file f ON f.id = o.import_id "
            " WHERE f.office_id = d.office_id AND o.attributes->'collected'->'collector'->>'token' = d.id::text) AS bundles "
            "FROM collector_download d WHERE d.office_id = %s ORDER BY d.created_at DESC",
            (office_id,),
        ).fetchall()
        bundles = conn.execute(
            "SELECT f.id, f.filename, f.uploaded_by, f.uploaded_at, o.hostname, o.serial, o.edr_status, o.edr_product, "
            "o.last_seen, f.issues FROM import_file f JOIN device_observation o ON o.import_id = f.id "
            "WHERE f.office_id = %s AND f.template = 'collector' ORDER BY f.uploaded_at DESC LIMIT 500",
            (office_id,),
        ).fetchall()
    return {"enabled": str(office_id) in get_settings().ec_collector_keys, "downloads": downloads, "bundles": bundles}


@router.get("/download")
def download(office_id: UUID, user: CurrentUser) -> Response:
    """A zip for this office: the signed script, office.json (public key + token), the signing certificate."""
    key_arn = _key_arn(office_id)
    folder = Path(get_settings().collector_dir)
    script = folder / SCRIPT
    if not script.is_file():
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "collector script missing from this build")
    pub = load_der_public_key(kms_public_key(key_arn))
    if not isinstance(pub, rsa.RSAPublicKey):
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "collector key is not RSA")
    numbers = pub.public_numbers()
    with tx() as conn:
        can_write(conn, user, office_id)
        office = conn.execute("SELECT name, county FROM office WHERE id = %s", (office_id,)).fetchone()
        assert office is not None
        row = conn.execute(
            "INSERT INTO collector_download (office_id, key_arn, created_by) VALUES (%s, %s, %s) RETURNING id, created_at",
            (office_id, key_arn, user.email),
        ).fetchone()
        assert row is not None
        audit.record(conn, user, "collector.download", office_id, download=str(row["id"]))
    office_name = f"{office['name']} ({office['county']})"
    config = {
        "format": "ccr-collector-config/1",
        "office_id": str(office_id),
        "office_name": office_name,
        "key_arn": key_arn,
        "public_key": {"kty": "RSA", "n": _b64int(numbers.n), "e": _b64int(numbers.e)},
        "token": str(row["id"]),
        "issued": row["created_at"].isoformat(),
        "upload": f"{get_settings().public_url}/offices/{office_id}/devices",
    }
    text = script.read_bytes()
    signed = b"# SIG # Begin signature block" in text
    cert = folder / CERT
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(SCRIPT, text)
        z.writestr("office.json", json.dumps(config, indent=2))
        if cert.is_file():
            z.writestr(CERT, cert.read_bytes())
        z.writestr(
            "README.txt",
            README.format(
                office=office_name,
                who=user.email,
                when=row["created_at"].strftime("%d %b %Y %H:%M UTC"),
                token=row["id"],
                signed=(
                    f"Authenticode, D-Biz lab certificate ({CERT}; lab only, not yet a public CA)"
                    if signed
                    else "NOT SIGNED (development build)"
                ),
            ).replace("\n", "\r\n"),
        )
    slug = "".join(c if c.isalnum() else "-" for c in office["name"]).strip("-").lower()[:40]
    return Response(
        buf.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="ccr-collector-{slug}.zip"'},
    )


@router.post("/downloads/{download_id}/revoke")
def revoke(office_id: UUID, download_id: UUID, user: CurrentUser) -> dict[str, str]:
    """Bundles from a revoked download are refused from now on (already loaded ones stay, labelled)."""
    with tx() as conn:
        can_write(conn, user, office_id)
        n = conn.execute(
            "UPDATE collector_download SET revoked_by = %s, revoked_at = now() WHERE id = %s AND office_id = %s AND revoked_at IS NULL",
            (user.email, download_id, office_id),
        ).rowcount
        if not n:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "download not found or already revoked")
        audit.record(conn, user, "collector.revoke", office_id, download=str(download_id))
    return {"status": "revoked"}


@router.post("/bundles", status_code=status.HTTP_201_CREATED)
async def upload(office_id: UUID, filename: str, request: Request, user: CurrentUser) -> dict[str, Any]:
    raw = await request.body()
    with tx() as conn:
        can_write(conn, user, office_id)
    key_arn = _key_arn(office_id)
    try:
        env = bundle.parse_envelope(raw)
        if env["office_id"] != str(office_id):
            raise bundle.BundleError("bundle was made for a different office")
        if env["key_arn"] != key_arn:
            raise bundle.BundleError("bundle was made with an old or different collector key; download the collector again")
        facts = bundle.open_bundle(env, lambda ek: kms_unwrap(key_arn, ek))
        warnings = bundle.check(facts)
    except bundle.BundleError as e:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(e)) from e
    obs = bundle.observation(facts)
    token = str(facts["collector"]["token"])
    sha = hashlib.sha256(raw).hexdigest()
    with tx() as conn:
        dl = conn.execute(
            "SELECT revoked_at FROM collector_download WHERE id::text = %s AND office_id = %s", (token, office_id)
        ).fetchone()
        if dl is None:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY, "bundle comes from a collector this office never downloaded"
            )
        if dl["revoked_at"] is not None:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "bundle comes from a revoked collector download")
        if conn.execute("SELECT 1 FROM import_file WHERE office_id = %s AND sha256 = %s", (office_id, sha)).fetchone():
            raise HTTPException(status.HTTP_409_CONFLICT, "this bundle was already uploaded")
        issues = [{"row": None, "level": "warning", "message": w} for w in warnings]
        f = conn.execute(
            "INSERT INTO import_file (office_id, template, filename, sha256, content, export_date, uploaded_by, rows_total, "
            "rows_loaded, rows_rejected, issues) VALUES (%s, 'collector', %s, %s, %s, %s, %s, 1, 1, 0, %s) RETURNING id",
            (
                office_id,
                filename[:200],
                sha,
                raw,
                obs["last_seen"].date() if obs["last_seen"] else None,
                user.email,
                Jsonb(issues),
            ),
        ).fetchone()
        assert f is not None
        conn.execute(
            "INSERT INTO device_observation (office_id, source, import_id, hostname, serial, mac, os, os_build, last_seen, "
            "edr_product, edr_status, managed, site, attributes) VALUES (%s, 'collector', %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (
                office_id,
                f["id"],
                obs["hostname"],
                obs["serial"],
                obs["mac"],
                obs["os"],
                obs["os_build"],
                obs["last_seen"],
                obs["edr_product"],
                obs["edr_status"],
                obs["managed"],
                obs["site"],
                Jsonb(obs["attributes"]),
            ),
        )
        audit.record(
            conn, user, "collector.bundle", office_id, filename=filename, sha256=sha, hostname=obs["hostname"], download=token
        )
    return {
        "status": "loaded",
        "hostname": obs["hostname"],
        "serial": obs["serial"],
        "edr_status": obs["edr_status"],
        "edr_product": obs["edr_product"],
        "warnings": warnings,
    }
