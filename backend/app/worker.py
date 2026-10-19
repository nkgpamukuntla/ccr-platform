"""Worker: for each office that consented, read Microsoft Graph and seal the raw bundle in S3.

    python -m app.worker

Runs as a scheduled ECS task in the worker subnets (the only ones with a route out, R6).
It writes each bundle under the office's prefix with the office's own KMS key, and has no
permission to read it back. It records the run and a credential fingerprint, then publishes
the liveness heartbeat. It never evaluates anything; that is the evaluator's job.
"""

import base64
import json
import logging
import sys
import time
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import boto3
import httpx
from psycopg.types.json import Jsonb

from app import db
from app.config import Settings, get_settings
from app.microsoft import graph
from app.microsoft.signer import KmsSigner
from app.microsoft.token import TokenError, get_token

log = logging.getLogger("worker")
UUID_RE = "^[0-9a-fA-F-]{36}$"


def _fingerprint(s: Settings) -> str:
    """HMAC (KMS) of the credential identity, recorded on every exchange."""
    kms = boto3.client("kms", region_name=s.aws_region)
    mac: bytes = kms.generate_mac(
        KeyId=s.ec_fingerprint_key_id,
        MacAlgorithm="HMAC_SHA_256",
        Message=f"{s.ms_client_id}|{s.ms_cert_thumbprint_sha256}".encode(),
    )["Mac"]
    return base64.urlsafe_b64encode(mac).rstrip(b"=").decode()


def consented_offices() -> list[dict[str, Any]]:
    with db.tx() as conn:
        return conn.execute(
            "SELECT DISTINCT ON (k.office_id) k.office_id, k.tenant_ref FROM consent k "
            "WHERE k.source = 'microsoft365' AND k.status = 'granted' AND k.tenant_ref ~ %s "
            "ORDER BY k.office_id, k.granted_at DESC",
            (UUID_RE,),
        ).fetchall()


def collect_one(s: Settings, http: httpx.Client, signer: KmsSigner, office_id: UUID, ms_tenant: str, fingerprint: str) -> str:
    raw_key = s.ec_raw_keys[str(office_id)]
    with db.tx() as conn:
        row = conn.execute(
            "INSERT INTO collection_run (office_id, source, ms_tenant_id, status, credential_fingerprint) "
            "VALUES (%s, 'microsoft365', %s, 'running', %s) RETURNING id",
            (office_id, ms_tenant, fingerprint),
        ).fetchone()
    assert row is not None
    run_id = row["id"]
    started = datetime.now(UTC).isoformat()
    try:
        token = get_token(http, signer, s.ms_client_id, ms_tenant, s.ms_cert_thumbprint_sha1, s.ms_cert_thumbprint_sha256)
        reads = [graph.fetch(http, token, r) for r in graph.READS]
        bundle = {
            "schema": "ccr.raw.microsoft365.v1",
            "run_id": str(run_id),
            "office_id": str(office_id),
            "ms_tenant_id": ms_tenant,
            "client_id": s.ms_client_id,
            "credential_fingerprint": fingerprint,
            "started_at": started,
            "finished_at": datetime.now(UTC).isoformat(),
            "reads": reads,
        }
        key = f"{office_id}/microsoft365/{run_id}.json"
        put = boto3.client("s3", region_name=s.aws_region).put_object(
            Bucket=s.ec_raw_bucket,
            Key=key,
            Body=json.dumps(bundle, separators=(",", ":")).encode(),
            ContentType="application/json",
            ServerSideEncryption="aws:kms",
            SSEKMSKeyId=raw_key,  # the bucket policy refuses any other key for this prefix
            BucketKeyEnabled=False,
        )
        summary = {r["name"]: r["status"] for r in reads}
        with db.tx() as conn:
            conn.execute(
                "UPDATE collection_run SET status = 'collected', finished_at = now(), s3_key = %s, s3_version_id = %s, "
                "summary = %s WHERE id = %s",
                (key, put.get("VersionId"), Jsonb(summary), run_id),
            )
        log.info(json.dumps({"event": "collected", "office": str(office_id), "run": str(run_id), "reads": summary}))
        return "collected"
    except (TokenError, httpx.HTTPError, Exception) as e:  # noqa: BLE001 - every failure is recorded on the run
        with db.tx() as conn:
            conn.execute(
                "UPDATE collection_run SET status = 'failed', finished_at = now(), error = %s WHERE id = %s",
                (f"{type(e).__name__}: {str(e)[:500]}", run_id),
            )
        log.error(
            json.dumps(
                {
                    "event": "failed",
                    "office": str(office_id),
                    "run": str(run_id),
                    "error": type(e).__name__,
                    "message": str(e)[:300],
                }
            )
        )
        return "failed"


def heartbeat(s: Settings) -> None:
    boto3.client("cloudwatch", region_name=s.aws_region).put_metric_data(
        Namespace=s.ec_heartbeat_namespace,
        MetricData=[
            {"MetricName": s.ec_heartbeat_metric, "Dimensions": [{"Name": "Environment", "Value": s.environment}], "Value": 1}
        ],
    )


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    s = get_settings()
    missing = [k for k in ("ms_client_id", "ms_cert_thumbprint_sha1", "ec_signing_key_id", "ec_raw_bucket") if not getattr(s, k)]
    if missing:
        log.error(json.dumps({"event": "not_configured", "missing": missing}))
        return 2
    db.open_pool()
    try:
        signer = KmsSigner(s.ec_signing_key_id, s.aws_region)
        fingerprint = _fingerprint(s) if s.ec_fingerprint_key_id else ""
        results: dict[str, int] = {}
        with httpx.Client(headers={"User-Agent": "ccr-evidence-collector/1"}) as http:
            for o in consented_offices():
                if str(o["office_id"]) not in s.ec_raw_keys:
                    log.warning(
                        json.dumps(
                            {
                                "event": "skipped",
                                "office": str(o["office_id"]),
                                "reason": "no raw key: add the office id to tenant_ids in Terraform",
                            }
                        )
                    )
                    results["skipped"] = results.get("skipped", 0) + 1
                    continue
                outcome = collect_one(s, http, signer, o["office_id"], o["tenant_ref"], fingerprint)
                results[outcome] = results.get(outcome, 0) + 1
        heartbeat(s)
        log.info(json.dumps({"event": "cycle_done", "results": results, "at": time.time()}))
        return 1 if results.get("failed") else 0
    finally:
        db.close_pool()


if __name__ == "__main__":
    sys.exit(main())
