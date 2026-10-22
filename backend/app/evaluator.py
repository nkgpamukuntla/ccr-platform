"""Evaluator: turns sealed raw bundles into control results. No internet (R6).

    python -m app.evaluator

Runs in the evaluator subnets, whose only egress is S3 (the raw bucket), KMS and Postgres.
It opens each bundle through S3 (the office's key decrypts only that office's prefix) and
writes results; it cannot write raw data or reach any source.
"""

import json
import logging
import sys
from typing import Any

import boto3
from psycopg.types.json import Jsonb

from app import db
from app.config import get_settings
from app.controls import ControlResult, evaluate, facts
from app.scuba import aad as scuba_aad
from app.scuba.baseline import requirement
from app.scuba.evaluate import BASELINE, ScubaResult, evaluate_aad, rollup

log = logging.getLogger("evaluator")


def scuba_results(bundle: dict[str, Any]) -> list[ScubaResult]:
    """ScubaGear's Entra rules over the recorded responses; empty if the bundle has none or OPA fails."""
    rec = bundle.get("scuba_aad")
    if not rec or not rec.get("responses"):
        return []
    try:
        provider = scuba_aad.build_provider(scuba_aad.RecordedGraph(rec["responses"]))
        return evaluate_aad(scuba_aad.opa_input(provider, bundle["ms_tenant_id"]))
    except Exception as e:  # noqa: BLE001 - SCuBA scoring is additive; the controls still evaluate
        log.error(
            json.dumps({"event": "scuba_failed", "run": bundle.get("run_id"), "error": f"{type(e).__name__}: {str(e)[:300]}"})
        )
        return []


def _aligned(r: ControlResult, scuba: list[ScubaResult]) -> ControlResult:
    """Controls 1-3 take their state from the SCuBA policies they map to (IRMA roll-up)."""
    up = rollup(r.control, scuba)
    if up is None:
        return r
    state, detail = up
    if state == "not_observed":
        # SCuBA could not establish it (e.g. consent not yet updated): keep the Graph reading, say why.
        return r.model_copy(
            update={"detail": {**r.detail, "scuba": {**detail, "note": "SCuBA rules could not evaluate; Graph reading shown"}}}
        )
    return r.model_copy(
        update={"state": state, "method": f"Connected · SCuBA {BASELINE} rules", "detail": {**detail, "graph_reading": r.detail}}
    )


def _store_scuba(conn: Any, run: dict[str, Any], bundle: dict[str, Any], scuba: list[ScubaResult]) -> None:
    summary: dict[str, int] = {}
    for x in scuba:
        summary[x.status] = summary.get(x.status, 0) + 1
    a = conn.execute(
        "INSERT INTO scuba_assessment (office_id, source, run_id, baseline, tenant_id, assessed_at, products, summary) "
        "VALUES (%s, 'collected', %s, %s, %s, %s, %s, %s) RETURNING id",
        (run["office_id"], run["id"], BASELINE, bundle["ms_tenant_id"], run["finished_at"], ["aad"], Jsonb(summary)),
    ).fetchone()
    for x in scuba:
        conn.execute(
            "INSERT INTO scuba_result (assessment_id, product, policy_id, requirement, criticality, status, details) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (a["id"], x.product, x.policy_id, requirement(x.policy_id), x.criticality, x.status, x.details),
        )


def evaluate_pending(s3: Any, bucket: str, limit: int = 50) -> dict[str, int]:
    with db.tx() as conn:
        runs = conn.execute(
            "SELECT id, office_id, s3_key, s3_version_id, finished_at FROM collection_run "
            "WHERE status = 'collected' ORDER BY started_at LIMIT %s",
            (limit,),
        ).fetchall()
    done = {"evaluated": 0, "failed": 0}
    for run in runs:
        try:
            kwargs = {"Bucket": bucket, "Key": run["s3_key"]}
            if run["s3_version_id"]:
                kwargs["VersionId"] = run["s3_version_id"]
            bundle = json.loads(s3.get_object(**kwargs)["Body"].read())
            if bundle.get("run_id") != str(run["id"]) or bundle.get("office_id") != str(run["office_id"]):
                raise ValueError("bundle does not match its run record")
            results = evaluate(bundle)
            scuba = scuba_results(bundle)
            if scuba:
                results = [_aligned(r, scuba) for r in results]
            with db.tx() as conn:
                if scuba:
                    _store_scuba(conn, run, bundle, scuba)
                for r in results:
                    conn.execute(
                        "INSERT INTO control_result (run_id, office_id, control, name, state, method, detail, as_of) "
                        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                        (run["id"], run["office_id"], r.control, r.name, r.state, r.method, Jsonb(r.detail), run["finished_at"]),
                    )
                conn.execute(
                    "INSERT INTO run_facts (run_id, office_id, facts) VALUES (%s, %s, %s)",
                    (run["id"], run["office_id"], Jsonb(facts(bundle))),
                )
                conn.execute("UPDATE collection_run SET status = 'evaluated' WHERE id = %s", (run["id"],))
            done["evaluated"] += 1
            log.info(json.dumps({"event": "evaluated", "run": str(run["id"]), "states": {r.control: r.state for r in results}}))
        except Exception as e:  # noqa: BLE001 - recorded on the run, the next one continues
            with db.tx() as conn:
                conn.execute(
                    "UPDATE collection_run SET status = 'evaluation_failed', error = %s WHERE id = %s",
                    (f"{type(e).__name__}: {str(e)[:500]}", run["id"]),
                )
            done["failed"] += 1
            log.error(json.dumps({"event": "evaluation_failed", "run": str(run["id"]), "error": type(e).__name__}))
    return done


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    s = get_settings()
    db.open_pool()
    try:
        done = evaluate_pending(boto3.client("s3", region_name=s.aws_region), s.ec_raw_bucket)
        log.info(json.dumps({"event": "evaluation_done", **done}))
        return 1 if done["failed"] else 0
    finally:
        db.close_pool()


if __name__ == "__main__":
    sys.exit(main())
