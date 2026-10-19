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
from app.controls import evaluate, facts

log = logging.getLogger("evaluator")


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
            with db.tx() as conn:
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
