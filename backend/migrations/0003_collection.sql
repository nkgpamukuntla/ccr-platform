-- Phase 2: collection runs, observations, control results; worker and evaluator roles.

-- One collection run per office and source. The raw bundle is sealed in S3 under the
-- office's own key; the worker writes it and cannot read it back.
CREATE TABLE collection_run (
    id                     uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    office_id              uuid NOT NULL REFERENCES office (id),
    source                 text NOT NULL,
    ms_tenant_id           text NOT NULL,
    started_at             timestamptz NOT NULL DEFAULT now(),
    finished_at            timestamptz,
    status                 text NOT NULL CHECK (status IN ('running', 'collected', 'failed', 'evaluated', 'evaluation_failed')),
    s3_key                 text,
    s3_version_id          text,
    summary                jsonb NOT NULL DEFAULT '{}',
    credential_fingerprint text,
    error                  text
);
CREATE INDEX collection_run_office ON collection_run (office_id, started_at DESC);
CREATE INDEX collection_run_pending ON collection_run (status) WHERE status = 'collected';

-- What a run showed, after evaluation: one row per control, plus context facts.
CREATE TABLE control_result (
    run_id     uuid NOT NULL REFERENCES collection_run (id),
    office_id  uuid NOT NULL REFERENCES office (id),
    control    smallint NOT NULL CHECK (control BETWEEN 1 AND 8),
    name       text NOT NULL,
    state      text NOT NULL CHECK (state IN ('met', 'gap', 'weak', 'not_observed', 'pending')),
    method     text NOT NULL,
    detail     jsonb NOT NULL DEFAULT '{}',
    as_of      timestamptz NOT NULL,
    PRIMARY KEY (run_id, control)
);
CREATE INDEX control_result_office ON control_result (office_id, as_of DESC);

CREATE TABLE run_facts (
    run_id    uuid PRIMARY KEY REFERENCES collection_run (id),
    office_id uuid NOT NULL REFERENCES office (id),
    facts     jsonb NOT NULL
);

DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'ec_worker') THEN
        CREATE ROLE ec_worker LOGIN;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'ec_evaluator') THEN
        CREATE ROLE ec_evaluator LOGIN;
    END IF;
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'rds_iam') THEN
        GRANT rds_iam TO ec_worker, ec_evaluator;
    END IF;
END $$;

GRANT USAGE ON SCHEMA public TO ec_worker, ec_evaluator;

-- Worker: which offices consented, and its own run records. Nothing about results.
GRANT SELECT ON office, consent TO ec_worker;
GRANT SELECT, INSERT, UPDATE ON collection_run TO ec_worker;

-- Evaluator: reads runs, writes results. No consent, no membership, no credentials.
GRANT SELECT, UPDATE ON collection_run TO ec_evaluator;
GRANT SELECT, INSERT ON control_result, run_facts TO ec_evaluator;

-- Portal: reads what was found.
GRANT SELECT ON collection_run, control_result, run_facts TO ec_portal;
