-- SCuBA (CISA ScubaGear) results: one row per baseline policy per assessment.
-- An assessment is either our own collection scored with ScubaGear's rules (source 'collected',
-- tied to a collection run), or a ScubaGear report the office ran and uploaded (source 'imported').

CREATE TABLE scuba_assessment (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    office_id      uuid NOT NULL REFERENCES office (id),
    source         text NOT NULL CHECK (source IN ('collected', 'imported')),
    run_id         uuid REFERENCES collection_run (id),
    baseline       text NOT NULL,          -- e.g. v1.8.0 (rules used, or the tool version that produced an import)
    tenant_id      text NOT NULL,
    assessed_at    timestamptz NOT NULL,
    products       text[] NOT NULL,
    summary        jsonb NOT NULL DEFAULT '{}',
    imported_by    text,
    file_sha256    text,
    created_at     timestamptz NOT NULL DEFAULT now(),
    CHECK ((source = 'collected') = (run_id IS NOT NULL))
);
CREATE INDEX scuba_assessment_office ON scuba_assessment (office_id, assessed_at DESC);

CREATE TABLE scuba_result (
    assessment_id   uuid NOT NULL REFERENCES scuba_assessment (id) ON DELETE CASCADE,
    product         text NOT NULL,
    policy_id       text NOT NULL,
    requirement     text,
    criticality     text NOT NULL,
    status          text NOT NULL CHECK (status IN ('pass', 'fail', 'warning', 'na', 'error')),
    details         text NOT NULL DEFAULT '',
    PRIMARY KEY (assessment_id, policy_id)
);

-- Evaluator writes collected assessments; portal writes imports and reads both.
GRANT SELECT, INSERT ON scuba_assessment, scuba_result TO ec_evaluator;
GRANT SELECT, INSERT ON scuba_assessment, scuba_result TO ec_portal;
