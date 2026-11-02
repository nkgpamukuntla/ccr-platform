-- Phase 5: findings to remediation (walkthrough slides 23-25), exports, and email notifications.
-- Remediation is tracking only (R7): the platform never changes the customer's systems. An item
-- closes only when fresh evidence no longer shows the finding (app/remediation.py).

CREATE TABLE remediation_item (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    office_id      uuid NOT NULL REFERENCES office (id),
    finding_key    text NOT NULL,          -- stable key from app/findings_engine.py, e.g. control:2
    title          text NOT NULL,
    recommendation text NOT NULL,
    control        integer,
    owner          text NOT NULL,          -- county IT, its MSP, site staff, or a named person
    target_date    date,
    status         text NOT NULL DEFAULT 'open'
                   CHECK (status IN ('open', 'in_progress', 'awaiting_evidence', 'closed')),
    created_by     text NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    closed_at      timestamptz,
    closed_reason  text,
    CHECK ((status = 'closed') = (closed_at IS NOT NULL))
);
-- One live item per finding; once closed, a finding that comes back opens a new item.
CREATE UNIQUE INDEX remediation_item_live ON remediation_item (office_id, finding_key) WHERE status <> 'closed';

CREATE TABLE remediation_event (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    item_id     uuid NOT NULL REFERENCES remediation_item (id),
    at          timestamptz NOT NULL DEFAULT now(),
    actor       text NOT NULL,             -- an email, or 'evidence' for closure by re-read
    from_status text,
    to_status   text NOT NULL,
    note        text
);
CREATE INDEX remediation_event_item ON remediation_event (item_id);

-- Who is told what. An office recipient hears about that office; a workspace recipient about
-- every office in it. Emails carry a summary and a link only, never the findings themselves.
CREATE TABLE notification_recipient (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    office_id     uuid REFERENCES office (id),
    workspace_id  uuid REFERENCES workspace (id),
    email         text NOT NULL,
    events        text[] NOT NULL,         -- scan_report (one per scan, with changes), scan_failed
    added_by      text NOT NULL,
    added_at      timestamptz NOT NULL DEFAULT now(),
    CHECK ((office_id IS NULL) <> (workspace_id IS NULL))
);
CREATE UNIQUE INDEX notification_recipient_office ON notification_recipient (office_id, lower(email)) WHERE office_id IS NOT NULL;
CREATE UNIQUE INDEX notification_recipient_workspace ON notification_recipient (workspace_id, lower(email)) WHERE workspace_id IS NOT NULL;

-- Outbox: the portal and the worker queue, then send through SES. ref de-duplicates
-- (one scan report per run, one overdue reminder per item per day).
CREATE TABLE notification_outbox (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    office_id   uuid REFERENCES office (id),
    event       text NOT NULL,
    ref         text NOT NULL,
    recipient   text NOT NULL,
    subject     text NOT NULL,
    body        text NOT NULL,
    queued_at   timestamptz NOT NULL DEFAULT now(),
    sent_at     timestamptz,
    attempts    integer NOT NULL DEFAULT 0,
    last_error  text,
    message_id  text,
    UNIQUE (event, ref, recipient)
);
CREATE INDEX notification_outbox_pending ON notification_outbox (queued_at) WHERE sent_at IS NULL;

-- The findings as reported after each scan, so the next report can say what changed.
CREATE TABLE finding_snapshot (
    id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    office_id    uuid NOT NULL REFERENCES office (id),
    run_id       uuid NOT NULL REFERENCES collection_run (id),
    taken_at     timestamptz NOT NULL DEFAULT now(),
    headline     jsonb NOT NULL,           -- control states, device and coverage counts
    findings     jsonb NOT NULL,           -- [{key, title, severity}]
    UNIQUE (run_id)
);
CREATE INDEX finding_snapshot_office ON finding_snapshot (office_id, taken_at DESC);

GRANT SELECT, INSERT, UPDATE ON remediation_item TO ec_portal;
GRANT SELECT ON finding_snapshot TO ec_portal;
GRANT SELECT, INSERT ON remediation_event TO ec_portal;
GRANT SELECT, INSERT, UPDATE, DELETE ON notification_recipient TO ec_portal;
GRANT SELECT, INSERT, UPDATE ON notification_outbox TO ec_portal;

-- The worker builds one scan report per evaluated run (summary and changes only) and drains the outbox.
GRANT SELECT ON workspace, control_result, scuba_assessment, scuba_result, device_observation,
    notification_recipient TO ec_worker;
GRANT SELECT, UPDATE ON remediation_item TO ec_worker;  -- closure on fresh evidence only (app/remediation.py)
GRANT INSERT ON remediation_event TO ec_worker;
GRANT SELECT, INSERT ON finding_snapshot TO ec_worker;
GRANT SELECT, INSERT, UPDATE ON notification_outbox TO ec_worker;
