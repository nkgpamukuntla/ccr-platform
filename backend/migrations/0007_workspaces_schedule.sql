-- Workspaces: the platform serves more than the courts. A workspace is one customer or programme
-- (the Georgia courts under the AOC, D-Biz itself, another organisation). Every office belongs to
-- one. R11 still applies: this is separation of views, not tenant isolation; evidence stays
-- sealed per office by its own KMS keys.

CREATE TABLE workspace (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name        text NOT NULL UNIQUE,
    kind        text NOT NULL CHECK (kind IN ('courts', 'organization')),
    industry    text,
    created_at  timestamptz NOT NULL DEFAULT now(),
    created_by  text NOT NULL
);

INSERT INTO workspace (name, kind, industry, created_by)
VALUES ('Georgia Courts (AOC)', 'courts', 'Judiciary', 'migration 0007');

ALTER TABLE office ADD COLUMN workspace_id uuid REFERENCES workspace (id);
UPDATE office SET workspace_id = (SELECT id FROM workspace WHERE name = 'Georgia Courts (AOC)');
ALTER TABLE office ALTER COLUMN workspace_id SET NOT NULL;
ALTER TABLE office DROP CONSTRAINT office_county_name_key;
ALTER TABLE office ADD CONSTRAINT office_workspace_county_name_key UNIQUE (workspace_id, county, name);
CREATE INDEX office_workspace ON office (workspace_id);

-- Read-only viewers of a whole workspace (the AOC for the courts; a CISO for an organisation).
-- Members of the Cognito group aoc_viewer view every courts workspace, as before.
CREATE TABLE workspace_membership (
    email         text NOT NULL,
    workspace_id  uuid NOT NULL REFERENCES workspace (id),
    role          text NOT NULL CHECK (role IN ('workspace_viewer')),
    added_at      timestamptz NOT NULL DEFAULT now(),
    added_by      text NOT NULL,
    PRIMARY KEY (email, workspace_id)
);

-- Scans run once a day at the end of each office's business day, in its own time zone
-- (app/schedule.py). Georgia is Eastern time.
ALTER TABLE office ADD COLUMN time_zone text NOT NULL DEFAULT 'America/New_York';
ALTER TABLE office ADD COLUMN collect_at time NOT NULL DEFAULT '18:00';

GRANT SELECT, INSERT, UPDATE ON workspace TO ec_portal;
GRANT SELECT, INSERT, DELETE ON workspace_membership TO ec_portal;
