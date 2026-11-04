-- Deleting an office archives it: hidden everywhere, scans stop and its consent is revoked,
-- while its evidence and audit history stay (they are what was shown to courts and insurers).
ALTER TABLE office ADD COLUMN archived_at timestamptz;
ALTER TABLE office ADD COLUMN archived_by text;

-- A new office may reuse the name of an archived one.
ALTER TABLE office DROP CONSTRAINT office_workspace_county_name_key;
CREATE UNIQUE INDEX office_workspace_county_name_live ON office (workspace_id, county, name) WHERE archived_at IS NULL;
