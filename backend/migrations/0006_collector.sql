-- Phase 3b: the offline collector. Each download is recorded; its id is the token baked into
-- office.json and carried inside every bundle that collector writes, so a bundle can be traced
-- to who downloaded it and refused once that download is revoked. Bundles themselves are kept
-- as uploaded in import_file (template 'collector'), their devices in device_observation.

CREATE TABLE collector_download (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    office_id   uuid NOT NULL REFERENCES office (id),
    key_arn     text NOT NULL,
    created_by  text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    revoked_by  text,
    revoked_at  timestamptz
);
CREATE INDEX collector_download_office ON collector_download (office_id);

GRANT SELECT, INSERT ON collector_download TO ec_portal;
GRANT UPDATE (revoked_by, revoked_at) ON collector_download TO ec_portal;
