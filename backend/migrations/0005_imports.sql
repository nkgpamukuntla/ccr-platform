-- Phase 3a: CSV imports from the county's own tools, and the device observations they carry.
-- Every imported file is kept as uploaded (bytes + SHA-256) and is never edited; each device row
-- points back to the file it came from.

CREATE TABLE import_file (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    office_id     uuid NOT NULL REFERENCES office (id),
    template      text NOT NULL,
    filename      text NOT NULL,
    sha256        text NOT NULL,
    content       bytea NOT NULL,
    export_date   date,
    uploaded_by   text NOT NULL,
    uploaded_at   timestamptz NOT NULL DEFAULT now(),
    rows_total    integer NOT NULL,
    rows_loaded   integer NOT NULL,
    rows_rejected integer NOT NULL,
    issues        jsonb NOT NULL DEFAULT '[]',
    UNIQUE (office_id, sha256)
);

CREATE TABLE device_observation (
    id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    office_id    uuid NOT NULL REFERENCES office (id),
    source       text NOT NULL,            -- e.g. import:edr_hosts
    import_id    uuid REFERENCES import_file (id),
    hostname     text,
    serial       text,
    mac          text,
    os           text,
    os_build     text,
    last_seen    timestamptz,
    edr_product  text,
    edr_status   text,                     -- active | inactive | none
    managed      boolean,
    site         text,
    attributes   jsonb NOT NULL DEFAULT '{}',
    observed_at  timestamptz NOT NULL DEFAULT now(),
    CHECK (hostname IS NOT NULL OR serial IS NOT NULL)
);
CREATE INDEX device_observation_office ON device_observation (office_id);

GRANT SELECT, INSERT ON import_file, device_observation TO ec_portal;
