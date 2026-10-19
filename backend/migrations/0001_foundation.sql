-- Phase 1 foundation: tenancy, sites, onboarding, consent, connections, audit.
-- R11: none of this is tenant isolation. Office scoping is enforced in the application,
-- and what holds against a compromised component is the grants at the end.
-- gen_random_uuid() is core in PostgreSQL 13+; no extension needed.


-- A governed office (clerk, magistrate, sheriff...). Consent is per office, not per county.
CREATE TABLE office (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name              text NOT NULL,
    office_type       text NOT NULL,
    county            text NOT NULL,
    signatory_name    text,
    technical_contact text,
    created_at        timestamptz NOT NULL DEFAULT now(),
    created_by        text NOT NULL,
    UNIQUE (county, name)
);

-- The court site register (264 sites); offices confirm the sites they use.
CREATE TABLE site (
    id      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    code    text NOT NULL UNIQUE,
    name    text NOT NULL,
    address text,
    county  text NOT NULL,
    courts  text[] NOT NULL DEFAULT '{}'
);

CREATE TABLE office_site (
    office_id uuid NOT NULL REFERENCES office (id) ON DELETE CASCADE,
    site_id   uuid NOT NULL REFERENCES site (id),
    confirmed boolean NOT NULL DEFAULT true,
    PRIMARY KEY (office_id, site_id)
);

-- Which signed-in users belong to which office. Keyed on the verified email Cognito
-- returns, so an admin can add someone before their first sign-in.
CREATE TABLE membership (
    email     text NOT NULL CHECK (email = lower(email)),
    office_id uuid NOT NULL REFERENCES office (id) ON DELETE CASCADE,
    role      text NOT NULL CHECK (role IN ('office_admin', 'office_member')),
    added_at  timestamptz NOT NULL DEFAULT now(),
    added_by  text NOT NULL,
    PRIMARY KEY (email, office_id)
);

-- Step 2 answers and the derived profile (A-E) and path.
CREATE TABLE environment_profile (
    office_id  uuid PRIMARY KEY REFERENCES office (id) ON DELETE CASCADE,
    answers    jsonb NOT NULL,
    profile    char(1) NOT NULL CHECK (profile IN ('A', 'B', 'C', 'D', 'E')),
    path       jsonb NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    updated_by text NOT NULL
);

CREATE TABLE onboarding (
    office_id       uuid PRIMARY KEY REFERENCES office (id) ON DELETE CASCADE,
    completed_steps smallint[] NOT NULL DEFAULT '{}',
    live_at         timestamptz,
    updated_at      timestamptz NOT NULL DEFAULT now()
);

-- Consent record per office and source; revocable at any time.
CREATE TABLE consent (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    office_id   uuid NOT NULL REFERENCES office (id) ON DELETE CASCADE,
    source      text NOT NULL,
    status      text NOT NULL CHECK (status IN ('granted', 'revoked')),
    scopes      jsonb NOT NULL DEFAULT '[]',
    tenant_ref  text,
    granted_by  text NOT NULL,
    granted_at  timestamptz NOT NULL DEFAULT now(),
    revoked_by  text,
    revoked_at  timestamptz
);
CREATE UNIQUE INDEX consent_one_active ON consent (office_id, source) WHERE status = 'granted';

-- How each source is reached. The credential itself lives in Secrets Manager (R5);
-- only its ARN is recorded, and the portal can write it but never read it back.
CREATE TABLE connection (
    office_id        uuid NOT NULL REFERENCES office (id) ON DELETE CASCADE,
    source           text NOT NULL,
    mode             text NOT NULL CHECK (mode IN ('connect', 'import', 'collect', 'questionnaire')),
    secret_arn       text,
    status           text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'ready', 'failed')),
    last_test_at     timestamptz,
    last_test_result jsonb,
    updated_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (office_id, source)
);

-- Append-only audit log.
CREATE TABLE audit_log (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    at          timestamptz NOT NULL DEFAULT now(),
    actor_sub   text NOT NULL,
    actor_email text NOT NULL,
    office_id   uuid,
    action      text NOT NULL,
    detail      jsonb NOT NULL DEFAULT '{}'
);
CREATE INDEX audit_log_office ON audit_log (office_id, at DESC);

CREATE FUNCTION audit_log_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only';
END $$;
CREATE TRIGGER audit_log_no_change BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_append_only();

-- Runtime role for the portal. Grants are the boundary (R11).
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'ec_portal') THEN
        CREATE ROLE ec_portal LOGIN;
    END IF;
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'rds_iam') THEN
        GRANT rds_iam TO ec_portal;
    END IF;
END $$;

GRANT USAGE ON SCHEMA public TO ec_portal;
GRANT SELECT ON site TO ec_portal;
GRANT SELECT, INSERT, UPDATE ON office, office_site, membership, environment_profile, onboarding,
    consent, connection TO ec_portal;
GRANT DELETE ON office_site, membership, connection TO ec_portal;
GRANT SELECT, INSERT ON audit_log TO ec_portal;
