-- Countries whose frameworks apply to an office (app/frameworks.py): US, AU, SG.
-- Existing offices take theirs from the time zone they scan in; any other office chooses on the
-- Compliance page.

ALTER TABLE office ADD COLUMN jurisdictions text[] NOT NULL DEFAULT '{}';
UPDATE office SET jurisdictions = '{US}' WHERE time_zone LIKE 'America/%';
UPDATE office SET jurisdictions = '{AU}' WHERE time_zone LIKE 'Australia/%';
UPDATE office SET jurisdictions = '{SG}' WHERE time_zone = 'Asia/Singapore';

-- The scan report (sent by the worker) builds findings, which now include Intune and email facts.
GRANT SELECT ON run_facts TO ec_worker;
