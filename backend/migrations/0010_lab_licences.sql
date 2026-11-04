-- A Lab workspace for test tenants, so their demo results never sit beside real court offices
-- in the AOC view. The CDX demo tenant (Lab County A) moves there.
INSERT INTO workspace (name, kind, industry, created_by)
VALUES ('Lab (test tenants)', 'organization', 'Testing', 'migration 0010')
ON CONFLICT (name) DO NOTHING;

UPDATE office SET workspace_id = (SELECT id FROM workspace WHERE name = 'Lab (test tenants)')
WHERE name ILIKE 'Lab County%' OR id::text LIKE 'e9661935-%';

-- Licence prices per office (app/licences.py has list prices; an office enters its contract prices).
ALTER TABLE office ADD COLUMN licence_prices jsonb NOT NULL DEFAULT '{}';
