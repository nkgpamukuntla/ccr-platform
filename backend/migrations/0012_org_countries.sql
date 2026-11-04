-- Countries belong to the organisation; each office sits in one of them (app/frameworks.py).
-- countries:         where the organisation operates (offices choose one of these)
-- frameworks:        frameworks the organisation requires, applied to offices in that framework's country
--                    (empty = every framework of the office's country)
-- group_frameworks:  frameworks the organisation requires in every office, whatever its country
ALTER TABLE workspace ADD COLUMN countries text[] NOT NULL DEFAULT '{}';
ALTER TABLE workspace ADD COLUMN frameworks text[] NOT NULL DEFAULT '{}';
ALTER TABLE workspace ADD COLUMN group_frameworks text[] NOT NULL DEFAULT '{}';
ALTER TABLE office ADD COLUMN country text;

UPDATE office SET country = jurisdictions[1] WHERE cardinality(jurisdictions) > 0;
UPDATE office SET country = 'IN' WHERE country IS NULL AND time_zone = 'Asia/Kolkata';
UPDATE office SET country = 'US' WHERE country IS NULL AND time_zone LIKE 'America/%';

UPDATE workspace SET countries = '{US}' WHERE kind = 'courts';
UPDATE workspace SET countries = '{AU,IN,SG,US}' WHERE kind = 'organization' AND (name ILIKE '%d-biz%' OR name ILIKE '%dbiz%');
UPDATE workspace w SET countries = ARRAY(
    SELECT DISTINCT o.country FROM office o WHERE o.workspace_id = w.id AND o.country IS NOT NULL ORDER BY 1)
WHERE countries = '{}';
