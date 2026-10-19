-- Sample entries from the site register so a test office can be onboarded end to end.
-- The full 264-site register is loaded from the AOC's list when it is supplied.
INSERT INTO site (code, name, address, county, courts) VALUES
    ('BUL-01', 'Bulloch County Judicial Annex', '20 Siebald Street', 'Bulloch', '{Juvenile,State,Superior}'),
    ('BUL-02', 'Bulloch County Courthouse', '2 North Main Street', 'Bulloch', '{Probate,State}'),
    ('LAB-A1', 'Lab County A Courthouse', 'Lab', 'Lab A', '{Superior,Magistrate}'),
    ('LAB-E1', 'Lab County E Courthouse', 'Lab', 'Lab E', '{Probate}')
ON CONFLICT (code) DO NOTHING;
