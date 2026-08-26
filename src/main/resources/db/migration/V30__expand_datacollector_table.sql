ALTER TABLE datacollector_checks ADD COLUMN IF NOT EXISTS description VARCHAR;
ALTER TABLE datacollector_checks ADD COLUMN IF NOT EXISTS severity VARCHAR;

