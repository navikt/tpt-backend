ALTER TABLE datacollector_checks
    ADD COLUMN suppressed BOOLEAN NOT NULL DEFAULT FALSE;

