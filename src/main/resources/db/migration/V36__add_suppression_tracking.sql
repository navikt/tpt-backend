ALTER TABLE workload_vulnerabilities
    ADD COLUMN suppressed_at TIMESTAMP;

UPDATE workload_vulnerabilities
SET suppressed_at = discovered_at
WHERE suppressed;

ALTER TABLE vulnerability_resolution_gaps
    ADD COLUMN suppressed BOOLEAN NOT NULL DEFAULT FALSE;
