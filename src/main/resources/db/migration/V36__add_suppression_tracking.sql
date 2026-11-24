ALTER TABLE workload_vulnerabilities
    ADD COLUMN suppressed_at TIMESTAMP;

-- Existing suppressions have no known start, so they are backfilled to discovery. Earlier resolution
-- gaps would then fall inside the suppression interval and resurrect phantom active periods.
DELETE FROM vulnerability_resolution_gaps
WHERE vulnerability_id IN (SELECT id FROM workload_vulnerabilities WHERE suppressed);

UPDATE workload_vulnerabilities
SET suppressed_at = discovered_at
WHERE suppressed;

ALTER TABLE vulnerability_resolution_gaps
    ADD COLUMN suppressed BOOLEAN NOT NULL DEFAULT FALSE;
