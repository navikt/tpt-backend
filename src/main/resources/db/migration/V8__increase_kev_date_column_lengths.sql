-- Increase date column lengths in KEV tables to accommodate ISO 8601 timestamps
-- dateReleased from CISA API is in format: 2026-01-23T18:00:05.4207Z (25 characters)
-- dateAdded and dueDate are in format: 2026-01-23 (10 characters, but keeping consistent size)

ALTER TABLE kev_catalog_metadata
    ALTER COLUMN date_released TYPE VARCHAR(30);

ALTER TABLE kev_vulnerabilities
    ALTER COLUMN date_added TYPE VARCHAR(30);

ALTER TABLE kev_vulnerabilities
    ALTER COLUMN due_date TYPE VARCHAR(30);
