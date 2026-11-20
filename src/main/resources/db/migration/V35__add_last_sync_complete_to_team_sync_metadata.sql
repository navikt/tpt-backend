ALTER TABLE team_sync_metadata
    ADD COLUMN last_sync_complete BOOLEAN NOT NULL DEFAULT TRUE;

UPDATE team_sync_metadata
SET last_sync_complete = FALSE
WHERE last_synced_at = TIMESTAMPTZ '1970-01-01 00:00:00+00';
