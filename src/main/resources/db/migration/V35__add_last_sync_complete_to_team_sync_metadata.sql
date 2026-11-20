ALTER TABLE team_sync_metadata
    ADD COLUMN last_sync_complete BOOLEAN NOT NULL DEFAULT TRUE;
