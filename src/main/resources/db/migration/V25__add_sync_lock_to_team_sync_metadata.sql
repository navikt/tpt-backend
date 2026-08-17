ALTER TABLE team_sync_metadata
    ADD COLUMN sync_locked_until TIMESTAMP WITH TIME ZONE NULL;

CREATE INDEX idx_team_sync_metadata_lock ON team_sync_metadata(sync_locked_until)
    WHERE sync_locked_until IS NOT NULL;
