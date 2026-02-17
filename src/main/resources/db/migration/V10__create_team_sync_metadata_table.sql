CREATE TABLE team_sync_metadata (
    team_slug VARCHAR(100) PRIMARY KEY,
    last_synced_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_team_sync_metadata_last_synced ON team_sync_metadata(last_synced_at);
