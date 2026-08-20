CREATE TABLE github_team_sync_metadata (
    team_slug              VARCHAR(100) PRIMARY KEY,
    last_refresh_triggered_at TIMESTAMP WITH TIME ZONE NOT NULL,
    sync_locked_until      TIMESTAMP WITH TIME ZONE NULL,
    created_at             TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at             TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_github_team_sync_metadata_lock ON github_team_sync_metadata(sync_locked_until)
    WHERE sync_locked_until IS NOT NULL;
