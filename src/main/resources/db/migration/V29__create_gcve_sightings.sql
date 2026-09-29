CREATE TABLE gcve_sightings_summary (
    cve_id              VARCHAR(50) PRIMARY KEY,
    exploited_count     INT         NOT NULL DEFAULT 0,
    poc_count           INT         NOT NULL DEFAULT 0,
    seen_count          INT         NOT NULL DEFAULT 0,
    latest_exploited_at TIMESTAMP,
    latest_poc_at       TIMESTAMP,
    latest_seen_at      TIMESTAMP,
    created_at          TIMESTAMP   NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMP   NOT NULL DEFAULT NOW()
);

CREATE TABLE gcve_sightings_sync_state (
    id                INT  PRIMARY KEY DEFAULT 1,
    last_fetched_date DATE NOT NULL,
    updated_at        TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE OR REPLACE FUNCTION update_gcve_sightings_summary_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_gcve_sightings_summary_updated_at
BEFORE UPDATE ON gcve_sightings_summary
FOR EACH ROW
EXECUTE FUNCTION update_gcve_sightings_summary_updated_at();
