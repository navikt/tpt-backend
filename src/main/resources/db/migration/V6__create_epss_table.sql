-- EPSS (Exploit Prediction Scoring System) Scores Table
-- Stores exploit prediction scores with staleness tracking

CREATE TABLE epss_scores (
    -- Core identifier
    cve_id VARCHAR(20) PRIMARY KEY,

    -- EPSS data from API
    epss_score VARCHAR(20) NOT NULL,
    percentile VARCHAR(20) NOT NULL,
    score_date VARCHAR(20) NOT NULL,

    -- Staleness tracking
    last_updated TIMESTAMP NOT NULL DEFAULT NOW(),

    -- Metadata
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Performance indexes
CREATE INDEX idx_epss_scores_last_updated ON epss_scores(last_updated);

-- Comments for documentation
COMMENT ON TABLE epss_scores IS 'Stores EPSS exploit prediction scores with staleness tracking for selective refresh';
COMMENT ON COLUMN epss_scores.cve_id IS 'CVE identifier (e.g., CVE-2021-44228)';
COMMENT ON COLUMN epss_scores.epss_score IS 'Exploit prediction probability score (0-1 as string from API)';
COMMENT ON COLUMN epss_scores.percentile IS 'Percentile ranking of this CVE (0-1 as string from API)';
COMMENT ON COLUMN epss_scores.score_date IS 'Date when EPSS calculated this score (YYYY-MM-DD format from API)';
COMMENT ON COLUMN epss_scores.last_updated IS 'Timestamp when this record was last fetched/updated from EPSS API';
