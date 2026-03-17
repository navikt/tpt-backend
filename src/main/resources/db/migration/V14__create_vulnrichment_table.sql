CREATE TABLE vulnrichment_data (
    cve_id VARCHAR(20) PRIMARY KEY,
    exploitation_status VARCHAR(20),
    automatable VARCHAR(10),
    technical_impact VARCHAR(20),
    last_updated TIMESTAMP NOT NULL DEFAULT NOW(),
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_vulnrichment_exploitation ON vulnrichment_data(exploitation_status);
