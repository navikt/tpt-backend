-- KEV (CISA Known Exploited Vulnerabilities) Catalog Tables
-- Stores KEV catalog metadata and individual vulnerabilities with staleness tracking

-- Catalog Metadata Table
-- Tracks catalog version and update information
CREATE TABLE kev_catalog_metadata (
    id SERIAL PRIMARY KEY,
    catalog_title VARCHAR(255) NOT NULL,
    catalog_version VARCHAR(50) NOT NULL,
    date_released VARCHAR(20) NOT NULL,
    vulnerability_count INT NOT NULL,
    last_updated TIMESTAMP NOT NULL DEFAULT NOW(),
    created_at TIMESTAMP DEFAULT NOW()
);

-- Vulnerabilities Table
-- Stores individual KEV vulnerability records
CREATE TABLE kev_vulnerabilities (
    cve_id VARCHAR(20) PRIMARY KEY,
    catalog_id INT NOT NULL REFERENCES kev_catalog_metadata(id) ON DELETE CASCADE,
    vendor_project VARCHAR(500) NOT NULL,
    product VARCHAR(500) NOT NULL,
    vulnerability_name VARCHAR(1000) NOT NULL,
    date_added VARCHAR(20) NOT NULL,
    short_description TEXT NOT NULL,
    required_action TEXT NOT NULL,
    due_date VARCHAR(20) NOT NULL,
    known_ransomware_campaign_use VARCHAR(20) NOT NULL,
    notes TEXT NOT NULL,
    cwes JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Performance indexes
CREATE INDEX idx_kev_vulnerabilities_catalog_id ON kev_vulnerabilities(catalog_id);
CREATE INDEX idx_kev_vulnerabilities_date_added ON kev_vulnerabilities(date_added);
CREATE INDEX idx_kev_catalog_last_updated ON kev_catalog_metadata(last_updated DESC);

-- Comments for documentation
COMMENT ON TABLE kev_catalog_metadata IS 'Stores CISA KEV catalog metadata with staleness tracking';
COMMENT ON TABLE kev_vulnerabilities IS 'Stores individual KEV vulnerabilities normalized for efficient queries';
COMMENT ON COLUMN kev_catalog_metadata.last_updated IS 'Timestamp when this catalog was last fetched from CISA';
COMMENT ON COLUMN kev_vulnerabilities.cve_id IS 'CVE identifier (primary key)';
COMMENT ON COLUMN kev_vulnerabilities.cwes IS 'JSON array of CWE identifiers';
COMMENT ON COLUMN kev_vulnerabilities.known_ransomware_campaign_use IS 'Known or Unknown - whether used in ransomware campaigns';
