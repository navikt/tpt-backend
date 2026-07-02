CREATE TABLE gcve_cves (
    cve_id VARCHAR(50) PRIMARY KEY,
    cna_source VARCHAR(100),

    published_date TIMESTAMP,
    last_updated_date TIMESTAMP,

    -- CVSS v3.1
    cvss_v31_score DECIMAL(3,1),
    cvss_v31_severity VARCHAR(20),
    cvss_v31_vector VARCHAR(200),

    -- CVSS v4.0
    cvss_v40_score DECIMAL(3,1),
    cvss_v40_severity VARCHAR(20),
    cvss_v40_vector VARCHAR(200),

    description TEXT,
    cwe_ids TEXT,
    gcve_references TEXT,

    has_exploit_reference BOOLEAN DEFAULT FALSE,
    has_patch_reference BOOLEAN DEFAULT FALSE,

    -- SSVC (from CISA-ADP container)
    ssvc_exploitation VARCHAR(20),
    ssvc_automatable VARCHAR(10),
    ssvc_technical_impact VARCHAR(20),

    -- KEV (from CISA-ADP container)
    has_kev_entry BOOLEAN DEFAULT FALSE,
    kev_date_added VARCHAR(20),

    raw_response TEXT,

    fetched_at TIMESTAMP NOT NULL DEFAULT NOW(),
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_gcve_cves_published ON gcve_cves(published_date);
CREATE INDEX idx_gcve_cves_updated ON gcve_cves(last_updated_date);
CREATE INDEX idx_gcve_cves_fetched ON gcve_cves(fetched_at);
CREATE INDEX idx_gcve_cves_cvss_v31 ON gcve_cves(cvss_v31_score) WHERE cvss_v31_score IS NOT NULL;
CREATE INDEX idx_gcve_cves_has_kev ON gcve_cves(has_kev_entry) WHERE has_kev_entry = TRUE;

CREATE TABLE gcve_sync_status (
    id VARCHAR(50) PRIMARY KEY DEFAULT 'default',
    last_sync_timestamp TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);
