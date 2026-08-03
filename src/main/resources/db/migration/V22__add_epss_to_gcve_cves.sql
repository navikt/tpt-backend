ALTER TABLE gcve_cves
    ADD COLUMN epss_score       DOUBLE PRECISION,
    ADD COLUMN epss_percentile  VARCHAR(20),
    ADD COLUMN has_ransomware_campaign_use BOOLEAN NOT NULL DEFAULT FALSE;
