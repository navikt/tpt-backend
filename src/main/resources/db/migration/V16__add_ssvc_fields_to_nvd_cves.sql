ALTER TABLE nvd_cves ADD COLUMN exploitation_status VARCHAR(20);
ALTER TABLE nvd_cves ADD COLUMN automatable VARCHAR(10);
ALTER TABLE nvd_cves ADD COLUMN technical_impact VARCHAR(20);

CREATE INDEX idx_nvd_cves_exploitation ON nvd_cves(exploitation_status)
    WHERE exploitation_status IS NOT NULL;
