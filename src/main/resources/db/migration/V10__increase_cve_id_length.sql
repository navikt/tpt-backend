-- Increase CVE ID column length from 20 to 50 characters
-- Some CVE identifiers (e.g., UBUNTU-CVE-2024-12797, GHSA-xxxx-xxxx-xxxx) exceed 20 characters

-- Core vulnerability tables
ALTER TABLE cves ALTER COLUMN id TYPE VARCHAR(50);
ALTER TABLE workload_vulnerabilities ALTER COLUMN cve_id TYPE VARCHAR(50);

-- External data source tables
ALTER TABLE nvd_cves ALTER COLUMN cve_id TYPE VARCHAR(50);
ALTER TABLE epss_scores ALTER COLUMN cve_id TYPE VARCHAR(50);
ALTER TABLE kev_vulnerabilities ALTER COLUMN cve_id TYPE VARCHAR(50);

COMMENT ON COLUMN cves.id IS 'CVE identifier (e.g., CVE-2024-1234, UBUNTU-CVE-2024-12797, GHSA-xxxx-xxxx-xxxx)';
COMMENT ON COLUMN nvd_cves.cve_id IS 'CVE identifier (e.g., CVE-2024-1234, UBUNTU-CVE-2024-12797)';
COMMENT ON COLUMN epss_scores.cve_id IS 'CVE identifier (e.g., CVE-2021-44228, UBUNTU-CVE-2024-12797)';
COMMENT ON COLUMN kev_vulnerabilities.cve_id IS 'CVE identifier (e.g., CVE-2024-1234, UBUNTU-CVE-2024-12797)';

