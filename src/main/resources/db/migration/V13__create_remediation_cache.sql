CREATE TABLE remediation_cache (
    cve_id VARCHAR(50) NOT NULL,
    package_ecosystem VARCHAR(100) NOT NULL,
    remediation_text TEXT NOT NULL,
    generated_at TIMESTAMP NOT NULL,
    PRIMARY KEY (cve_id, package_ecosystem)
);
