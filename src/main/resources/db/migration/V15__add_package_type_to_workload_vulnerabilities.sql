ALTER TABLE workload_vulnerabilities
    ADD COLUMN package_type VARCHAR(50);

UPDATE workload_vulnerabilities
SET package_type = LOWER(SPLIT_PART(SUBSTRING(package_name FROM 5), '/', 1))
WHERE package_name LIKE 'pkg:%';
