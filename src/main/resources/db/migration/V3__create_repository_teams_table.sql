-- GitHub Repository Data Tables
-- Stores repository information from GitHub including teams and vulnerabilities from Kafka messages

-- Main repository table with teams as array
CREATE TABLE github_repositories (
    repository_name VARCHAR(500) PRIMARY KEY,
    nais_teams TEXT[] NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Vulnerabilities table for repository vulnerabilities
CREATE TABLE github_vulnerabilities (
    id SERIAL PRIMARY KEY,
    repository_name VARCHAR(500) NOT NULL REFERENCES github_repositories(repository_name) ON DELETE CASCADE,
    severity VARCHAR(20) NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Identifiers table for vulnerability identifiers (CVE, GHSA, etc.)
CREATE TABLE github_vulnerability_identifiers (
    id SERIAL PRIMARY KEY,
    vulnerability_id INTEGER NOT NULL REFERENCES github_vulnerabilities(id) ON DELETE CASCADE,
    identifier_value VARCHAR(100) NOT NULL,
    identifier_type VARCHAR(20) NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Performance indexes
-- Index on repository_name for looking up all vulnerabilities for a repository
CREATE INDEX idx_github_vulns_repository ON github_vulnerabilities(repository_name);

-- Index on vulnerability_id for joining vulnerabilities with their identifiers
CREATE INDEX idx_github_vuln_identifiers_vuln_id ON github_vulnerability_identifiers(vulnerability_id);

-- Index for updated_at queries on repositories
CREATE INDEX idx_github_repositories_updated ON github_repositories(updated_at);
