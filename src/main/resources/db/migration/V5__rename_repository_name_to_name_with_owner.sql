-- Rename repository_name to name_with_owner to match GitHub's naming convention
-- This reflects the actual field name we receive from GitHub API (nameWithOwner)

ALTER TABLE github_repositories
    RENAME COLUMN repository_name TO name_with_owner;

ALTER TABLE github_vulnerabilities
    RENAME COLUMN repository_name TO name_with_owner;

-- Update indexes to reflect the new column name
DROP INDEX IF EXISTS idx_github_vulns_repository;
CREATE INDEX idx_github_vulns_name_with_owner ON github_vulnerabilities(name_with_owner);
