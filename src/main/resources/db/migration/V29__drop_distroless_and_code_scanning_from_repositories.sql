ALTER TABLE github_repositories
    DROP COLUMN IF EXISTS uses_distroless,
    DROP COLUMN IF EXISTS code_scanning_status;
