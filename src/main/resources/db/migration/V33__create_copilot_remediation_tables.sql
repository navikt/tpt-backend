CREATE TABLE copilot_remediations (
    id BIGSERIAL PRIMARY KEY,
    repository VARCHAR(255) NOT NULL,
    vulnerability_identifier VARCHAR(255) NOT NULL,
    package_name VARCHAR(512) NOT NULL DEFAULT '',
    status VARCHAR(20) NOT NULL,
    task_id VARCHAR(255),
    task_url TEXT,
    requested_by VARCHAR(255) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_copilot_remediations_key UNIQUE (repository, vulnerability_identifier, package_name)
);

CREATE INDEX idx_copilot_remediations_repository ON copilot_remediations(repository);

CREATE TABLE copilot_authorization_requests (
    state VARCHAR(128) PRIMARY KEY,
    code_verifier VARCHAR(128) NOT NULL,
    requested_by VARCHAR(255) NOT NULL,
    repository VARCHAR(255) NOT NULL,
    vulnerability_identifier VARCHAR(255) NOT NULL,
    package_name VARCHAR(512) NOT NULL DEFAULT '',
    workload_id VARCHAR(512),
    return_path TEXT NOT NULL,
    expires_at TIMESTAMP NOT NULL
);

CREATE INDEX idx_copilot_authorization_requests_expires_at ON copilot_authorization_requests(expires_at);
