CREATE INDEX idx_workload_vulnerabilities_team_resolved
    ON workload_vulnerabilities (team_slug, resolved_at);

CREATE TABLE workloads (
    app_nais_id   VARCHAR(255) PRIMARY KEY,
    team_slug     VARCHAR(100) NOT NULL,
    app_name      VARCHAR(255) NOT NULL,
    workload_type VARCHAR(20)  NOT NULL,
    environment   VARCHAR(100),
    first_seen_at TIMESTAMP    NOT NULL,
    removed_at    TIMESTAMP
);

CREATE INDEX idx_workloads_team ON workloads (team_slug);

CREATE TABLE workload_deployments (
    app_nais_id VARCHAR(255) NOT NULL REFERENCES workloads (app_nais_id) ON DELETE CASCADE,
    deployed_at TIMESTAMP    NOT NULL,
    PRIMARY KEY (app_nais_id, deployed_at)
);

CREATE TABLE workload_absences (
    app_nais_id VARCHAR(255) NOT NULL REFERENCES workloads (app_nais_id) ON DELETE CASCADE,
    removed_at  TIMESTAMP    NOT NULL,
    returned_at TIMESTAMP    NOT NULL,
    PRIMARY KEY (app_nais_id, removed_at)
);

CREATE TABLE vulnerability_resolution_gaps (
    vulnerability_id INTEGER   NOT NULL REFERENCES workload_vulnerabilities (id) ON DELETE CASCADE,
    resolved_at      TIMESTAMP NOT NULL,
    reappeared_at    TIMESTAMP NOT NULL,
    PRIMARY KEY (vulnerability_id, resolved_at)
);
