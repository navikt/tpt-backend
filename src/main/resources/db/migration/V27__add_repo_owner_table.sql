CREATE TABLE datacollector_repo_owners (
    owner   VARCHAR NOT NULL,
    check_id VARCHAR NOT NULL,
    PRIMARY KEY(owner, check_id),
    CONSTRAINT fk_reponame FOREIGN KEY (check_id) REFERENCES datacollector_checks(id) ON DELETE CASCADE
);
