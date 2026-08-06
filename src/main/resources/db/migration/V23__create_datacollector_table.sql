CREATE TABLE datacollector_checks (
    id           VARCHAR PRIMARY KEY,
    check_name   VARCHAR NOT NULL,
    repo         VARCHAR NOT NULL,
    result       VARCHAR NOT NULL,
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE datacollector_check_failure_reasons (
    reason              VARCHAR NOT NULL,
    check_id            VARCHAR NOT NULL,
    CONSTRAINT fk_check_id FOREIGN KEY(check_id) REFERENCES datacollector_checks(id) ON DELETE CASCADE
);

