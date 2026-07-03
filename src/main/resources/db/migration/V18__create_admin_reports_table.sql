CREATE TABLE admin_reports (
    report_type  VARCHAR(50) PRIMARY KEY,
    payload      TEXT        NOT NULL,
    generated_at TIMESTAMP   NOT NULL DEFAULT NOW()
);
