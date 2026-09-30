CREATE TABLE sse_event_log (
    id BIGSERIAL PRIMARY KEY,
    type VARCHAR(100) NOT NULL,
    payload TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_sse_event_log_created_at ON sse_event_log(created_at);
