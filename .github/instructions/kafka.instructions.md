---
applyTo: "src/main/**/kafka/**/*.kt"
---

# Kafka Integration

Consumer client for receiving JSON data from other applications via Aiven Kafka with SSL/TLS (PKCS12 keystore,
JKS truststore, `tpt-backend` consumer group, `earliest` offset reset, auto-commit every 1s).

## Optional Feature

Kafka is **optional**, gated on configuration:

- If `KAFKA_BROKERS` is not set, skip consumer initialization entirely and start normally — this must always pass health checks.
- Required env vars when enabled: `KAFKA_BROKERS`, `KAFKA_TOPICS` (comma-separated), plus the NAIS-provided SSL
  material (`KAFKA_CERTIFICATE_PATH`, `KAFKA_PRIVATE_KEY_PATH`, `KAFKA_CA_PATH`, `KAFKA_CREDSTORE_PASSWORD`,
  `KAFKA_KEYSTORE_PATH`, `KAFKA_TRUSTSTORE_PATH`).

## Health Check Contract

- **Liveness** (`/isalive`): always `200 OK`, never affected by Kafka status.
- **Readiness**: reflects consumer health — `503` if the consumer is unhealthy (e.g. polling failed), `200` once
  reconnected. This lets old pods keep serving traffic during a Kafka outage instead of being killed.
- On poll failure: log the error, mark unhealthy, wait 5s, retry.

## SSE Event Log

SSE events are never fanned out through Kafka. Publishers (sync services, `GcveSyncConsumer`) write via
`SseEventPublisher` to the Postgres `sse_event_log` table (insert + `pg_notify` in one transaction); every pod's
`SseEventLogListener` (LISTEN/NOTIFY) feeds its local `SseEventBus`. `SseEventLogConsumer` only ingests the
`github_vuln_sync_*` events from tpt-data-collector into that log (the `/callbacks/github/sync/*` endpoints do the
same over HTTP). Publishing must be best-effort and never fail a sync.
