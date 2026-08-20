package no.nav.tpt.infrastructure.kafka

object KafkaKey {
    const val TEAM_SYNC = "team_sync"
    const val TEAM_SYNC_STARTED = "team_sync_started"
    const val TEAM_SYNC_COMPLETE = "team_sync_complete"
    const val VULN_DATA_SYNC = "vuln_data_sync"
    const val GCVE_SYNC = "gcve_sync"
    const val GCVE_SYNC_COMPLETE = "gcve_sync_complete"
    const val GITHUB_VULNERABILITY_DATA = "github_vulnerability_data"
    // Published by tpt-data-collector. Consumed by SseFanoutConsumer to push progress
    // events to the frontend over SSE. Key casing must stay lowercase snake_case —
    // the match is case-sensitive.
    const val GITHUB_VULN_SYNC_STARTED = "github_vuln_sync_started"
    const val GITHUB_VULN_SYNC_COMPLETE = "github_vuln_sync_complete"
}
