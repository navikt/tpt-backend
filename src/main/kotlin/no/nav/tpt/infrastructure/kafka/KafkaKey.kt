package no.nav.tpt.infrastructure.kafka

object KafkaKey {
    const val TEAM_SYNC = "team_sync"
    const val VULN_DATA_SYNC = "vuln_data_sync"
    const val GCVE_SYNC = "gcve_sync"
    const val GITHUB_VULNERABILITY_DATA = "github_vulnerability_data"
    // Published by tpt-data-collector and ingested into the Postgres SSE event log.
    const val GITHUB_VULN_SYNC_STARTED = "github_vuln_sync_started"
    const val GITHUB_VULN_SYNC_COMPLETE = "github_vuln_sync_complete"
}
