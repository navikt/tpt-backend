package no.nav.tpt.infrastructure.sse

data class SseEventEnvelope(
    val id: Long,
    val event: SseEvent,
) {
    val type: String
        get() = when (event) {
            is SseEvent.TeamSyncStarted -> "team_sync_started"
            is SseEvent.TeamSyncComplete -> "team_sync_complete"
            is SseEvent.TeamSyncFailed -> "team_sync_failed"
            is SseEvent.GcveSyncComplete -> "gcve_sync_complete"
            is SseEvent.GitHubVulnSyncStarted -> "github_vuln_sync_started"
            is SseEvent.GitHubVulnSyncComplete -> "github_vuln_sync_complete"
        }
}
