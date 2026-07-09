package no.nav.tpt.infrastructure.sse

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
sealed class SseEvent {
    @Serializable
    @SerialName("team_sync_started")
    data class TeamSyncStarted(val teamSlug: String, val timestamp: String) : SseEvent()

    @Serializable
    @SerialName("team_sync_complete")
    data class TeamSyncComplete(val teamSlug: String, val timestamp: String) : SseEvent()

    @Serializable
    @SerialName("gcve_sync_complete")
    data class GcveSyncComplete(val cveCount: Int, val timestamp: String) : SseEvent()
}
