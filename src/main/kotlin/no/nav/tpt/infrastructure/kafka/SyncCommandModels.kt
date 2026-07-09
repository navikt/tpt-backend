package no.nav.tpt.infrastructure.kafka

import kotlinx.serialization.Serializable

@Serializable
data class TeamSyncCommand(val teamSlug: String)

@Serializable
data class VulnerabilityDataSyncCommand(val triggeredAt: String)

@Serializable
data class GcveSyncCommand(val triggeredAt: String)
