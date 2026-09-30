package no.nav.tpt.infrastructure.datacollector

import kotlinx.serialization.Serializable

@Serializable
data class GitHubSyncSignal(val teams: List<String>, val timestamp: String)
