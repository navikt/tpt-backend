package no.nav.tpt.infrastructure.kafka

import kotlinx.serialization.Serializable

@Serializable
data class GitHubRepositoryMessage(
    val repositoryName: String,
    val naisTeams: List<String>? = null,
    val vulnerabilities: List<GitHubVulnerabilityMessage>? = null
)

@Serializable
data class GitHubVulnerabilityMessage(
    val severity: String,
    val identifiers: List<GitHubIdentifierMessage>
)

@Serializable
data class GitHubIdentifierMessage(
    val value: String,
    val type: String
)
