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
    val identifiers: List<GitHubIdentifierMessage>,
    val dependencyScope: String? = null,
    val dependabotUpdatePullRequestUrl: String? = null,
    val publishedAt: String? = null,
    val cvssScore: Double? = null,
    val summary: String? = null,
    val packageEcosystem: String? = null,
    val packageName: String? = null
)

@Serializable
data class GitHubIdentifierMessage(
    val value: String,
    val type: String
)
