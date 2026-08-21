package no.nav.tpt.infrastructure.github

import kotlinx.serialization.Serializable

@Serializable
data class GitHubRepositoryMessage(
    val nameWithOwner: String,
    val naisTeams: List<String>,
    val vulnerabilities: List<GitHubVulnerabilityMessage>
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

@Serializable
data class DockerfileFeaturesMessage(
    val repoName: String,
    val usesDistroless: Boolean
)
