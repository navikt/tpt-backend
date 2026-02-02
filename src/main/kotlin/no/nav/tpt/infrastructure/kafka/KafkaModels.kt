package no.nav.tpt.infrastructure.kafka

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class GitHubRepositoryMessage(
    @SerialName("nameWithOwner")
    val nameWithOwner: String? = null,
    @SerialName("repositoryName")
    val repositoryName: String? = null,
    val naisTeams: List<String>? = null,
    val vulnerabilities: List<GitHubVulnerabilityMessage>? = null
) {
    fun getRepositoryIdentifier(): String {
        return nameWithOwner ?: repositoryName ?: throw IllegalArgumentException("Either nameWithOwner or repositoryName must be provided")
    }
}

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
