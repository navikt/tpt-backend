package no.nav.tpt.infrastructure.github

import no.nav.tpt.infrastructure.kafka.GitHubRepositoryMessage
import java.time.Instant

class MockGitHubRepository(
    private val mockRepositories: List<GitHubRepositoryData> = emptyList(),
    private val mockVulnerabilities: Map<String, List<GitHubVulnerabilityData>> = emptyMap()
) : GitHubRepository {

    override suspend fun upsertRepositoryData(message: GitHubRepositoryMessage) {
        // No-op for tests
    }

    override suspend fun updateDockerfileFeatures(repoName: String, usesDistroless: Boolean) {
        // No-op for tests
    }

    override suspend fun getRepository(nameWithOwner: String): GitHubRepositoryData? {
        return mockRepositories.find { it.nameWithOwner == nameWithOwner }
    }

    override suspend fun getVulnerabilities(nameWithOwner: String): List<GitHubVulnerabilityData> {
        return mockVulnerabilities[nameWithOwner] ?: emptyList()
    }

    override suspend fun getAllRepositories(): List<GitHubRepositoryData> {
        return mockRepositories
    }

    override suspend fun getRepositoriesByTeams(teamSlugs: List<String>): List<GitHubRepositoryData> {
        return mockRepositories.filter { repo ->
            repo.naisTeams.any { it in teamSlugs }
        }
    }
}
