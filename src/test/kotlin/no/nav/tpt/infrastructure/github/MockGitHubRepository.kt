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

    override suspend fun getRepository(repositoryName: String): GitHubRepositoryData? {
        return mockRepositories.find { it.repositoryName == repositoryName }
    }

    override suspend fun getVulnerabilities(repositoryName: String): List<GitHubVulnerabilityData> {
        return mockVulnerabilities[repositoryName] ?: emptyList()
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
