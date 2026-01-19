package no.nav.tpt.infrastructure.github

import no.nav.tpt.infrastructure.kafka.GitHubRepositoryMessage

interface GitHubRepository {
    suspend fun upsertRepositoryData(message: GitHubRepositoryMessage)
    suspend fun getRepository(repositoryName: String): GitHubRepositoryData?
    suspend fun getVulnerabilities(repositoryName: String): List<GitHubVulnerabilityData>
    suspend fun getAllRepositories(): List<GitHubRepositoryData>
}
