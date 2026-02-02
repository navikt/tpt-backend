package no.nav.tpt.infrastructure.github

import no.nav.tpt.infrastructure.kafka.GitHubRepositoryMessage

interface GitHubRepository {
    suspend fun upsertRepositoryData(message: GitHubRepositoryMessage)
    suspend fun updateDockerfileFeatures(repoName: String, usesDistroless: Boolean)
    suspend fun getRepository(nameWithOwner: String): GitHubRepositoryData?
    suspend fun getVulnerabilities(nameWithOwner: String): List<GitHubVulnerabilityData>
    suspend fun getAllRepositories(): List<GitHubRepositoryData>
    suspend fun getRepositoriesByTeams(teamSlugs: List<String>): List<GitHubRepositoryData>
}
