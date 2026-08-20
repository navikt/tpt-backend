package no.nav.tpt.infrastructure.github



interface GitHubRepository {
    suspend fun upsertRepositoryData(message: GitHubRepositoryMessage)
    suspend fun updateDockerfileFeatures(repoName: String, usesDistroless: Boolean)
    suspend fun updateCodeScanningStatus(repoName: String, status: String)
    suspend fun getRepository(nameWithOwner: String): GitHubRepositoryData?
    suspend fun getVulnerabilities(nameWithOwner: String): List<GitHubVulnerabilityData>
    suspend fun getAllRepositories(): List<GitHubRepositoryData>
    suspend fun getRepositoriesByTeams(teamSlugs: List<String>): List<GitHubRepositoryData>
    suspend fun deleteRepositoriesExclusivelyOwnedBy(teamSlugs: List<String>)
    suspend fun removeTeamsFromSharedRepositories(teamSlugs: List<String>)
}
