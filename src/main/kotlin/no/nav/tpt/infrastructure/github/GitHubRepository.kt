package no.nav.tpt.infrastructure.github



interface GitHubRepository {
    suspend fun upsertRepositoryData(message: GitHubRepositoryMessage)
    suspend fun getRepository(nameWithOwner: String): GitHubRepositoryData?
    suspend fun getVulnerabilities(nameWithOwner: String): List<GitHubVulnerabilityData>
    suspend fun getAllRepositories(): List<GitHubRepositoryData>
    suspend fun getRepositoriesByTeams(teamSlugs: List<String>): List<GitHubRepositoryData>
    suspend fun deleteRepositoriesExclusivelyOwnedBy(teamSlugs: List<String>)
    suspend fun removeTeamsFromSharedRepositories(teamSlugs: List<String>)
    suspend fun tryAcquireRefreshLock(teamSlug: String): Boolean
    suspend fun releaseRefreshLock(teamSlug: String)
    suspend fun getLastSyncedAt(teamSlugs: List<String>): Map<String, String>
}
