package no.nav.tpt.infrastructure.nais

interface NaisApiService {
    suspend fun getVulnerabilitiesForUser(email: String, bypassCache: Boolean = false): UserVulnerabilitiesData
    suspend fun getVulnerabilitiesForTeam(teamSlug: String, bypassCache: Boolean = false): UserVulnerabilitiesData
    suspend fun getTeamMembershipsForUser(email: String): List<String>
}

