package no.nav.tpt.infrastructure.nais

interface NaisApiService {
    suspend fun getAllTeams(): List<TeamInfo>
    suspend fun getVulnerabilitiesForUser(email: String): UserVulnerabilitiesData
    suspend fun getVulnerabilitiesForTeam(teamSlug: String): UserVulnerabilitiesData
    suspend fun getTeamMembershipsForUser(email: String): List<String>
}

