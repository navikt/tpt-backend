package no.nav.appsecguide.infrastructure.nais

interface NaisApiService {
    suspend fun getApplicationsForTeam(teamSlug: String): ApplicationsForTeamResponse
    suspend fun getApplicationsForUser(email: String): ApplicationsForUserResponse
    suspend fun getVulnerabilitiesForTeam(teamSlug: String): VulnerabilitiesForTeamResponse
    suspend fun getVulnerabilitiesForUser(email: String): VulnerabilitiesForUserResponse
}

