package no.nav.appsecguide.infrastructure.nais

interface NaisApiService {
    suspend fun getApplicationsForTeam(teamSlug: String): TeamApplicationsData
    suspend fun getApplicationsForUser(email: String): UserApplicationsData
    suspend fun getVulnerabilitiesForTeam(teamSlug: String): TeamVulnerabilitiesData
    suspend fun getVulnerabilitiesForUser(email: String): UserVulnerabilitiesData
}

