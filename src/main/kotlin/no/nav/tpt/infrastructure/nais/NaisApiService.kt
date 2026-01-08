package no.nav.tpt.infrastructure.nais

interface NaisApiService {
    suspend fun getApplicationsForUser(email: String): UserApplicationsData
    suspend fun getVulnerabilitiesForUser(email: String): UserVulnerabilitiesData
}

