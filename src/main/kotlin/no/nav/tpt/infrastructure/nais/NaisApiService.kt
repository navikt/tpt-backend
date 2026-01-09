package no.nav.tpt.infrastructure.nais

interface NaisApiService {
    suspend fun getApplicationsForUser(email: String, bypassCache: Boolean = false): UserApplicationsData
    suspend fun getVulnerabilitiesForUser(email: String, bypassCache: Boolean = false): UserVulnerabilitiesData
}

